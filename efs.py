#!/usr/bin/env python3
"""Manage a portable ext4 filesystem in a file-backed LUKS2 container."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from typing import Iterator, NoReturn, Sequence


MIN_SIZE_MIB = 8
MIGRATION_OVERHEAD_MIB = 32
MAPPER_PREFIX = "efs-"
KEYSLOTS_SIZE = "1MiB"
UUID_RE = re.compile(r"^[0-9a-fA-F-]+$")


class EfsError(Exception):
    """An expected, user-facing failure."""


def fail(message: str) -> NoReturn:
    raise EfsError(message)


def require(*commands: str) -> None:
    missing = [command for command in commands if shutil.which(command) is None]
    if missing:
        fail(f"required command not found: {', '.join(missing)}")


def run(
    args: Sequence[str],
    *,
    root: bool = False,
    capture: bool = False,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    command = list(args)
    if root and os.geteuid() != 0:
        require("sudo")
        command = ["sudo", "--", *command]
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    if result.returncode not in allowed_returncodes:
        rendered = " ".join(args[:2])
        fail(f"{rendered} failed with exit status {result.returncode}")
    return result


def existing_file(value: str) -> Path:
    path = Path(value).absolute()
    if path.is_symlink():
        fail(f"refusing symbolic link: {path}")
    if not path.exists():
        fail(f"file does not exist: {path}")
    if not path.is_file():
        fail(f"not a regular file: {path}")
    return path


def new_file_path(value: str) -> Path:
    path = Path(value).absolute()
    if path.exists() or path.is_symlink():
        fail(f"destination already exists: {path}")
    parent = path.parent
    if not parent.is_dir():
        fail(f"destination directory does not exist: {parent}")
    if not os.access(parent, os.W_OK):
        fail(f"destination directory is not writable: {parent}")
    return path


def luks_uuid(container: Path) -> str:
    result = run(["cryptsetup", "luksUUID", str(container)], capture=True)
    uuid = result.stdout.strip()
    if not uuid or UUID_RE.fullmatch(uuid) is None:
        fail(f"could not read a valid LUKS UUID from {container}")
    return uuid.lower()


def mapping_name(container: Path) -> str:
    return MAPPER_PREFIX + luks_uuid(container).replace("-", "")


def mapper_path(name: str) -> Path:
    return Path("/dev/mapper") / name


def mounted_targets(mapper: Path) -> list[Path]:
    result = run(
        ["findmnt", "--json", "--output", "TARGET", "--source", str(mapper)],
        capture=True,
        allowed_returncodes=(0, 1),
    )
    if result.returncode == 1 or not result.stdout.strip():
        return []
    try:
        filesystems = json.loads(result.stdout)["filesystems"]
        return [Path(item["target"]) for item in filesystems]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        fail(f"could not understand findmnt output: {error}")


@contextmanager
def lock_container(container: Path) -> Iterator[None]:
    # cryptsetup takes its own lock on the container file. Lock its directory
    # so cooperating efs processes serialize operations without deadlocking
    # cryptsetup. Directory locks are advisory and do not create sidecar files.
    descriptor = os.open(
        container.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        fail(f"another efs operation is using {container}")
    try:
        yield
    finally:
        os.close(descriptor)


def close_mapping(name: str, *, unmount: bool) -> None:
    mapper = mapper_path(name)
    if not mapper.exists():
        return
    targets = mounted_targets(mapper)
    if targets and not unmount:
        fail(f"mapping is unexpectedly mounted at {targets[0]}")
    for target in targets:
        run(["umount", str(target)], root=True)
    run(["cryptsetup", "close", name], root=True)


def create_temp_path(destination: Path) -> Path:
    descriptor, value = tempfile.mkstemp(
        prefix=f".{destination.name}.tmp.", dir=destination.parent
    )
    os.close(descriptor)
    os.chmod(value, 0o600)
    return Path(value)


def allocate(path: Path, size_mib: int) -> None:
    byte_count = size_mib * 1024 * 1024
    if shutil.which("fallocate"):
        run(["fallocate", "--length", str(byte_count), str(path)])
    else:
        with path.open("r+b") as output:
            output.truncate(byte_count)


def publish(temp: Path, destination: Path) -> None:
    # Recheck immediately before rename. os.rename is atomic; this script never
    # deliberately replaces a destination.
    if destination.exists() or destination.is_symlink():
        fail(f"destination appeared while working: {destination}")
    os.rename(temp, destination)


def format_luks(path: Path) -> None:
    print("Choose a passphrase for the new LUKS2 container.", file=sys.stderr)
    run(
        [
            "cryptsetup",
            "luksFormat",
            "--batch-mode",
            "--type",
            "luks2",
            "--pbkdf",
            "argon2id",
            "--luks2-keyslots-size",
            KEYSLOTS_SIZE,
            "--verify-passphrase",
            str(path),
        ],
        root=True,
    )


def open_mapping(container: Path, name: str) -> None:
    run(["cryptsetup", "open", "--type", "luks", str(container), name], root=True)


def owner_ids() -> tuple[int, int]:
    uid = int(os.environ.get("SUDO_UID", os.getuid()))
    gid = int(os.environ.get("SUDO_GID", os.getgid()))
    return uid, gid


def prepare_mountpoint(mountpoint: Path, *, allow_root_create: bool = False) -> bool:
    """Validate the mountpoint and return whether this call created it."""
    if mountpoint.is_symlink():
        fail(f"refusing symbolic-link mountpoint: {mountpoint}")
    if not mountpoint.exists():
        try:
            mountpoint.mkdir(mode=0o700)
        except PermissionError:
            if not allow_root_create:
                raise
            require("chown", "mkdir")
            run(["mkdir", "--mode", "0700", str(mountpoint)], root=True)
            uid, gid = owner_ids()
            run(["chown", f"{uid}:{gid}", str(mountpoint)], root=True)
        return True
    if not mountpoint.is_dir():
        fail(f"mountpoint is not a directory: {mountpoint}")
    if any(mountpoint.iterdir()):
        fail(f"mountpoint is not empty: {mountpoint}")
    mounted = run(
        ["findmnt", "--noheadings", "--mountpoint", str(mountpoint)],
        capture=True,
        allowed_returncodes=(0, 1),
    )
    if mounted.returncode == 0:
        fail(f"mountpoint is already in use: {mountpoint}")
    return False


def create(args: argparse.Namespace) -> None:
    if args.size_mib < MIN_SIZE_MIB:
        fail(f"SIZE_MIB must be at least {MIN_SIZE_MIB}")
    require("cryptsetup", "findmnt", "mkfs.ext4")
    destination = new_file_path(args.container)
    temp = create_temp_path(destination)
    name: str | None = None
    try:
        allocate(temp, args.size_mib)
        format_luks(temp)
        name = mapping_name(temp)
        open_mapping(temp, name)
        uid, gid = owner_ids()
        run(
            [
                "mkfs.ext4",
                "-q",
                "-E",
                f"root_owner={uid}:{gid}",
                "-L",
                "efs",
                str(mapper_path(name)),
            ],
            root=True,
        )
        close_mapping(name, unmount=False)
        name = None
        publish(temp, destination)
        print(f"Created encrypted container: {destination}")
    finally:
        if name is not None:
            try:
                close_mapping(name, unmount=False)
            except EfsError as error:
                print(f"efs: cleanup warning: {error}", file=sys.stderr)
        if temp.exists():
            temp.unlink()


def open_container(args: argparse.Namespace) -> None:
    require("cryptsetup", "findmnt", "mount", "umount")
    container = existing_file(args.container)
    name = mapping_name(container)
    if args.mountpoint:
        mountpoint = Path(args.mountpoint).absolute()
        allow_root_create = False
    else:
        mountpoint = Path("/mnt") / name
        allow_root_create = True

    created_mountpoint = False
    mapper = mapper_path(name)
    with lock_container(container):
        try:
            if mapper.exists():
                targets = mounted_targets(mapper)
                if targets:
                    fail(f"container is already open at {targets[0]}")
                fail(f"container mapping is already open as {name}")

            created_mountpoint = prepare_mountpoint(
                mountpoint, allow_root_create=allow_root_create
            )

            try:
                open_mapping(container, name)
                run(
                    ["mount", "-o", "nodev,nosuid", str(mapper), str(mountpoint)],
                    root=True,
                )
            except EfsError:
                if mapper.exists():
                    close_mapping(name, unmount=False)
                raise
            print(f"Opened {container} at {mountpoint}")
        except Exception:
            if created_mountpoint:
                try:
                    mountpoint.rmdir()
                except OSError:
                    pass
            raise


def close_container(args: argparse.Namespace) -> None:
    require("cryptsetup", "findmnt", "umount")
    container = existing_file(args.container)
    name = mapping_name(container)
    with lock_container(container):
        mapper = mapper_path(name)
        if not mapper.exists():
            fail(f"container is not open: {container}")
        targets = mounted_targets(mapper)
        if not targets:
            fail(f"container is mapped but not mounted; close it manually as {name}")
        close_mapping(name, unmount=True)
    print(f"Closed encrypted container: {container}")


def status(args: argparse.Namespace) -> None:
    require("cryptsetup", "findmnt")
    container = existing_file(args.container)
    name = mapping_name(container)
    mapper = mapper_path(name)
    if not mapper.exists():
        print("closed")
        return
    targets = mounted_targets(mapper)
    if targets:
        print("open at " + ", ".join(map(str, targets)))
    else:
        print(f"mapped but not mounted as {name}")


def grow(args: argparse.Namespace) -> None:
    """Grow a closed container and its ext4 filesystem."""
    if args.size_mib < MIN_SIZE_MIB:
        fail(f"SIZE_MIB must be at least {MIN_SIZE_MIB}")
    require("cryptsetup", "e2fsck", "findmnt", "resize2fs")
    container = existing_file(args.container)
    requested_bytes = args.size_mib * 1024 * 1024
    name = mapping_name(container)

    with lock_container(container):
        mapper = mapper_path(name)
        if mapper.exists():
            targets = mounted_targets(mapper)
            if targets:
                fail(f"close the container before growing it; open at {targets[0]}")
            fail(f"close the existing mapping before growing it: {name}")

        current_bytes = container.stat().st_size
        if requested_bytes < current_bytes:
            current_mib = (current_bytes + 1024 * 1024 - 1) // (1024 * 1024)
            fail(
                f"shrinking is not supported; current container size is "
                f"approximately {current_mib} MiB"
            )

        # Equality is allowed so an interrupted grow can safely be resumed.
        if requested_bytes > current_bytes:
            allocate(container, args.size_mib)

        opened = False
        try:
            open_mapping(container, name)
            opened = True
            run(
                ["e2fsck", "-f", "-p", str(mapper)],
                root=True,
                allowed_returncodes=(0, 1),
            )
            run(["resize2fs", str(mapper)], root=True)
        finally:
            if opened:
                close_mapping(name, unmount=False)

    print(f"Grew encrypted container to {args.size_mib} MiB: {container}")


def migrate(args: argparse.Namespace) -> None:
    require("cryptsetup", "e2fsck", "findmnt", "openssl")
    legacy = existing_file(args.legacy_aes)
    destination = new_file_path(args.new_container)
    size_mib = max(
        MIN_SIZE_MIB,
        (legacy.stat().st_size + 1024 * 1024 - 1) // (1024 * 1024)
        + MIGRATION_OVERHEAD_MIB,
    )
    temp = create_temp_path(destination)
    name: str | None = None
    try:
        allocate(temp, size_mib)
        format_luks(temp)
        name = mapping_name(temp)
        open_mapping(temp, name)
        mapper = mapper_path(name)
        print("Enter the OLD OpenSSL passphrase.", file=sys.stderr)
        run(
            [
                "openssl",
                "enc",
                "-d",
                "-aes-256-cbc",
                "-md",
                args.digest,
                "-in",
                str(legacy),
                "-out",
                str(mapper),
            ],
            root=True,
        )
        run(["e2fsck", "-fn", str(mapper)], root=True)
        close_mapping(name, unmount=False)
        name = None
        publish(temp, destination)
        print(f"Migrated to encrypted container: {destination}")
        print(f"The legacy encrypted file was preserved: {legacy}")
    finally:
        if name is not None:
            try:
                close_mapping(name, unmount=False)
            except EfsError as error:
                print(f"efs: cleanup warning: {error}", file=sys.stderr)
        if temp.exists():
            temp.unlink()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Manage a portable ext4 filesystem in a LUKS2 file."
    )
    commands = result.add_subparsers(dest="command", required=True)

    create_parser = commands.add_parser("create", help="create a new container")
    create_parser.add_argument("container")
    create_parser.add_argument("size_mib", type=int, metavar="SIZE_MIB")
    create_parser.set_defaults(handler=create)

    open_parser = commands.add_parser("open", help="unlock and mount a container")
    open_parser.add_argument("container")
    open_parser.add_argument("mountpoint", nargs="?")
    open_parser.set_defaults(handler=open_container)

    close_parser = commands.add_parser("close", help="unmount and lock a container")
    close_parser.add_argument("container")
    close_parser.set_defaults(handler=close_container)

    status_parser = commands.add_parser("status", help="show container state")
    status_parser.add_argument("container")
    status_parser.set_defaults(handler=status)

    grow_parser = commands.add_parser(
        "grow", help="grow a closed container and its ext4 filesystem"
    )
    grow_parser.add_argument("container")
    grow_parser.add_argument("size_mib", type=int, metavar="NEW_SIZE_MIB")
    grow_parser.set_defaults(handler=grow)

    migrate_parser = commands.add_parser(
        "migrate", help="convert an original OpenSSL-CBC efs image"
    )
    migrate_parser.add_argument("legacy_aes")
    migrate_parser.add_argument("new_container")
    migrate_parser.add_argument(
        "--digest", choices=("md5", "sha256"), default="md5",
        help="old OpenSSL password digest (default: md5)",
    )
    migrate_parser.set_defaults(handler=migrate)
    return result


def interrupted(_signum: int, _frame: object) -> NoReturn:
    raise KeyboardInterrupt


def main(argv: Sequence[str] | None = None) -> int:
    signal.signal(signal.SIGTERM, interrupted)
    try:
        args = parser().parse_args(argv)
        args.handler(args)
        return 0
    except EfsError as error:
        print(f"efs: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"efs: operating-system error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("efs: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
