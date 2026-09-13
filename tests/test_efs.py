"""Focused safety and cleanup tests for efs."""

import argparse
import gzip
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("efs", Path(__file__).parents[1] / "efs.py")
efs = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(efs)


class PathSafetyTests(unittest.TestCase):
    def test_new_file_path_refuses_an_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "private.efs"
            destination.write_bytes(b"do not replace")
            with self.assertRaisesRegex(efs.EfsError, "already exists"):
                efs.new_file_path(str(destination))
            self.assertEqual(destination.read_bytes(), b"do not replace")

    def test_existing_file_refuses_a_symbolic_link(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            link = Path(directory) / "link"
            target.touch()
            link.symlink_to(target)
            with self.assertRaisesRegex(efs.EfsError, "symbolic link"):
                efs.existing_file(str(link))

    @mock.patch.object(efs, "run")
    def test_empty_existing_mountpoint_uses_exact_mountpoint_check(self, run):
        run.return_value = mock.Mock(returncode=1)
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(efs.prepare_mountpoint(Path(directory)))
        self.assertIn("--mountpoint", run.call_args.args[0])

    @mock.patch.object(efs, "run")
    def test_mounted_target_preserves_spaces(self, run):
        run.return_value = mock.Mock(
            returncode=0,
            stdout='{"filesystems": [{"target": "/media/My Drive/private.mnt"}]}',
        )
        self.assertEqual(
            efs.mounted_targets(Path("/dev/mapper/efs-test")),
            [Path("/media/My Drive/private.mnt")],
        )

    def test_efs_lock_does_not_lock_container_file(self):
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory) / "private.efs"
            container.touch()
            with efs.lock_container(container), container.open("rb") as handle:
                # cryptsetup must be able to take its own lock on this file.
                efs.fcntl.flock(handle, efs.fcntl.LOCK_EX | efs.fcntl.LOCK_NB)


class CryptoCommandTests(unittest.TestCase):
    @mock.patch.object(efs, "run")
    def test_luks_format_uses_argon2id_and_passphrase_verification(self, run):
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory) / "container"
            with container.open("wb") as output:
                output.truncate(8 * 1024 * 1024)
            efs.format_luks(container)
        command = run.call_args.args[0]
        self.assertIn("argon2id", command)
        self.assertIn("1MiB", command)
        self.assertIn("--verify-passphrase", command)
        self.assertEqual(run.call_args.kwargs["root"], True)

    @mock.patch.object(efs, "run")
    def test_large_luks_format_uses_normal_keyslot_area(self, run):
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory) / "container"
            with container.open("wb") as output:
                output.truncate(65 * 1024 * 1024)
            efs.format_luks(container)
        self.assertNotIn("--luks2-keyslots-size", run.call_args.args[0])


class CreateTests(unittest.TestCase):
    def args(self, destination: Path, size: int = 8):
        return argparse.Namespace(container=str(destination), size_mib=size)

    @mock.patch.object(efs, "require")
    @mock.patch.object(efs, "allocate")
    @mock.patch.object(efs, "format_luks")
    @mock.patch.object(efs, "mapping_name", return_value="efs-test")
    @mock.patch.object(efs, "open_mapping")
    @mock.patch.object(efs, "close_mapping")
    @mock.patch.object(efs, "run")
    def test_create_publishes_only_after_formatting(
        self, run, close_mapping, open_mapping, _mapping_name, format_luks,
        _allocate, _require
    ):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "private.efs"
            efs.create(self.args(destination))
            self.assertTrue(destination.is_file())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            format_luks.assert_called_once()
            open_mapping.assert_called_once()
            close_mapping.assert_called_once_with("efs-test", unmount=False)
            self.assertTrue(
                any(value.startswith("root_owner=") for value in run.call_args.args[0])
            )

    @mock.patch.object(efs, "require")
    @mock.patch.object(efs, "allocate")
    @mock.patch.object(efs, "format_luks", side_effect=efs.EfsError("format failed"))
    def test_failed_create_leaves_no_destination(
        self, _format_luks, _allocate, _require
    ):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "private.efs"
            with self.assertRaisesRegex(efs.EfsError, "format failed"):
                efs.create(self.args(destination))
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_rejects_too_small_container_before_creating_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "private.efs"
            with self.assertRaisesRegex(efs.EfsError, "at least 8"):
                efs.create(self.args(destination, 7))
            self.assertFalse(destination.exists())


class GrowTests(unittest.TestCase):
    @mock.patch.object(efs, "require")
    @mock.patch.object(efs, "mapping_name", return_value="efs-test")
    @mock.patch.object(efs, "mapper_path", return_value=Path("/not-open/efs-test"))
    @mock.patch.object(efs, "allocate")
    @mock.patch.object(efs, "open_mapping")
    @mock.patch.object(efs, "close_mapping")
    @mock.patch.object(efs, "run")
    def test_grow_expands_container_then_ext4(
        self, run, close_mapping, open_mapping, allocate, _mapper_path,
        _mapping_name, _require
    ):
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory) / "private.efs"
            container.write_bytes(b"old container")
            args = argparse.Namespace(container=str(container), size_mib=128)
            efs.grow(args)

        allocate.assert_called_once_with(container, 128)
        open_mapping.assert_called_once_with(container, "efs-test")
        close_mapping.assert_called_once_with("efs-test", unmount=False)
        commands = [call.args[0][0] for call in run.call_args_list]
        self.assertEqual(commands, ["e2fsck", "resize2fs"])

    @mock.patch.object(efs, "require")
    @mock.patch.object(efs, "mapping_name", return_value="efs-test")
    @mock.patch.object(efs, "mapper_path", return_value=Path("/not-open/efs-test"))
    def test_grow_refuses_shrink(self, _mapper_path, _mapping_name, _require):
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory) / "private.efs"
            with container.open("wb") as output:
                output.truncate(128 * 1024 * 1024)
            args = argparse.Namespace(container=str(container), size_mib=8)
            with self.assertRaisesRegex(efs.EfsError, "shrinking is not supported"):
                efs.grow(args)


class CompressionTests(unittest.TestCase):
    @mock.patch.object(efs, "require")
    @mock.patch.object(efs, "mapping_name", return_value="efs-test")
    @mock.patch.object(efs, "mapper_path", return_value=Path("/not-open/efs-test"))
    def test_pack_gzip_verifies_then_replaces_container(
        self, _mapper_path, _mapping_name, _require
    ):
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory) / "private.efs"
            original = b"encrypted blocks" + bytes(1024 * 1024)
            container.write_bytes(original)
            args = argparse.Namespace(
                container=str(container), format="gzip", force_large=False
            )
            efs.pack(args)
            archive = Path(f"{container}.gz")
            self.assertFalse(container.exists())
            self.assertEqual(gzip.decompress(archive.read_bytes()), original)

    @mock.patch.object(efs, "require")
    @mock.patch.object(efs, "luks_uuid", return_value="test-uuid")
    @mock.patch.object(efs, "run")
    def test_unpack_gzip_validates_then_replaces_archive(
        self, run, _luks_uuid, _require
    ):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "private.efs.gz"
            original = b"LUKS container bytes"
            archive.write_bytes(gzip.compress(original))
            efs.unpack(argparse.Namespace(archive=str(archive)))
            container = Path(directory) / "private.efs"
            self.assertFalse(archive.exists())
            self.assertEqual(container.read_bytes(), original)
            self.assertEqual(run.call_args.args[0][:2], ["cryptsetup", "isLuks"])

    @mock.patch.object(efs, "require")
    def test_pack_refuses_large_container_without_override(self, _require):
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory) / "private.efs"
            with container.open("wb") as output:
                output.truncate(65 * 1024 * 1024)
            args = argparse.Namespace(
                container=str(container), format="gzip", force_large=False
            )
            with self.assertRaisesRegex(efs.EfsError, "limited to 64 MiB"):
                efs.pack(args)
            self.assertTrue(container.exists())

    @mock.patch.object(efs, "require")
    @mock.patch.object(efs, "mapping_name", return_value="efs-test")
    @mock.patch.object(efs, "mapper_path", return_value=Path("/not-open/efs-test"))
    @mock.patch.object(efs, "run_to_file", side_effect=efs.EfsError("compression failed"))
    def test_failed_pack_preserves_container(
        self, _run_to_file, _mapper_path, _mapping_name, _require
    ):
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory) / "private.efs"
            container.write_bytes(b"encrypted container")
            args = argparse.Namespace(
                container=str(container), format="gzip", force_large=False
            )
            with self.assertRaisesRegex(efs.EfsError, "compression failed"):
                efs.pack(args)
            self.assertTrue(container.exists())
            self.assertFalse(Path(f"{container}.gz").exists())

    @mock.patch.object(efs, "require")
    @mock.patch.object(efs, "run", side_effect=efs.EfsError("not LUKS"))
    def test_failed_unpack_preserves_archive(self, _run, _require):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "private.efs.gz"
            archive.write_bytes(gzip.compress(b"not a LUKS container"))
            with self.assertRaisesRegex(efs.EfsError, "not LUKS"):
                efs.unpack(argparse.Namespace(archive=str(archive)))
            self.assertTrue(archive.exists())
            self.assertFalse((Path(directory) / "private.efs").exists())


if __name__ == "__main__":
    unittest.main()
