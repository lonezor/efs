# efs

`efs` creates a Linux filesystem inside one movable, encrypted file. The file
uses LUKS2 and can be copied to another disk or computer like any other file.
While it is open, Linux decrypts filesystem blocks through device mapper; no
second plaintext filesystem image is created.

## Requirements

- Linux with device mapper support
- Python 3.9 or newer
- `cryptsetup`, `e2fsprogs`, and `util-linux`
- `zstd` for compact transport archives (or `gzip` as a fallback)
- root access through `sudo`, unless already running as root

On Debian and Ubuntu, install the required system tools with:

```sh
sudo apt install cryptsetup e2fsprogs util-linux zstd
```

## Use

Create a small 8 MiB container:

```sh
./efs.py create private.efs 8
```

`private.efs` is a relative path, so this creates the file in the current
working directory. For example, when the command is run from
`/home/lonezor/efs`, the resulting file is `/home/lonezor/efs/private.efs`.
To choose another location, provide an absolute path:

```sh
./efs.py create /media/lonezor/USB/private.efs 1024
```

The number is the container's total size in MiB. Eight MiB is the minimum; the
LUKS2 header uses about 2 MiB, leaving the remainder for ext4. Larger containers
work in exactly the same way: use `1024` for 1 GiB.

For containers up to and including 64 MiB, `cryptsetup` warns that the keyslots
area is very small. This is expected. The compact 1 MiB area makes these tiny
containers practical, but limits how many additional passphrases can be added
later. It does not reduce the strength of the active passphrase or data
encryption. Containers larger than 64 MiB use cryptsetup's normal keyslot area.

Open it at a local mountpoint, or supply another mountpoint:

```sh
./efs.py open private.efs
./efs.py open private.efs /mnt/private
```

When no mountpoint is supplied, the script creates `/mnt/efs-<LUKS UUID>`. This
keeps the decrypted view away from USB and cloud-sync directories. The command
prints the exact path after opening. An explicit mountpoint should likewise be
outside any directory synchronized to cloud storage.

Close it before copying, disconnecting its storage medium, or shutting down:

```sh
./efs.py close private.efs
```

Check whether it is open:

```sh
./efs.py status private.efs
```

## Packing small containers for transport

A mostly empty encrypted container still contains large unwritten zero-filled
regions, so it can compress well for email, cloud storage, and small removable
media. Pack a closed container with:

```sh
./efs.py pack private.efs
```

The default chooses Zstandard when available and creates `private.efs.zst`;
otherwise it creates `private.efs.gz`. The original `.efs` file is removed only
after the archive passes the compressor's integrity check. The archive remains
encrypted and can be copied like any other file.

Restore it before opening or growing it:

```sh
./efs.py unpack private.efs.zst
./efs.py open private.efs
```

`unpack` validates the restored file as LUKS before removing the archive. Packing
is automatic only for containers up to 64 MiB. Larger files take longer and
usually compress less as they fill with encrypted data; override the limit with
`--force-large` if that tradeoff is worthwhile. Use `--format gzip` when the
destination computer does not have Zstandard.

Always close the container before packing it. A packed archive cannot be opened
or grown directly: unpack it, make changes, close it, and pack it again. The
archive's size may reveal roughly how much of the container has been written,
although it does not reveal the stored content.

Grow a closed container to a new total size of 2 GiB:

```sh
./efs.py grow private.efs 2048
```

`grow` only expands containers; it never shrinks them. Close the container
first. If an interruption happens after the outer file grows, run the same
command with the same size again to finish checking and expanding ext4.

The default mount options are `nodev,nosuid`. Files can still be executable.
Add `noexec` to the mount options in `efs.py` if the container only stores
documents and data.

## Moving and backing up containers

Always close the container before copying it. A copy made while it is open can
contain an inconsistent filesystem. Keep normal backups: encryption does not
protect against deletion, media failure, or damage to the LUKS header.

The LUKS UUID travels inside the file, so `efs` recognizes a container after it
is renamed or moved. Do not open two byte-for-byte copies with the same UUID at
the same time. Give a long-lived clone a new UUID with `cryptsetup luksUUID`.

## Migrating an old efs image

The original script produced `fs.ext4.aes` with OpenSSL AES-256-CBC. Migrate it
without writing a plaintext image to disk:

```sh
./efs.py migrate fs.ext4.aes private.efs
```

Archives written by the original 2010-era OpenSSL normally use MD5 for its old
password derivation. If the archive was produced by OpenSSL 1.1.0 or newer and
the default digest was used, select SHA-256:

```sh
./efs.py migrate fs.ext4.aes private.efs --digest sha256
```

Migration asks first for a new LUKS passphrase, then for the old OpenSSL
passphrase. It validates the ext4 filesystem and keeps the old encrypted file.
AES-CBC cannot authenticate old data, so validation can detect many wrong keys
or damaged archives but cannot prove that an archive was not modified.

## Security notes

LUKS2 uses a randomly generated volume key and Argon2id password derivation.
Use a long, unique passphrase. Anyone who controls the Linux computer while the
container is open can read or change its files.

The regular LUKS2 storage mode used here encrypts data but does not authenticate
every disk sector. It is a practical format for portable Linux storage and
protects confidentiality at rest; it is not designed to detect chosen changes
to the encrypted container. LUKS2 authenticated storage through `dm-integrity`
has significant format, space, recovery, and kernel-compatibility tradeoffs and
is outside this small wrapper.
