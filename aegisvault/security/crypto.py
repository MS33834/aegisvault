"""AES-256-GCM streaming encryption."""

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = b"\x01"
SALT_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


def _open_no_follow(path: Path, flags: int, mode: int = 0o600) -> int:
    """Open *path* without following symlinks when supported by the OS."""
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags, mode)


def _atomic_write_bytes(destination: Path, data: bytes) -> None:
    """Write *data* to a temp file in the same directory, then atomically replace.

    The temp file lives next to *destination* so the final rename stays on a
    single filesystem and is atomic.  If anything fails the temp file is removed
    and *destination* is left untouched.
    """
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp_path = destination.with_name(f".{destination.name}.{os.urandom(8).hex()}.tmp")
    try:
        fd = _open_no_follow(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as dst:
            dst.write(data)
        os.replace(tmp_path, destination)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def encrypt_file_stream(
    source: Path,
    destination: Path,
    key: bytes,
    salt: bytes,
) -> bytes:
    """Encrypt source file to destination using AES-256-GCM.

    File format: [1B version][32B salt][12B nonce][ciphertext][16B tag]

    The ciphertext is buffered and written to a temp file which is atomically
    renamed onto *destination* so a crash never leaves a partially written vault.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)

    aad = VERSION + salt
    src_fd = _open_no_follow(source, os.O_RDONLY)
    with os.fdopen(src_fd, "rb") as src:
        plaintext = src.read()
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    _atomic_write_bytes(destination, VERSION + salt + nonce + ciphertext)

    # The last TAG_LEN bytes of ciphertext are the GCM authentication tag.
    return nonce


def decrypt_file_stream(
    source: Path,
    destination: Path,
    key: bytes,
) -> None:
    """Decrypt source file to destination using AES-256-GCM.

    The plaintext is fully recovered and authenticated before *destination* is
    touched, so a failed or tampered decryption can never truncate an existing
    destination file.  The write itself is atomic (temp file + rename).
    """
    aesgcm = AESGCM(key)

    src_fd = _open_no_follow(source, os.O_RDONLY)
    with os.fdopen(src_fd, "rb") as src:
        version = src.read(1)
        if version != VERSION:
            raise ValueError("Unsupported vault file version")
        salt = src.read(SALT_LEN)
        if len(salt) != SALT_LEN:
            raise ValueError("Truncated vault file: short salt")
        nonce = src.read(NONCE_LEN)
        if len(nonce) != NONCE_LEN:
            raise ValueError("Truncated vault file: short nonce")
        ciphertext = src.read()

    aad = version + salt
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    _atomic_write_bytes(destination, plaintext)
