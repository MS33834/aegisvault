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


def encrypt_file_stream(
    source: Path,
    destination: Path,
    key: bytes,
    salt: bytes,
) -> bytes:
    """Encrypt source file to destination using AES-256-GCM.

    File format: [1B version][32B salt][12B nonce][ciphertext][16B tag]
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    aad = VERSION + salt
    src_fd = _open_no_follow(source, os.O_RDONLY)
    dst_fd = _open_no_follow(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(src_fd, "rb") as src, os.fdopen(dst_fd, "wb") as dst:
        dst.write(VERSION)
        dst.write(salt)
        dst.write(nonce)

        plaintext = src.read()
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        dst.write(ciphertext)

    # The last TAG_LEN bytes of ciphertext are the GCM authentication tag.
    return nonce


def decrypt_file_stream(
    source: Path,
    destination: Path,
    key: bytes,
) -> None:
    """Decrypt source file to destination using AES-256-GCM."""
    aesgcm = AESGCM(key)

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    src_fd = _open_no_follow(source, os.O_RDONLY)
    dst_fd = _open_no_follow(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(src_fd, "rb") as src, os.fdopen(dst_fd, "wb") as dst:
        version = src.read(1)
        if version != VERSION:
            raise ValueError("Unsupported vault file version")
        salt = src.read(SALT_LEN)
        nonce = src.read(NONCE_LEN)
        ciphertext = src.read()

        aad = version + salt
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        dst.write(plaintext)
