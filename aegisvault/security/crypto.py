"""AES-256-GCM streaming encryption."""

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = b"\x01"
SALT_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


def encrypt_file_stream(
    source: Path,
    destination: Path,
    key: bytes,
    salt: bytes,
    chunk_size: int = 64 * 1024,
) -> bytes:
    """Encrypt source file to destination using AES-256-GCM.

    File format: [1B version][32B salt][12B nonce][ciphertext][16B tag]
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)

    destination.parent.mkdir(parents=True, exist_ok=True)

    aad = VERSION + salt
    with source.open("rb") as src, destination.open("wb") as dst:
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
    chunk_size: int = 64 * 1024,
) -> None:
    """Decrypt source file to destination using AES-256-GCM."""
    aesgcm = AESGCM(key)

    with source.open("rb") as src, destination.open("wb") as dst:
        version = src.read(1)
        if version != VERSION:
            raise ValueError("Unsupported vault file version")
        salt = src.read(SALT_LEN)
        nonce = src.read(NONCE_LEN)
        ciphertext = src.read()

        aad = version + salt
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        dst.write(plaintext)
