"""Tests for encryption layer."""

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from aegisvault.security.crypto import decrypt_file_stream, encrypt_file_stream
from aegisvault.security.keytree import derive_file_key, derive_vault_key, generate_salt


@pytest.fixture
def vault_key() -> bytes:
    """Fixture for a deterministic test vault key."""
    master = b"0" * 32
    return derive_vault_key(master)


def test_encrypt_decrypt_roundtrip(tmp_path: Path, vault_key: bytes) -> None:
    """Encrypt and decrypt a file, ensuring roundtrip correctness."""
    source = tmp_path / "secret.txt"
    destination = tmp_path / "secret.txt.vault"
    decrypted = tmp_path / "secret_decrypted.txt"
    secret = b"This is a secret message for AegisVault."
    source.write_bytes(secret)

    salt = generate_salt()
    file_key = derive_file_key(vault_key, salt)
    encrypt_file_stream(source, destination, file_key, salt)

    assert destination.exists()
    assert destination.stat().st_size > 32 + 12 + 16

    decrypt_file_stream(destination, decrypted, file_key)
    assert decrypted.read_bytes() == secret


def test_tampered_vault_fails(tmp_path: Path, vault_key: bytes) -> None:
    """Tampered ciphertext must fail GCM authentication."""
    source = tmp_path / "secret.txt"
    destination = tmp_path / "secret.txt.vault"
    decrypted = tmp_path / "secret_decrypted.txt"
    source.write_bytes(b"tamper test")

    salt = generate_salt()
    file_key = derive_file_key(vault_key, salt)
    encrypt_file_stream(source, destination, file_key, salt)

    data = destination.read_bytes()
    data = data[:-1] + bytes([data[-1] ^ 0xFF])
    destination.write_bytes(data)

    with pytest.raises((InvalidTag, ValueError)):
        decrypt_file_stream(destination, decrypted, file_key)
