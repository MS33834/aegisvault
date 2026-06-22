"""Tests for master key providers."""

import os
import stat
from pathlib import Path

import pytest

from aegisvault.security.master_key import (
    FilePasswordProvider,
    TpmMasterKeyProvider,
    create_master_key_provider,
)


def test_file_password_provider_deterministic(tmp_path: Path) -> None:
    """Same password and storage_path produces the same key."""
    p1 = FilePasswordProvider(password="hello-world", storage_path=tmp_path)
    p2 = FilePasswordProvider(password="hello-world", storage_path=tmp_path)
    assert p1.get_key() == p2.get_key()
    assert len(p1.get_key()) == 32
    assert (tmp_path / "filepassword.salt").exists()


def test_file_password_provider_password_file(tmp_path: Path) -> None:
    """Provider can read password from a file."""
    pw_file = tmp_path / "password.txt"
    pw_file.write_text("file-password")
    provider = FilePasswordProvider(password_file=pw_file, storage_path=tmp_path)
    assert provider.exists()
    key = provider.get_key()
    assert len(key) == 32


def test_file_password_provider_rejects_both_args() -> None:
    """Cannot specify both password and password_file."""
    with pytest.raises(ValueError):
        FilePasswordProvider(password="x", password_file=Path("/tmp/pw"))


def test_file_password_provider_different_storage_different_keys(tmp_path: Path) -> None:
    """Different storage_path values must produce different keys for the same password."""
    p1 = FilePasswordProvider(password="hello-world", storage_path=tmp_path / "a")
    p2 = FilePasswordProvider(password="hello-world", storage_path=tmp_path / "b")
    assert p1.get_key() != p2.get_key()


def test_file_password_provider_salt_reloads_after_restart(tmp_path: Path) -> None:
    """A provider created after the salt file exists reuses the persisted salt."""
    p1 = FilePasswordProvider(password="hello-world", storage_path=tmp_path)
    key1 = p1.get_key()

    p2 = FilePasswordProvider(password="hello-world", storage_path=tmp_path)
    key2 = p2.get_key()

    assert key1 == key2
    salt = (tmp_path / "filepassword.salt").read_bytes()
    assert len(salt) == 32


def test_file_password_provider_salt_file_permissions(tmp_path: Path) -> None:
    """The salt file is created with owner-only read/write permissions."""
    provider = FilePasswordProvider(password="hello-world", storage_path=tmp_path)
    provider.get_key()
    salt_path = tmp_path / "filepassword.salt"
    mode = stat.S_IMODE(salt_path.stat().st_mode)
    expected = stat.S_IRUSR | stat.S_IWUSR
    assert mode == expected, f"Expected {oct(expected)}, got {oct(mode)}"


def test_file_password_provider_concurrent_init_converges(tmp_path: Path) -> None:
    """Simulated concurrent initialisation converges on the persisted salt."""
    salt_path = tmp_path / "filepassword.salt"
    salt_path.write_bytes(os.urandom(32))
    p1 = FilePasswordProvider(password="hello-world", storage_path=tmp_path)
    p2 = FilePasswordProvider(password="hello-world", storage_path=tmp_path)
    # Both providers must derive the same key from the pre-existing salt.
    assert p1.get_key() == p2.get_key()


def test_tpm_provider_not_implemented() -> None:
    """TPM provider raises NotImplementedError."""
    provider = TpmMasterKeyProvider(Path("/tmp/dummy"))
    assert not provider.exists()
    with pytest.raises(NotImplementedError):
        provider.get_key()


def test_factory_unknown_provider() -> None:
    """Factory rejects unknown provider names."""
    with pytest.raises(ValueError):
        create_master_key_provider("unknown", Path("/tmp/dummy"))
