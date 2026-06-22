"""Tests for master key providers."""

import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aegisvault.security.master_key import (
    _REGISTRY,
    DpapiMasterKeyProvider,
    FilePasswordProvider,
    TpmMasterKeyProvider,
    create_master_key_provider,
    get_registered_providers,
    register_provider,
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


def test_file_password_provider_no_storage_path_uses_ephemeral_salt(caplog) -> None:
    """Without storage_path a random ephemeral salt is used and a warning is logged."""
    provider = FilePasswordProvider(password="hello-world")
    key1 = provider.get_key()
    key2 = provider.get_key()
    assert len(key1) == 32
    # Same instance caches the ephemeral salt.
    assert key1 == key2
    assert "ephemeral random salt" in caplog.text


def test_file_password_provider_salt_is_cached_in_memory(tmp_path: Path) -> None:
    """_get_or_create_salt returns the cached value on subsequent calls."""
    provider = FilePasswordProvider(password="hello-world", storage_path=tmp_path)
    salt1 = provider._get_or_create_salt()
    salt2 = provider._get_or_create_salt()
    assert salt1 == salt2
    # And it matches the file.
    assert salt1 == (tmp_path / "filepassword.salt").read_bytes()


def test_file_password_provider_atomic_write_existing_salt(tmp_path: Path) -> None:
    """Atomic write returns silently when the salt file already exists."""
    salt_path = tmp_path / "filepassword.salt"
    salt_path.write_bytes(os.urandom(32))
    provider = FilePasswordProvider(password="hello-world", storage_path=tmp_path)
    key = provider.get_key()
    assert len(key) == 32


def test_file_password_provider_atomic_write_existing_file_directly(tmp_path: Path) -> None:
    """The atomic helper itself returns silently when the target file exists."""
    salt_path = tmp_path / "filepassword.salt"
    salt_path.write_bytes(os.urandom(32))
    FilePasswordProvider._atomic_write_salt(salt_path, b"new-salt")
    assert salt_path.read_bytes() != b"new-salt"


def test_file_password_provider_atomic_write_closes_fd_on_error(
    tmp_path: Path, monkeypatch
) -> None:
    """If writing fails the file descriptor is closed before the exception propagates."""
    fake_fd = 12345
    closed_fds = []

    def fake_open(path, flags, mode):
        return fake_fd

    def fake_fdopen(fd, mode):
        raise OSError("simulated write failure")

    def fake_close(fd):
        closed_fds.append(fd)

    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "fdopen", fake_fdopen)
    monkeypatch.setattr(os, "close", fake_close)

    with pytest.raises(OSError, match="simulated write failure"):
        FilePasswordProvider._atomic_write_salt(tmp_path / "filepassword.salt", b"x")

    assert closed_fds == [fake_fd]


def test_file_password_provider_atomic_write_ignores_close_oserror(
    tmp_path: Path, monkeypatch
) -> None:
    """An OSError while closing the fd is swallowed before the original exception."""
    fake_fd = 12345

    def fake_open(path, flags, mode):
        return fake_fd

    def fake_fdopen(fd, mode):
        raise OSError("simulated write failure")

    def fake_close(fd):
        raise OSError("close failed")

    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "fdopen", fake_fdopen)
    monkeypatch.setattr(os, "close", fake_close)

    with pytest.raises(OSError, match="simulated write failure"):
        FilePasswordProvider._atomic_write_salt(tmp_path / "filepassword.salt", b"x")


def test_file_password_provider_no_password() -> None:
    """Provider without a password raises RuntimeError."""
    provider = FilePasswordProvider()
    assert not provider.exists()
    with pytest.raises(RuntimeError, match="No password configured"):
        provider.get_key()


def test_tpm_provider_not_implemented() -> None:
    """TPM provider raises NotImplementedError."""
    provider = TpmMasterKeyProvider(Path("/tmp/dummy"))
    assert not provider.exists()
    with pytest.raises(NotImplementedError):
        provider.get_key()


def test_dpapi_provider_exists(tmp_path: Path) -> None:
    """DPAPI provider reflects whether the storage file exists."""
    storage = tmp_path / "master_key.bin"
    provider = DpapiMasterKeyProvider(storage_path=storage)
    assert not provider.exists()
    storage.write_bytes(b"protected")
    assert provider.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="Linux-only degradation test")
def test_dpapi_provider_get_key_on_linux(tmp_path: Path) -> None:
    """DPAPI provider raises a clear error when get_key is called on Linux."""
    provider = DpapiMasterKeyProvider(storage_path=tmp_path / "master_key.bin")
    with pytest.raises(RuntimeError, match="only available on Windows"):
        provider.get_key()


def test_dpapi_provider_protect_and_store_delegates_to_win_helpers(
    tmp_path: Path, monkeypatch
) -> None:
    """_protect_and_store writes the output of win_helpers.protect_data to disk."""
    provider = DpapiMasterKeyProvider(storage_path=tmp_path / "master_key.bin")

    def fake_protect(data: bytes) -> bytes:
        return b"protected:" + data

    monkeypatch.setattr("aegisvault.security.win_helpers.protect_data", fake_protect)
    provider._protect_and_store(b"master-secret")
    assert provider.storage_path.read_bytes() == b"protected:master-secret"


def test_dpapi_provider_generates_and_protects_new_key_on_windows(
    tmp_path: Path, monkeypatch
) -> None:
    """On Windows a missing storage file triggers key generation and protection."""
    provider = DpapiMasterKeyProvider(storage_path=tmp_path / "master_key.bin")

    protected = []

    def fake_protect(data: bytes) -> bytes:
        protected.append(data)
        return b"blob" + data

    monkeypatch.setattr("aegisvault.security.win_helpers.protect_data", fake_protect)
    monkeypatch.setattr(sys, "platform", "win32")

    key = provider.get_key()
    assert len(key) == 32
    assert protected == [key]
    assert provider.storage_path.read_bytes() == b"blob" + key


def test_factory_creates_builtin_providers(tmp_path: Path) -> None:
    """Factory returns the correct built-in provider instances."""
    fp = create_master_key_provider("filepassword", tmp_path, password="x")
    assert isinstance(fp, FilePasswordProvider)

    dp = create_master_key_provider("dpapi", tmp_path / "dpapi.bin")
    assert isinstance(dp, DpapiMasterKeyProvider)

    tpm = create_master_key_provider("tpm", tmp_path / "tpm.bin")
    assert isinstance(tpm, TpmMasterKeyProvider)

    # Case-insensitive lookup.
    assert isinstance(
        create_master_key_provider("FilePassword", tmp_path, password="x"),
        FilePasswordProvider,
    )


def test_factory_unknown_provider() -> None:
    """Factory rejects unknown provider names."""
    with pytest.raises(ValueError):
        create_master_key_provider("unknown", Path("/tmp/dummy"))


def test_register_provider_round_trip(tmp_path: Path) -> None:
    """Custom providers can be registered and instantiated through the factory."""
    before = dict(_REGISTRY)
    try:

        class DummyProvider(FilePasswordProvider):
            pass

        register_provider("dummy", DummyProvider)
        assert "dummy" in get_registered_providers()
        provider = create_master_key_provider("dummy", tmp_path, password="x")
        assert isinstance(provider, DummyProvider)
    finally:
        _REGISTRY.clear()
        _REGISTRY.update(before)


def test_register_provider_rejects_non_provider() -> None:
    """Registering a class that is not a MasterKeyProvider raises TypeError."""
    with pytest.raises(TypeError):
        register_provider("bad", str)


def test_factory_reuses_cached_dpapi_key(tmp_path: Path, monkeypatch) -> None:
    """DPAPI provider caches the decrypted key and does not re-read the file."""
    storage = tmp_path / "master_key.bin"
    storage.write_bytes(b"protected")
    provider = DpapiMasterKeyProvider(storage_path=storage)

    mock_unprotect = MagicMock(return_value=b"decrypted-key")
    monkeypatch.setattr("aegisvault.security.win_helpers.unprotect_data", mock_unprotect)
    monkeypatch.setattr(sys, "platform", "win32")

    assert provider.get_key() == b"decrypted-key"
    assert provider.get_key() == b"decrypted-key"
    mock_unprotect.assert_called_once_with(b"protected")
