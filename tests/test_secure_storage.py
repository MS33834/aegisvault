"""Tests for secure field-level storage."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from aegisvault.platform.secure_storage import (
    _key_file_path,
    _load_or_create_fallback_key,
    seal,
    unseal,
)


@pytest.fixture
def isolated_key_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Use a temporary key file so tests do not touch the user's home directory."""
    key_path = tmp_path / "storage.key"
    monkeypatch.setenv("AEGISVAULT_STORAGE_KEY_FILE", str(key_path))
    # Force re-evaluation of the cached module-level default by patching the helper.
    monkeypatch.setattr(
        "aegisvault.platform.secure_storage._DEFAULT_KEY_PATH", key_path
    )
    return key_path


def test_empty_value_roundtrip() -> None:
    """Empty strings are passed through unchanged."""
    assert seal("") == ""
    assert unseal("") == ""


def test_fallback_seal_roundtrip(isolated_key_file: Path) -> None:
    """On non-Windows, values are encrypted with AES-256-GCM and prefixed with 'aes:'."""
    original = "secret-api-key"
    sealed = seal(original)
    assert sealed.startswith("aes:")
    assert sealed != original
    assert unseal(sealed) == original


def test_fallback_key_is_persistent(isolated_key_file: Path) -> None:
    """The same key is reused across seal/unseal calls."""
    sealed = seal("secret-one")
    # Re-load the key and decrypt: should succeed without creating a new key.
    assert unseal(sealed) == "secret-one"
    assert isolated_key_file.exists()


def test_fallback_key_warns_on_permissive_permissions(
    isolated_key_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A warning is emitted when the key file has group/other read permissions."""
    isolated_key_file.write_bytes(os.urandom(32))
    isolated_key_file.chmod(0o644)

    with patch(
        "aegisvault.platform.secure_storage.logger.warning"
    ) as mock_warning:
        _load_or_create_fallback_key()

    mock_warning.assert_called_once()
    assert "permissive" in mock_warning.call_args[0][0]


def test_unknown_format_passthrough() -> None:
    """Values without prefix are returned as-is."""
    assert unseal("raw-value") == "raw-value"


def test_key_file_path_respects_env_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """AEGISVAULT_STORAGE_KEY_FILE overrides the default key file path."""
    custom = tmp_path / "custom.key"
    monkeypatch.setenv("AEGISVAULT_STORAGE_KEY_FILE", str(custom))
    assert _key_file_path() == custom
