"""Field-level encryption for sensitive connection fields.

On Windows 11 uses DPAPI (user-bound).
On other platforms uses AES-256-GCM with a persistent key file stored under
``~/.config/aegisvault/.storage_key`` (or ``AEGISVAULT_STORAGE_KEY_FILE``).
The key file is created with owner-only permissions (0o600) and its
permissions are verified on load.
"""

import base64
import logging
import os
import stat
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


_DEFAULT_KEY_PATH = Path.home() / ".config" / "aegisvault" / ".storage_key"
_KEY_ENV_VAR = "AEGISVAULT_STORAGE_KEY_FILE"


def _is_windows() -> bool:
    """Return True if running on Windows."""
    return sys.platform == "win32"


def _key_file_path() -> Path:
    """Return the path to the fallback storage key file."""
    if _KEY_ENV_VAR in os.environ:
        return Path(os.environ[_KEY_ENV_VAR]).expanduser()
    return _DEFAULT_KEY_PATH


def _load_or_create_fallback_key() -> bytes:
    """Return a 32-byte AES key, generating it if necessary.

    The key file is created with 0o600 permissions. If an existing file has
    overly permissive permissions, a warning is emitted.
    """
    key_path = _key_file_path()
    if key_path.exists():
        mode = key_path.stat().st_mode
        if mode & stat.S_IRWXG or mode & stat.S_IRWXO:
            logger.warning(
                "Storage key file %s has permissive permissions (%o). "
                "Restrict it to owner-only access.",
                key_path,
                stat.S_IMODE(mode),
            )
        return key_path.read_bytes()

    key = os.urandom(32)
    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(
        key_path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
    except Exception:
        os.close(fd)
        raise
    return key


def _fallback_seal(value: str) -> str:
    """Seal *value* using AES-256-GCM with the persistent fallback key."""
    key = _load_or_create_fallback_key()
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), None)
    blob = nonce + ciphertext
    return f"aes:{base64.b64encode(blob).decode('ascii')}"


def _fallback_unseal(value: str) -> str:
    """Unseal an AES-256-GCM encrypted value."""
    key = _load_or_create_fallback_key()
    raw = base64.b64decode(value[4:].encode("ascii"))
    nonce, ciphertext = raw[:12], raw[12:]
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def seal(value: str) -> str:
    """Seal a sensitive string.

    On Windows returns base64(DPAPI(plaintext)) prefixed with 'dpapi:'.
    On other platforms returns AES-256-GCM ciphertext prefixed with 'aes:'.
    """
    if not value:
        return value
    if not _is_windows():
        return _fallback_seal(value)

    from aegisvault.security.win_helpers import protect_data

    protected = protect_data(value.encode("utf-8"))
    return f"dpapi:{base64.b64encode(protected).decode('ascii')}"


def unseal(value: str) -> str:
    """Unseal a sensitive string."""
    if not value:
        return value
    if value.startswith("aes:"):
        return _fallback_unseal(value)
    if value.startswith("dpapi:"):
        if not _is_windows():
            raise RuntimeError("Cannot unseal DPAPI value on non-Windows platform")
        from aegisvault.security.win_helpers import unprotect_data

        protected = base64.b64decode(value[6:].encode("ascii"))
        return unprotect_data(protected).decode("utf-8")
    return value


def seal_dict(data: dict[str, Any], fields: set[str]) -> dict[str, Any]:
    """Seal specified string fields in a dictionary."""
    result: dict[str, Any] = {}
    for key, val in data.items():
        if key in fields and isinstance(val, str):
            result[key] = seal(val)
        else:
            result[key] = val
    return result


def unseal_dict(data: dict[str, Any], fields: set[str]) -> dict[str, Any]:
    """Unseal specified string fields in a dictionary."""
    result: dict[str, Any] = {}
    for key, val in data.items():
        if key in fields and isinstance(val, str):
            result[key] = unseal(val)
        else:
            result[key] = val
    return result
