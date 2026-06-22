"""Master key providers for AegisVault.

A master key is the root secret from which the Vault Key is derived. Providers
control how that root secret is obtained and protected.
"""

import logging
import os
import stat
from abc import ABC, abstractmethod
from pathlib import Path

from aegisvault.security.keytree import generate_salt

logger = logging.getLogger(__name__)


class MasterKeyProvider(ABC):
    """Abstract base for master key acquisition and protection."""

    @abstractmethod
    def get_key(self) -> bytes:
        """Return the raw 32-byte master key."""

    @abstractmethod
    def exists(self) -> bool:
        """Return True if the protected key material is already stored."""


class FilePasswordProvider(MasterKeyProvider):
    """Development provider: derive master key from a password file or env var."""

    _FALLBACK_SALT = b"aegisvault-filepassword-salt-v1"

    def __init__(
        self,
        password: str | None = None,
        password_file: Path | None = None,
        storage_path: Path | None = None,
    ) -> None:
        if password and password_file:
            raise ValueError("Specify either password or password_file, not both")
        self._password = password
        self._password_file = password_file
        self._storage_path = storage_path
        self._key: bytes | None = None

    def _get_or_create_salt(self) -> bytes:
        """Return a persistent per-storage salt, or the fixed fallback salt."""
        if self._storage_path is None:
            # Development fallback: deterministic salt for backward compatibility.
            logger.warning(
                "FilePasswordProvider running without storage_path; "
                "using fixed development salt."
            )
            return self._FALLBACK_SALT
        salt_path = self._storage_path / "filepassword.salt"
        if salt_path.exists():
            return salt_path.read_bytes()

        salt = generate_salt()
        self._storage_path.mkdir(parents=True, exist_ok=True)
        self._atomic_write_salt(salt_path, salt)
        # Re-read from disk so concurrent initialisations always converge on
        # the same persisted salt.
        return salt_path.read_bytes()

    @staticmethod
    def _atomic_write_salt(path: Path, salt: bytes) -> None:
        """Write *salt* to *path* atomically with owner-only permissions.

        Uses O_CREAT | O_EXCL to avoid a TOCTOU race when multiple processes
        initialise the same storage directory for the first time.
        """
        try:
            fd = os.open(
                path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                stat.S_IRUSR | stat.S_IWUSR,
            )
        except FileExistsError:
            return
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(salt)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def get_key(self) -> bytes:
        """Derive master key from password using Argon2id."""
        if self._key is not None:
            return self._key
        password = self._password
        if password is None and self._password_file is not None:
            password = self._password_file.read_text(encoding="utf-8").strip()
        if password is None:
            raise RuntimeError("No password configured for FilePasswordProvider")
        from argon2.low_level import Type, hash_secret_raw

        salt = self._get_or_create_salt()
        self._key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID,
        )
        return self._key

    def exists(self) -> bool:
        """Always True if a password is available."""
        return self._password is not None or (
            self._password_file is not None and self._password_file.exists()
        )


class DpapiMasterKeyProvider(MasterKeyProvider):
    """Windows DPAPI-backed master key provider.

    The master key is generated once, protected with DPAPI for the current
    user, and persisted to disk. It is decrypted silently when needed.
    """

    def __init__(self, storage_path: Path) -> None:
        self.storage_path = storage_path
        self._key: bytes | None = None

    def get_key(self) -> bytes:
        """Return master key, generating and protecting it if necessary."""
        if self._key is not None:
            return self._key
        if not self.exists():
            self._key = generate_salt()
            self._protect_and_store(self._key)
            return self._key
        from aegisvault.security.win_helpers import unprotect_data

        protected = self.storage_path.read_bytes()
        self._key = unprotect_data(protected)
        return self._key

    def exists(self) -> bool:
        """Return True if a protected master key file exists."""
        return self.storage_path.exists()

    def _protect_and_store(self, key: bytes) -> None:
        from aegisvault.security.win_helpers import protect_data

        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        protected = protect_data(key)
        self.storage_path.write_bytes(protected)


class TpmMasterKeyProvider(MasterKeyProvider):
    """TPM-backed master key provider (placeholder for Phase 2+)."""

    def __init__(self, storage_path: Path) -> None:
        self.storage_path = storage_path

    def get_key(self) -> bytes:
        """Not yet implemented."""
        raise NotImplementedError(
            "TPM master key provider is not implemented in this phase. "
            "Use DPAPI or FilePassword on Windows 11."
        )

    def exists(self) -> bool:
        """Return False; TPM provider is not implemented."""
        return False


def create_master_key_provider(
    provider_name: str,
    storage_path: Path,
    password: str | None = None,
    password_file: Path | None = None,
) -> MasterKeyProvider:
    """Factory for master key providers."""
    if provider_name.lower() == "filepassword":
        return FilePasswordProvider(
            password=password,
            password_file=password_file,
            storage_path=storage_path,
        )
    if provider_name.lower() == "dpapi":
        return DpapiMasterKeyProvider(storage_path)
    if provider_name.lower() == "tpm":
        return TpmMasterKeyProvider(storage_path)
    raise ValueError(f"Unknown master key provider: {provider_name}")
