"""Master key providers for AegisVault.

A master key is the root secret from which the Vault Key is derived. Providers
control how that root secret is obtained and protected.
"""

import contextlib
import hashlib
import logging
import os
import stat
import sys
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from aegisvault.security.keytree import generate_salt

if TYPE_CHECKING:
    from aegisvault.security.audit_log import AuditLogger

logger = logging.getLogger(__name__)


def _secure_zero(value: bytes | None) -> None:
    """Best-effort overwrite of *value* with zeros.

    bytes objects are immutable, so this zeros a temporary mutable copy and
    then drops the reference. The original bytes will remain in memory until
    garbage collected; clearing the reference is the best that can be done
    from pure Python.
    """
    if value is None:
        return
    mutable = bytearray(value)
    for i in range(len(mutable)):
        mutable[i] = 0


# Pluggable provider registry. Built-in providers are registered at import time;
# downstream packages or tests can register additional providers at runtime.
_REGISTRY: dict[str, type["MasterKeyProvider"]] = {}


def register_provider(name: str, provider_cls: type["MasterKeyProvider"]) -> None:
    """Register a master key provider under *name* (case-insensitive)."""
    if not issubclass(provider_cls, MasterKeyProvider):
        raise TypeError("Provider must inherit from MasterKeyProvider")
    _REGISTRY[name.lower()] = provider_cls


def get_registered_providers() -> dict[str, type["MasterKeyProvider"]]:
    """Return a shallow copy of the registered providers map."""
    return dict(_REGISTRY)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write *data* to *path* atomically with owner-only permissions."""
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_bytes(data)
    os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
    tmp_path.replace(path)


class MasterKeyProvider(ABC):
    """Abstract base for master key acquisition and protection."""

    @abstractmethod
    def get_key(self) -> bytes:
        """Return the raw 32-byte master key."""

    @abstractmethod
    def exists(self) -> bool:
        """Return True if the protected key material is already stored."""

    @abstractmethod
    def clear(self) -> None:
        """Clear any cached key material from memory."""


class FilePasswordProvider(MasterKeyProvider):
    """Development provider: derive master key from a password file or env var."""

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
        self._salt: bytes | None = None

    def _get_or_create_salt(self) -> bytes:
        """Return a persistent per-storage salt.

        When *storage_path* is provided the salt is generated once, written to
        disk with owner-only permissions, and reused on subsequent runs. When
        *storage_path* is None a random ephemeral salt is generated for this
        process lifetime; the key will not survive a restart.
        """
        if self._salt is not None:
            return self._salt
        if self._storage_path is None:
            logger.warning(
                "FilePasswordProvider running without storage_path; "
                "using ephemeral random salt (key will not survive restart)."
            )
            self._salt = generate_salt()
            return self._salt
        salt_path = self._storage_path / "filepassword.salt"
        if salt_path.exists():
            self._salt = salt_path.read_bytes()
            return self._salt

        salt = generate_salt()
        self._storage_path.mkdir(parents=True, exist_ok=True)
        self._atomic_write_salt(salt_path, salt)
        # Re-read from disk so concurrent initialisations always converge on
        # the same persisted salt.
        self._salt = salt_path.read_bytes()
        return self._salt

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
        # os.fdopen takes ownership of *fd* once it succeeds; the with-block
        # below then owns closing it. If fdopen itself fails, *fd* is still
        # open and unowned, so close it manually here. (If fh.write fails the
        # with-block's __exit__ has already closed *fd* — closing it again
        # here would raise EBADF, which was the original double-close bug.)
        try:
            fh = os.fdopen(fd, "wb")
        except OSError:
            with contextlib.suppress(OSError):
                os.close(fd)
            raise
        with fh:
            fh.write(salt)

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

    def clear(self) -> None:
        """Clear any cached key material from memory."""
        if self._key is not None:
            _secure_zero(self._key)
            self._key = None


class DpapiMasterKeyProvider(MasterKeyProvider):
    """Windows DPAPI-backed master key provider.

    The master key is generated once, protected with DPAPI for the current
    user, and persisted to disk. It is decrypted silently when needed.

    On non-Windows platforms this provider can be instantiated and queried
    (``exists()``), but ``get_key()`` raises ``RuntimeError`` because DPAPI is
    not available. This allows the same application code to run on Linux while
    selecting a different provider, e.g. ``FilePasswordProvider``.
    """

    def __init__(self, storage_path: Path) -> None:
        self.storage_path = storage_path
        self._key: bytes | None = None

    def get_key(self) -> bytes:
        """Return master key, generating and protecting it if necessary."""
        if self._key is not None:
            return self._key
        if sys.platform != "win32":
            raise RuntimeError(
                "DPAPI master key provider is only available on Windows. "
                "Use FilePasswordProvider on Linux."
            )
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

    def clear(self) -> None:
        """Clear any cached key material from memory."""
        if self._key is not None:
            _secure_zero(self._key)
            self._key = None

    def _protect_and_store(self, key: bytes) -> None:
        from aegisvault.security.win_helpers import protect_data

        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        protected = protect_data(key)
        _atomic_write_bytes(self.storage_path, protected)


class TpmMasterKeyProvider(MasterKeyProvider):
    """TPM-backed master key provider.

    A 32-byte master-key material is generated once, encrypted with a
    persistent TPM RSA key (via ``NCryptEncrypt``), and stored on disk. The
    material can only be recovered by decrypting the blob with the same TPM
    key (via ``NCryptDecrypt``).

    On non-Windows platforms the provider can be instantiated and queried, but
    ``get_key()`` raises ``RuntimeError`` because the TPM/NCrypt API is not
    available. A Linux fallback using ``tpm2_createprimary``/``tpm2_create``/
    ``tpm2_unseal`` is intentionally left as an interface-only placeholder for
    this phase.

    When *hello_salt* is supplied, the raw TPM-protected material is further
    derived through HKDF-SHA256, producing a master key that additionally
    requires Windows Hello (or another source of the salt) to unlock.
    """

    TPM_RSA_KEY_LEN = 2048
    MASTER_KEY_LEN = 32

    def __init__(
        self,
        storage_path: Path,
        tpm_key_name: str = "AegisVaultTPMMasterKey",
        hello_salt: bytes | None = None,
    ) -> None:
        self.storage_path = storage_path
        self.tpm_key_name = tpm_key_name
        self.hello_salt = hello_salt
        self._key: bytes | None = None

    def get_key(self) -> bytes:
        """Return the master key, creating/protecting it if necessary."""
        if self._key is not None:
            return self._key
        if sys.platform != "win32":
            raise RuntimeError(
                "TPM master key provider is only available on Windows. "
                "Use FilePasswordProvider or DPAPI on this platform."
            )
        if not self.exists():
            key_material = generate_salt()
            encrypted = _ncrypt_encrypt_with_persistent_key(
                self.tpm_key_name,
                key_material,
                overwrite=True,
            )
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write_bytes(self.storage_path, encrypted)
        else:
            encrypted = self.storage_path.read_bytes()
            key_material = _ncrypt_decrypt_with_persistent_key(
                self.tpm_key_name,
                encrypted,
            )

        self._key = _derive_final_key(key_material, self.hello_salt)
        return self._key

    def exists(self) -> bool:
        """Return True if the encrypted master-key blob exists."""
        return self.storage_path.exists()

    def clear(self) -> None:
        """Clear any cached key material from memory."""
        if self._key is not None:
            _secure_zero(self._key)
            self._key = None


def _derive_final_key(key_material: bytes, hello_salt: bytes | None) -> bytes:
    """Derive the final 32-byte master key from TPM-decrypted material.

    If *hello_salt* is provided it is used as the HKDF salt, meaning the final
    key can only be produced when the salt (e.g. from Windows Hello) is also
    available. Otherwise *key_material* is returned unchanged.
    """
    if hello_salt is None:
        return key_material
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hello_salt,
        info=b"aegisvault-tpm-hello-v1",
    )
    return hkdf.derive(key_material)


if sys.platform == "win32":
    import ctypes
    import ctypes.wintypes as wintypes

    _MS_PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider"
    _BCRYPT_RSA_ALGORITHM = "RSA"
    _NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080
    _NCRYPT_PAD_PKCS1_FLAG = 0x00000002

    _NCRYPT = ctypes.windll.ncrypt

    def _check_ncrypt_status(status: int, operation: str) -> None:
        """Raise RuntimeError if an NCrypt call returned a non-zero status."""
        if status != 0:
            raise RuntimeError(f"{operation} failed with status 0x{status:08X}")

    def _open_tpm_provider() -> ctypes.c_void_p:
        """Open the Microsoft Platform Crypto Provider (TPM)."""
        provider = ctypes.c_void_p()
        status = _NCRYPT.NCryptOpenStorageProvider(
            ctypes.byref(provider),
            _MS_PLATFORM_CRYPTO_PROVIDER,
            0,
        )
        _check_ncrypt_status(status, "NCryptOpenStorageProvider")
        return provider

    def _get_or_create_persistent_key(
        provider: ctypes.c_void_p,
        key_name: str,
        overwrite: bool,
    ) -> ctypes.c_void_p:
        """Open an existing persisted TPM key or create a new RSA key."""
        key = ctypes.c_void_p()
        flags = _NCRYPT_OVERWRITE_KEY_FLAG if overwrite else 0

        # Try to open an existing persisted key first.
        status = _NCRYPT.NCryptOpenKey(
            provider,
            ctypes.byref(key),
            key_name,
            0,
            0,
        )
        if status == 0:
            return key

        # Not present: create a new persisted RSA key.
        status = _NCRYPT.NCryptCreatePersistedKey(
            provider,
            ctypes.byref(key),
            _BCRYPT_RSA_ALGORITHM,
            key_name,
            0,
            flags,
        )
        _check_ncrypt_status(status, "NCryptCreatePersistedKey")

        key_len = wintypes.DWORD(TpmMasterKeyProvider.TPM_RSA_KEY_LEN)
        status = _NCRYPT.NCryptSetProperty(
            key,
            "Length",
            ctypes.cast(ctypes.byref(key_len), ctypes.POINTER(wintypes.BYTE)),
            ctypes.sizeof(key_len),
            0,
        )
        _check_ncrypt_status(status, "NCryptSetProperty(Length)")

        status = _NCRYPT.NCryptFinalizeKey(key, 0)
        _check_ncrypt_status(status, "NCryptFinalizeKey")
        return key

    def _encrypt_with_key(key: ctypes.c_void_p, plaintext: bytes) -> bytes:
        """Encrypt *plaintext* with the public portion of *key*."""
        input_buf = ctypes.create_string_buffer(plaintext)
        output_len = wintypes.DWORD(0)
        status = _NCRYPT.NCryptEncrypt(
            key,
            ctypes.cast(input_buf, ctypes.POINTER(wintypes.BYTE)),
            len(plaintext),
            None,
            None,
            0,
            ctypes.byref(output_len),
            _NCRYPT_PAD_PKCS1_FLAG,
        )
        _check_ncrypt_status(status, "NCryptEncrypt(size probe)")

        output_buf = ctypes.create_string_buffer(output_len.value)
        status = _NCRYPT.NCryptEncrypt(
            key,
            ctypes.cast(input_buf, ctypes.POINTER(wintypes.BYTE)),
            len(plaintext),
            None,
            ctypes.cast(output_buf, ctypes.POINTER(wintypes.BYTE)),
            output_len.value,
            ctypes.byref(output_len),
            _NCRYPT_PAD_PKCS1_FLAG,
        )
        _check_ncrypt_status(status, "NCryptEncrypt")
        return bytes(output_buf[: output_len.value])

    def _decrypt_with_key(key: ctypes.c_void_p, ciphertext: bytes) -> bytes:
        """Decrypt *ciphertext* using the private key protected by the TPM."""
        input_buf = ctypes.create_string_buffer(ciphertext)
        output_len = wintypes.DWORD(0)
        status = _NCRYPT.NCryptDecrypt(
            key,
            ctypes.cast(input_buf, ctypes.POINTER(wintypes.BYTE)),
            len(ciphertext),
            None,
            None,
            0,
            ctypes.byref(output_len),
            _NCRYPT_PAD_PKCS1_FLAG,
        )
        _check_ncrypt_status(status, "NCryptDecrypt(size probe)")

        output_buf = ctypes.create_string_buffer(output_len.value)
        status = _NCRYPT.NCryptDecrypt(
            key,
            ctypes.cast(input_buf, ctypes.POINTER(wintypes.BYTE)),
            len(ciphertext),
            None,
            ctypes.cast(output_buf, ctypes.POINTER(wintypes.BYTE)),
            output_len.value,
            ctypes.byref(output_len),
            _NCRYPT_PAD_PKCS1_FLAG,
        )
        _check_ncrypt_status(status, "NCryptDecrypt")
        return bytes(output_buf[: output_len.value])

    def _ncrypt_encrypt_with_persistent_key(
        key_name: str,
        plaintext: bytes,
        overwrite: bool,
    ) -> bytes:
        """Encrypt *plaintext* using a persistent TPM RSA key."""
        provider = _open_tpm_provider()
        key = ctypes.c_void_p()
        try:
            key = _get_or_create_persistent_key(provider, key_name, overwrite)
            return _encrypt_with_key(key, plaintext)
        finally:
            if key:
                _NCRYPT.NCryptFreeObject(key)
            _NCRYPT.NCryptFreeObject(provider)

    def _ncrypt_decrypt_with_persistent_key(
        key_name: str,
        ciphertext: bytes,
    ) -> bytes:
        """Decrypt *ciphertext* using a persistent TPM RSA key."""
        provider = _open_tpm_provider()
        key = ctypes.c_void_p()
        try:
            key = _get_or_create_persistent_key(provider, key_name, overwrite=False)
            return _decrypt_with_key(key, ciphertext)
        finally:
            if key:
                _NCRYPT.NCryptFreeObject(key)
            _NCRYPT.NCryptFreeObject(provider)

else:

    def _ncrypt_encrypt_with_persistent_key(
        key_name: str,
        plaintext: bytes,
        overwrite: bool,
    ) -> bytes:
        raise RuntimeError("TPM/NCrypt operations are only available on Windows")

    def _ncrypt_decrypt_with_persistent_key(
        key_name: str,
        ciphertext: bytes,
    ) -> bytes:
        raise RuntimeError("TPM/NCrypt operations are only available on Windows")


# ── Master Key Rotation ──────────────────────────────────────────────────────


def should_rotate_key(creation_time: datetime, max_age_days: int = 90) -> bool:
    """Return True if the key is older than *max_age_days*.

    Parameters
    ----------
    creation_time:
        The timestamp when the current master key was created / last rotated.
    max_age_days:
        Maximum age in days before rotation is recommended. Default 90.
    """
    age = datetime.now(UTC) - creation_time
    return age > timedelta(days=max_age_days)


def _derive_vault_key_from_master(master_key: bytes) -> bytes:
    """Derive vault key from master key using HKDF-SHA256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"aegisvault-vault-key-rotation-v1",
    )
    return hkdf.derive(master_key)


def _encrypt_vault_key(vault_key: bytes, master_key: bytes) -> bytes:
    """Encrypt *vault_key* with *master_key* using AES-256-GCM.

    Returns *nonce* + *ciphertext* (the nonce is 12 bytes, so final length
    is 12 + 32 + 16 = 60 bytes).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    aesgcm = AESGCM(master_key)
    ciphertext = aesgcm.encrypt(nonce, vault_key, b"aegisvault-vault-key-wrap-v1")
    return nonce + ciphertext


def _decrypt_vault_key(wrapped: bytes, master_key: bytes) -> bytes:
    """Decrypt *wrapped* (nonce + ciphertext) with *master_key*."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = wrapped[:12]
    ciphertext = wrapped[12:]
    aesgcm = AESGCM(master_key)
    return aesgcm.decrypt(nonce, ciphertext, b"aegisvault-vault-key-wrap-v1")


def _re_encrypt_vault_files(
    vault_path: Path,
    old_vault_key: bytes,
    new_vault_key: bytes,
    audit_logger: "AuditLogger | None" = None,
) -> int:
    """Re-encrypt every encrypted file under *vault_path* with the new vault key.

    Each file is decrypted with its current file key (old vault key + file salt),
    then re-encrypted with the new file key (new vault key + same file salt).
    The operation is atomic per file (temp file + rename).

    Returns the number of files re-encrypted.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from aegisvault.security.keytree import derive_file_key

    version = b"\x01"
    salt_len = 32
    nonce_len = 12

    count = 0
    # Vault stores encrypted files in category subdirectories.
    if not vault_path.exists() or not vault_path.is_dir():
        return 0

    for category_dir in sorted(vault_path.iterdir()):
        if not category_dir.is_dir():
            continue
        for vault_file in sorted(category_dir.iterdir()):
            if not vault_file.is_file():
                continue
            try:
                data = vault_file.read_bytes()
            except OSError:
                logger.warning("Cannot read vault file %s during rotation", vault_file)
                continue

            if len(data) < 1 + salt_len + nonce_len:
                logger.warning("Skipping truncated vault file %s", vault_file)
                continue

            file_version = data[:1]
            if file_version != version:
                logger.warning("Skipping unknown-version vault file %s", vault_file)
                continue

            salt = data[1 : 1 + salt_len]
            old_nonce = data[1 + salt_len : 1 + salt_len + nonce_len]
            old_ciphertext = data[1 + salt_len + nonce_len :]

            # Decrypt with old file key.
            old_file_key = derive_file_key(old_vault_key, salt)
            aesgcm = AESGCM(old_file_key)
            aad = version + salt
            try:
                plaintext = aesgcm.decrypt(old_nonce, old_ciphertext, aad)
            except Exception:
                logger.warning(
                    "Cannot decrypt vault file %s during rotation (wrong key?)",
                    vault_file,
                )
                continue

            # Re-encrypt with new file key (keep same salt and version).
            new_file_key = derive_file_key(new_vault_key, salt)
            new_nonce = os.urandom(nonce_len)
            aesgcm_new = AESGCM(new_file_key)
            new_ciphertext = aesgcm_new.encrypt(new_nonce, plaintext, aad)

            new_data = version + salt + new_nonce + new_ciphertext

            # Atomic write: temp file in same directory, then rename.
            tmp_path = vault_file.with_name(f".{vault_file.name}.{os.urandom(8).hex()}.tmp")
            tmp_path.write_bytes(new_data)
            os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
            tmp_path.replace(vault_file)

            if audit_logger is not None:
                audit_logger.log(
                    "encrypted",
                    {
                        "operation": "key_rotation",
                        "vault_path": str(vault_file),
                    },
                )

            count += 1

    return count


def rotate_master_key(
    current_provider: "MasterKeyProvider",
    new_provider: "MasterKeyProvider",
    vault_key: bytes,
    storage_path: Path,
    audit_logger: "AuditLogger | None" = None,
) -> "MasterKeyProvider":
    """Rotate the master key to a new provider.

    Performs a full rotation:
    1. Unlock current master key from *current_provider*.
    2. Generate new master key from *new_provider*.
    3. Derive old and new vault keys.
    4. Re-encrypt all vault files with the new vault key.
    5. Atomically replace the master key storage.

    Parameters
    ----------
    current_provider:
        The currently active master key provider.
    new_provider:
        The new provider to rotate to. Must support ``get_key()`` and ``clear()``.
    vault_key:
        The current vault key bytes. Used to validate the old master key.
    storage_path:
        Path to the ``master_key.bin`` file. A backup is created before
        the atomic replacement.
    audit_logger:
        Optional audit logger for recording the rotation.

    Returns
    -------
    The new provider (same as *new_provider*) on success.
    """
    # 1. Unlock current master key.
    old_master_key = current_provider.get_key()
    old_derived_vault_key = _derive_vault_key_from_master(old_master_key)

    # Validate: the derived vault key must match the one currently in use.
    if old_derived_vault_key != vault_key:
        # Clean up and raise.
        current_provider.clear()
        raise ValueError(
            "Master key validation failed: derived vault key does not match "
            "the current vault key."
        )

    # 2. Generate new master key.
    new_master_key = new_provider.get_key()
    new_vault_key = _derive_vault_key_from_master(new_master_key)

    if new_vault_key == old_derived_vault_key:
        # Collision – should not happen with HKDF but be safe.
        current_provider.clear()
        new_provider.clear()
        raise RuntimeError("New vault key collides with old vault key; rotation aborted.")

    # 3. Re-encrypt vault files.
    vault_dir = storage_path.parent.parent / "Vault"
    if vault_dir.exists():
        file_count = _re_encrypt_vault_files(
            vault_dir, old_derived_vault_key, new_vault_key, audit_logger
        )
    else:
        file_count = 0

    # 4. Atomically replace the storage path.  Back up the old file first.
    if storage_path.exists():
        backup_path = storage_path.with_suffix(".bin.bak")
        storage_path.replace(backup_path)

    try:
        # Store the new master key material (or the wrapped vault key).
        # For FilePassword/Dpapi/Tpm providers, the secret is already stored
        # by get_key().  Write a rotation timestamp marker.
        rotation_marker = (
            datetime.now(UTC).isoformat().encode("utf-8")
            + b"\n"
            + hashlib.sha256(new_vault_key).digest()
        )
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_bytes(storage_path.with_name("master_key.bin"), rotation_marker)
    except Exception:
        # 5. Rollback on failure.
        if backup_path and backup_path.exists():
            backup_path.replace(storage_path)
        # Clear sensitive material.
        current_provider.clear()
        new_provider.clear()
        raise

    # 6. Audit log.
    if audit_logger is not None:
        audit_logger.log(
            "master_key_changed",
            {
                "operation": "rotation",
                "provider_type": type(new_provider).__name__,
                "files_re_encrypted": file_count,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )

    # Clear old provider's cached key.
    current_provider.clear()

    return new_provider


def emergency_rotate(
    current_provider: "MasterKeyProvider",
    new_provider: "MasterKeyProvider",
    vault_key: bytes,
    vault_key_backup_path: Path,
    audit_logger: "AuditLogger | None" = None,
) -> bytes:
    """Perform an emergency rotation when a key compromise is detected.

    Unlike :func:`rotate_master_key`, this function does **not** re-encrypt
    all vault files. Instead it:

    1. Wraps (encrypts) the existing *vault_key* with the new master key
       and stores the wrapped blob at *vault_key_backup_path*.
    2. The caller is responsible for using the wrapped vault key with the
       new provider to continue decrypting existing vault files.

    Parameters
    ----------
    current_provider:
        The possibly compromised provider.
    new_provider:
        The new provider to switch to.
    vault_key:
        The current vault key bytes.
    vault_key_backup_path:
        Path where the new-master-key-wrapped vault key blob is stored.
    audit_logger:
        Optional audit logger for forced audit records.

    Returns
    -------
    The new master key bytes so the caller can secure it independently.
    """
    # 1. Validate that current_provider can still produce the vault key.
    old_master = current_provider.get_key()
    old_derived = _derive_vault_key_from_master(old_master)
    if old_derived != vault_key:
        current_provider.clear()
        raise ValueError(
            "Current provider master key does not match the active vault key. "
            "Emergency rotation aborted."
        )

    # 2. Generate new master key and wrap the existing vault key.
    new_master = new_provider.get_key()
    wrapped = _encrypt_vault_key(vault_key, new_master)

    # 3. Store the wrapped vault key atomically.
    vault_key_backup_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_bytes(vault_key_backup_path, wrapped)

    # 4. Force audit logging – this is a security-critical event.
    if audit_logger is not None:
        audit_logger.log(
            "master_key_changed",
            {
                "operation": "emergency_rotation",
                "reason": "key_compromise",
                "provider_type": type(new_provider).__name__,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )

    # 5. Clear sensitive material from old provider.
    current_provider.clear()

    return new_master


def unwrap_vault_key(wrapped_path: Path, master_key: bytes) -> bytes:
    """Unwrap (decrypt) a vault key protected by *master_key*.

    This is the inverse of the wrapping performed by :func:`emergency_rotate`.

    Parameters
    ----------
    wrapped_path:
        Path to the wrapped vault key blob.
    master_key:
        The master key bytes from the current provider.

    Returns
    -------
    The original vault key bytes.
    """
    wrapped = wrapped_path.read_bytes()
    return _decrypt_vault_key(wrapped, master_key)


def create_master_key_provider(
    provider_name: str,
    storage_path: Path,
    password: str | None = None,
    password_file: Path | None = None,
    hello_salt: bytes | None = None,
) -> MasterKeyProvider:
    """Factory for master key providers.

    Looks up the provider in the pluggable registry. Built-in providers are
    registered automatically; custom providers can be added with
    ``register_provider``.
    """
    name = provider_name.lower()
    # Built-ins are constructed directly so mypy can verify their signatures.
    if name == "filepassword":
        return FilePasswordProvider(
            password=password,
            password_file=password_file,
            storage_path=storage_path,
        )
    if name == "dpapi":
        return DpapiMasterKeyProvider(storage_path)
    if name == "tpm":
        return TpmMasterKeyProvider(storage_path, hello_salt=hello_salt)
    provider_cls = _REGISTRY.get(name)
    if provider_cls is None:
        raise ValueError(f"Unknown master key provider: {provider_name}")
    # Custom providers are expected to accept a single ``storage_path`` argument.
    return provider_cls(storage_path)  # type: ignore[call-arg]


# Register built-in providers.
register_provider("filepassword", FilePasswordProvider)
register_provider("dpapi", DpapiMasterKeyProvider)
register_provider("tpm", TpmMasterKeyProvider)
