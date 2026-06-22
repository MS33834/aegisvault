"""Vault file operations.

Sensitive operations require a trusted local connection context.
"""

from pathlib import Path

from aegisvault.api.schemas import ClassificationResult, EncryptResult
from aegisvault.platform.models import Connection
from aegisvault.security.crypto import decrypt_file_stream, encrypt_file_stream
from aegisvault.security.keytree import derive_file_key, generate_salt
from aegisvault.security.policy import sensitive_operation


class VaultManager:
    """Manage encrypted Vault storage."""

    def __init__(self, vault_path: Path, vault_key: bytes) -> None:
        self.vault_path = vault_path
        self.vault_key = vault_key

    @sensitive_operation
    def encrypt(
        self,
        connection: Connection,
        source: Path,
        classification: ClassificationResult,
        task_id: str,
    ) -> EncryptResult:
        """Encrypt a file into the Vault."""
        salt = generate_salt()
        file_key = derive_file_key(self.vault_key, salt)

        disguise_filename = f"{classification.disguise_name}.{classification.disguise_extension}"
        category_dir = self.vault_path / classification.category
        category_dir.mkdir(parents=True, exist_ok=True)
        vault_path = category_dir / disguise_filename

        nonce = encrypt_file_stream(source, vault_path, file_key, salt)

        return EncryptResult(
            task_id=task_id,  # type: ignore[arg-type]
            vault_path=vault_path,
            salt=salt,
            nonce=nonce,
            tag=b"",  # GCM tag is appended to ciphertext by AESGCM.
        )

    @sensitive_operation
    def decrypt(
        self,
        connection: Connection,
        vault_path: Path,
        salt: bytes,
        destination: Path,
    ) -> None:
        """Decrypt a Vault file to destination."""
        file_key = derive_file_key(self.vault_key, salt)
        decrypt_file_stream(vault_path, destination, file_key)
