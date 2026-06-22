"""Tests for Vault sensitive operation policy enforcement."""

from pathlib import Path
from uuid import uuid4

import pytest

from aegisvault.api.schemas import ClassificationResult
from aegisvault.execution.vault import VaultManager
from aegisvault.platform.models import Connection, PlatformType
from aegisvault.security.keytree import derive_vault_key
from aegisvault.security.policy import SecurityPolicyError


@pytest.fixture
def vault_key() -> bytes:
    """Fixture for a deterministic test vault key."""
    master = b"0" * 32
    return derive_vault_key(master)


@pytest.fixture
def local_connection() -> Connection:
    """Trusted local connection."""
    return Connection(
        name="Local Ollama",
        platform_type=PlatformType.OLLAMA,
        base_url="http://127.0.0.1:11434/v1",
        is_local=True,
    )


@pytest.fixture
def cloud_connection() -> Connection:
    """Unauthorized cloud connection."""
    return Connection(
        name="Cloud OpenAI",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
    )


def test_vault_encrypt_rejects_cloud(
    tmp_path: Path,
    vault_key: bytes,
    cloud_connection: Connection,
) -> None:
    """Vault encryption must reject cloud connections."""
    source = tmp_path / "secret.txt"
    source.write_bytes(b"secret")
    manager = VaultManager(tmp_path / "vault", vault_key)
    classification = ClassificationResult(
        sensitivity="low",
        category="other",
        disguise_name="neutral",
        disguise_extension="log",
    )

    with pytest.raises(SecurityPolicyError):
        manager.encrypt(cloud_connection, source, classification, str(uuid4()))


def test_vault_decrypt_rejects_cloud(
    tmp_path: Path,
    vault_key: bytes,
    cloud_connection: Connection,
) -> None:
    """Vault decryption must reject cloud connections."""
    manager = VaultManager(tmp_path / "vault", vault_key)

    with pytest.raises(SecurityPolicyError):
        manager.decrypt(
            cloud_connection,
            tmp_path / "fake.vault",
            b"0" * 32,
            tmp_path / "out.txt",
        )


def test_vault_encrypt_accepts_local(
    tmp_path: Path,
    vault_key: bytes,
    local_connection: Connection,
) -> None:
    """Vault encryption accepts trusted local connections."""
    source = tmp_path / "secret.txt"
    source.write_bytes(b"secret")
    manager = VaultManager(tmp_path / "vault", vault_key)
    classification = ClassificationResult(
        sensitivity="low",
        category="other",
        disguise_name="neutral",
        disguise_extension="log",
    )

    result = manager.encrypt(local_connection, source, classification, str(uuid4()))
    assert result.vault_path.exists()
