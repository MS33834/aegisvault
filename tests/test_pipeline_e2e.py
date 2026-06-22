"""End-to-end tests for the processing pipeline."""

import json
from pathlib import Path
from uuid import uuid4

import pytest

from aegisvault.api.schemas import FileEvent
from aegisvault.config import AegisConfig
from aegisvault.execution.vault import VaultManager
from aegisvault.model.classifier import Classifier
from aegisvault.model.provider import ModelProvider
from aegisvault.orchestration.pipeline import ProcessingPipeline
from aegisvault.orchestration.state_machine import TaskState
from aegisvault.orchestration.task_store import TaskStore
from aegisvault.platform.models import Connection, PlatformType
from aegisvault.security.keytree import derive_vault_key


class FakeProvider(ModelProvider):
    """Fake model provider for testing."""

    def __init__(self, response: str) -> None:
        self.response = response

    async def chat_completion(self, messages: list[dict[str, object]]) -> str:
        return self.response

    async def health(self) -> bool:
        return True

    async def close(self) -> None:
        pass


@pytest.fixture
def local_connection() -> Connection:
    """Trusted local connection for tests."""
    return Connection(
        name="Local Test",
        platform_type=PlatformType.OLLAMA,
        base_url="http://127.0.0.1:11434/v1",
        is_local=True,
    )


@pytest.fixture
def classifier(local_connection: Connection) -> Classifier:
    """Classifier backed by fake provider."""
    response = json.dumps(
        {
            "sensitivity": "medium",
            "category": "work",
            "tags": ["report"],
            "summary": "A work report",
            "disguise_name": "team_building_2023",
            "disguise_extension": "log",
        }
    )
    return Classifier(FakeProvider(response), local_connection)


@pytest.fixture
def config(tmp_path: Path) -> AegisConfig:
    """Test configuration with isolated paths."""
    cfg = AegisConfig()
    cfg.paths.inbox = tmp_path / "Inbox"
    cfg.paths.vault = tmp_path / "Vault"
    cfg.paths.index = tmp_path / "Index"
    return cfg


@pytest.fixture
def vault_key() -> bytes:
    """Deterministic vault key for tests."""
    return derive_vault_key(b"0" * 32)


async def test_pipeline_encrypts_and_deletes_source(
    tmp_path: Path,
    config: AegisConfig,
    classifier: Classifier,
    vault_key: bytes,
) -> None:
    """Full pipeline moves file from Inbox to Vault and deletes source."""
    config.paths.inbox.mkdir(parents=True, exist_ok=True)
    source = config.paths.inbox / "secret.txt"
    source.write_text("top secret report")

    task_store = TaskStore(config.paths.index / "tasks.db")
    pipeline = ProcessingPipeline(config, classifier, task_store, vault_key)

    event = FileEvent(event_id=uuid4(), source_path=source)
    status = await pipeline.process(event)

    record = task_store.get(event.event_id)
    message = record.get("message") if record else "no record"
    assert status.state == TaskState.COMPLETED.name, message
    assert not source.exists()
    assert any(config.paths.vault.rglob("*.log"))

    record = task_store.get(event.event_id)
    assert record is not None
    assert record["vault_path"] is not None


async def test_pipeline_uses_injected_vault_manager(
    tmp_path: Path,
    config: AegisConfig,
    classifier: Classifier,
    vault_key: bytes,
) -> None:
    """ProcessingPipeline accepts an injected VaultManager instance."""
    config.paths.inbox.mkdir(parents=True, exist_ok=True)
    source = config.paths.inbox / "secret.txt"
    source.write_text("injected vault manager")

    task_store = TaskStore(config.paths.index / "tasks.db")
    vault_manager = VaultManager(config.paths.vault, vault_key)
    pipeline = ProcessingPipeline(
        config, classifier, task_store, vault_key, vault_manager=vault_manager
    )

    event = FileEvent(event_id=uuid4(), source_path=source)
    status = await pipeline.process(event)

    record = task_store.get(event.event_id)
    message = record.get("message") if record else "no record"
    assert status.state == TaskState.COMPLETED.name, message
    assert not source.exists()
    assert any(config.paths.vault.rglob("*.log"))
