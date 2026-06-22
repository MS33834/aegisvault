"""Tests for AegisAgent dependency injection."""

from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aegisvault.api.schemas import SearchQuery, TaskStatus
from aegisvault.config import AegisConfig
from aegisvault.model.classifier import Classifier
from aegisvault.model.provider import ModelProvider
from aegisvault.orchestration.agent import AegisAgent
from aegisvault.orchestration.state_machine import TaskState
from aegisvault.platform.models import Connection, PlatformType
from aegisvault.security.master_key import MasterKeyProvider


class FakeProvider(ModelProvider):
    """Minimal model provider for tests."""

    def __init__(self, response: str = "") -> None:
        self.response = response

    async def chat_completion(self, messages: list[dict[str, object]]) -> str:
        return self.response

    async def health(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class FakeMasterKeyProvider(MasterKeyProvider):
    """Deterministic master key provider for tests."""

    def get_key(self) -> bytes:
        return b"0" * 32

    def exists(self) -> bool:
        return True


class FakeTaskStore:
    """In-memory task store for injection tests."""

    def __init__(self) -> None:
        self._records: dict[str, dict[str, object]] = {}

    def create(self, task_id: UUID, source_path: Path) -> TaskStatus:
        self._records[str(task_id)] = {
            "state": TaskState.IDLE.name,
            "message": "",
        }
        return TaskStatus(task_id=task_id, state=TaskState.IDLE.name)

    def get(self, task_id: UUID) -> dict[str, object] | None:
        return self._records.get(str(task_id))

    def update_state(
        self, task_id: UUID, state: TaskState, message: str = ""
    ) -> TaskStatus:
        self._records[str(task_id)] = {"state": state.name, "message": message}
        return TaskStatus(task_id=task_id, state=state.name, message=message)


class FakeVaultManager:
    """Placeholder vault manager for agent construction tests."""


@pytest.fixture
def config(tmp_path: Path) -> AegisConfig:
    """Test configuration with isolated paths."""
    cfg = AegisConfig()
    cfg.paths.inbox = tmp_path / "Inbox"
    cfg.paths.vault = tmp_path / "Vault"
    cfg.paths.index = tmp_path / "Index"
    cfg.paths.connections = tmp_path / "Config" / "connections.json"
    return cfg


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
    return Classifier(FakeProvider(), local_connection)


def test_agent_get_status_with_injected_task_store(
    config: AegisConfig, classifier: Classifier
) -> None:
    """AegisAgent can use an injected TaskStore."""
    task_store = FakeTaskStore()
    task_id = uuid4()
    task_store._records[str(task_id)] = {
        "state": TaskState.COMPLETED.name,
        "message": "done",
    }

    agent = AegisAgent(
        config,
        task_store=task_store,
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
    )

    status = agent.get_status(task_id)
    assert status is not None
    assert status.state == TaskState.COMPLETED.name
    assert status.message == "done"


async def test_agent_search_returns_empty(
    config: AegisConfig, classifier: Classifier
) -> None:
    """AegisAgent.search works with injected dependencies."""
    agent = AegisAgent(
        config,
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
    )

    results = await agent.search(SearchQuery(query="anything"))
    assert results == []
