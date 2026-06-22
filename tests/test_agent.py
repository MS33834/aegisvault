"""Tests for AegisAgent dependency injection."""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from aegisvault.api.schemas import FileEvent, SearchQuery, SearchResult, TaskStatus
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

    def update_state(self, task_id: UUID, state: TaskState, message: str = "") -> TaskStatus:
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


def test_agent_get_status_missing_task_returns_none(
    config: AegisConfig, classifier: Classifier
) -> None:
    """AegisAgent.get_status returns None for unknown task IDs."""
    agent = AegisAgent(
        config,
        task_store=FakeTaskStore(),
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
    )

    assert agent.get_status(uuid4()) is None


async def test_agent_on_file_event_delegates_to_pipeline(
    config: AegisConfig, classifier: Classifier
) -> None:
    """AegisAgent.on_file_event forwards to the processing pipeline."""
    agent = AegisAgent(
        config,
        task_store=FakeTaskStore(),
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
    )
    expected = TaskStatus(task_id=uuid4(), state=TaskState.COMPLETED.name)

    async def fake_process(event: FileEvent) -> TaskStatus:
        return expected

    agent.pipeline.process = fake_process  # type: ignore[method-assign]

    event = FileEvent(event_id=uuid4(), source_path=Path("/tmp/file.txt"))
    result = await agent.on_file_event(event)

    assert result is expected


async def test_agent_search_returns_empty(config: AegisConfig, classifier: Classifier) -> None:
    """AegisAgent.search works with injected dependencies."""
    agent = AegisAgent(
        config,
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
    )

    results = await agent.search(SearchQuery(query="anything"))
    assert results == []


async def test_agent_search_returns_task_store_results(
    config: AegisConfig, classifier: Classifier
) -> None:
    """AegisAgent.search delegates to the task store and returns SearchResults."""

    class TaskStoreWithSearch:
        def search(self, query: str, top_k: int) -> list[SearchResult]:
            return [
                SearchResult(
                    vault_path=Path("/vault/work/report.log"),
                    category="work",
                    summary="A work report",
                    score=1.0,
                )
            ]

    agent = AegisAgent(
        config,
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
        task_store=TaskStoreWithSearch(),  # type: ignore[arg-type]
    )

    results = await agent.search(SearchQuery(query="report"))
    assert len(results) == 1
    assert results[0].category == "work"


def test_agent_start_monitoring_creates_watcher(
    config: AegisConfig, classifier: Classifier
) -> None:
    """start_monitoring creates an InboxWatcher and starts observing."""
    watcher = MagicMock()
    agent = AegisAgent(
        config,
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
        watcher=watcher,
    )

    loop = asyncio.new_event_loop()
    try:
        agent.start_monitoring(loop)
        watcher.start.assert_called_once()
        assert agent._loop is loop
    finally:
        agent.stop_monitoring()
        loop.close()


def test_agent_stop_monitoring_stops_watcher(config: AegisConfig, classifier: Classifier) -> None:
    """stop_monitoring stops the active InboxWatcher."""
    watcher = MagicMock()
    agent = AegisAgent(
        config,
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
        watcher=watcher,
    )

    loop = asyncio.new_event_loop()
    try:
        agent.start_monitoring(loop)
        agent.stop_monitoring()
        watcher.stop.assert_called_once()
        assert agent.watcher is None
        assert agent._loop is None
    finally:
        loop.close()


async def test_agent_on_file_event_sync_schedules_processing(
    config: AegisConfig, classifier: Classifier
) -> None:
    """The synchronous callback schedules async processing on the event loop."""
    agent = AegisAgent(
        config,
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
    )
    processed: list[FileEvent] = []

    async def fake_process(event: FileEvent) -> TaskStatus:
        processed.append(event)
        return TaskStatus(task_id=event.event_id, state=TaskState.COMPLETED.name)

    agent.pipeline.process = fake_process  # type: ignore[method-assign]

    loop = asyncio.get_running_loop()
    agent._loop = loop
    event = FileEvent(event_id=uuid4(), source_path=Path("/tmp/file.txt"))
    agent._on_file_event_sync(event)

    # Give the scheduled coroutine a chance to run.
    await asyncio.sleep(0.1)

    assert len(processed) == 1
    assert processed[0].event_id == event.event_id


def test_agent_on_file_event_sync_without_loop_warns(
    config: AegisConfig, classifier: Classifier, caplog: pytest.LogCaptureFixture
) -> None:
    """Dropping a file event without a loop produces a warning."""
    agent = AegisAgent(
        config,
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
    )

    event = FileEvent(event_id=uuid4(), source_path=Path("/tmp/file.txt"))
    agent._on_file_event_sync(event)

    assert "No event loop configured" in caplog.text


def test_agent_start_monitoring_creates_default_watcher(
    config: AegisConfig, classifier: Classifier, tmp_path: Path
) -> None:
    """start_monitoring creates an InboxWatcher when none is injected."""
    config.paths.inbox = tmp_path / "Inbox"
    agent = AegisAgent(
        config,
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
    )

    loop = asyncio.new_event_loop()
    try:
        agent.start_monitoring(loop)
        assert agent.watcher is not None
        assert agent._loop is loop
    finally:
        agent.stop_monitoring()
        loop.close()


def test_agent_stop_monitoring_without_watcher_is_no_op(
    config: AegisConfig, classifier: Classifier
) -> None:
    """stop_monitoring is safe when no watcher was started."""
    agent = AegisAgent(
        config,
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
    )

    agent.stop_monitoring()
    assert agent.watcher is None
    assert agent._loop is None


async def test_agent_handle_event_logs_exception(
    config: AegisConfig, classifier: Classifier, caplog: pytest.LogCaptureFixture
) -> None:
    """_handle_event logs exceptions from the pipeline."""
    agent = AegisAgent(
        config,
        classifier=classifier,
        master_key_provider=FakeMasterKeyProvider(),
        vault_manager=FakeVaultManager(),
    )

    async def failing_process(event: FileEvent) -> TaskStatus:
        raise ValueError("boom")

    agent.pipeline.process = failing_process  # type: ignore[method-assign]

    event = FileEvent(event_id=uuid4(), source_path=Path("/tmp/file.txt"))
    await agent._handle_event(event)

    assert "boom" in caplog.text
