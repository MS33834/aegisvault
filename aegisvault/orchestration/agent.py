"""Agent orchestrator using the processing pipeline."""

import asyncio
import logging
from uuid import UUID

from aegisvault.api.schemas import FileEvent, SearchQuery, SearchResult, TaskStatus
from aegisvault.config import AegisConfig
from aegisvault.execution.inbox_watcher import InboxWatcher
from aegisvault.execution.vault import VaultManager
from aegisvault.model.classifier import Classifier
from aegisvault.orchestration.pipeline import ProcessingPipeline
from aegisvault.orchestration.task_store import TaskStore
from aegisvault.platform.manager import ConnectionManager
from aegisvault.security.master_key import MasterKeyProvider, create_master_key_provider

logger = logging.getLogger(__name__)


class AegisAgent:
    """Main agent orchestrator."""

    def __init__(
        self,
        config: AegisConfig,
        connection_manager: ConnectionManager | None = None,
        task_store: TaskStore | None = None,
        classifier: Classifier | None = None,
        master_key_provider: MasterKeyProvider | None = None,
        vault_manager: VaultManager | None = None,
        watcher: InboxWatcher | None = None,
    ) -> None:
        self.config = config
        self.connection_manager = connection_manager or ConnectionManager(config.paths.connections)
        self.task_store = task_store or TaskStore(config.paths.index / "tasks.db")
        self.classifier = classifier or Classifier.from_manager(self.connection_manager)
        self.master_key_provider = master_key_provider or create_master_key_provider(
            config.security.master_key_provider,
            config.paths.connections.parent / "master_key.bin",
            password=config.security.master_key_password,
        )
        vault_key = self.master_key_provider.get_key()
        self.pipeline = ProcessingPipeline(
            config=config,
            classifier=self.classifier,
            task_store=self.task_store,
            vault_key=vault_key,
            vault_manager=vault_manager,
        )
        self.watcher = watcher
        self._loop: asyncio.AbstractEventLoop | None = None

    async def on_file_event(self, event: FileEvent) -> TaskStatus:
        """Handle a new file event end-to-end."""
        return await self.pipeline.process(event)

    def _on_file_event_sync(self, event: FileEvent) -> None:
        """Schedule async file processing on the running event loop."""
        if self._loop is None:
            logger.warning("No event loop configured; dropping file event %s", event.event_id)
            return
        asyncio.run_coroutine_threadsafe(self._handle_event(event), self._loop)

    async def _handle_event(self, event: FileEvent) -> None:
        """Process a file event and log failures."""
        try:
            await self.on_file_event(event)
        except Exception:
            logger.exception("Failed to process file event %s", event.event_id)

    def start_monitoring(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Start watching the configured Inbox directory."""
        self._loop = loop or asyncio.get_running_loop()
        if self.watcher is None:
            self.watcher = InboxWatcher(self.config.paths.inbox, self._on_file_event_sync)
        self.watcher.start()

    def stop_monitoring(self) -> None:
        """Stop watching the Inbox directory."""
        if self.watcher is not None:
            self.watcher.stop()
            self.watcher = None
        self._loop = None

    def get_status(self, task_id: UUID) -> TaskStatus | None:
        """Fetch task status from the store."""
        record = self.task_store.get(task_id)
        if record is None:
            return None
        return TaskStatus(
            task_id=task_id,
            state=str(record["state"]),
            message=str(record.get("message", "")),
        )

    async def search(self, query: SearchQuery) -> list[SearchResult]:
        """Search Vault metadata by keywords."""
        return self.task_store.search(query.query, top_k=query.top_k)
