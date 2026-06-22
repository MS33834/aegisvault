"""Agent orchestrator using the processing pipeline."""

import asyncio
import logging
from uuid import UUID

from aegisvault.api.schemas import FileEvent, SearchQuery, SearchResult, TaskStatus
from aegisvault.config import AegisConfig
from aegisvault.execution.inbox_watcher import InboxWatcher
from aegisvault.execution.vault import VaultManager
from aegisvault.model.classifier import Classifier
from aegisvault.model.embedding import LocalEmbeddingProvider, SentenceTransformersProvider
from aegisvault.orchestration.pipeline import ProcessingPipeline
from aegisvault.orchestration.task_store import TaskStore
from aegisvault.platform.manager import ConnectionManager
from aegisvault.security.audit_log import AuditLogger
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
        audit_logger: AuditLogger | None = None,
        embedding_provider: LocalEmbeddingProvider | None = None,
    ) -> None:
        self.config = config
        self.connection_manager = connection_manager or ConnectionManager(config.paths.connections)
        self.task_store = task_store or TaskStore(config.paths.index / "tasks.db")
        self.classifier = classifier or Classifier.from_manager(self.connection_manager)
        self.audit_logger = audit_logger
        if self.audit_logger is not None:
            self.audit_logger.log(
                "login_attempt",
                {"success": True, "component": "AegisAgent"},
            )
        self.master_key_provider = master_key_provider or create_master_key_provider(
            config.security.master_key_provider,
            config.paths.connections.parent / "master_key.bin",
            password=config.security.master_key_password,
        )
        self._embedding_provider = self._create_embedding_provider(embedding_provider)
        vault_key = self.master_key_provider.get_key()
        self.pipeline = ProcessingPipeline(
            config=config,
            classifier=self.classifier,
            task_store=self.task_store,
            vault_key=vault_key,
            vault_manager=vault_manager,
            audit_logger=self.audit_logger,
            embedding_provider=self._embedding_provider,
        )
        self.watcher = watcher
        self._loop: asyncio.AbstractEventLoop | None = None

    def _create_embedding_provider(
        self,
        injected: LocalEmbeddingProvider | None,
    ) -> LocalEmbeddingProvider | None:
        """Resolve the embedding provider, falling back to FTS if unavailable."""
        if injected is not None:
            return injected
        if not self.config.security.enable_semantic_search:
            return None
        try:
            return SentenceTransformersProvider(self.config.security.semantic_model)
        except Exception:
            logger.warning(
                "Semantic search is enabled but the embedding provider is unavailable. "
                "Falling back to full-text search.",
                exc_info=True,
            )
            return None

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
        if self.audit_logger is not None and self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._test_connection(), self._loop)

    def stop_monitoring(self) -> None:
        """Stop watching the Inbox directory."""
        if self.watcher is not None:
            self.watcher.stop()
            self.watcher = None
        self._loop = None

    async def _test_connection(self) -> None:
        """Test the active classifier connection and audit the result."""
        if self.audit_logger is None:
            return
        try:
            healthy = await self.classifier.provider.health()
            self.audit_logger.log(
                "connection_tested",
                {
                    "connection": self.classifier.connection.name,
                    "healthy": healthy,
                },
            )
        except Exception as exc:
            self.audit_logger.log(
                "connection_tested",
                {
                    "connection": self.classifier.connection.name,
                    "healthy": False,
                    "error": str(exc),
                },
            )

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
        """Search vault metadata by keywords and semantic similarity."""
        fts_results = self.task_store.search(query.query, top_k=query.top_k)
        if self._embedding_provider is None:
            return fts_results
        semantic_results = self.task_store.semantic_search(
            query.query,
            top_k=query.top_k,
            provider=self._embedding_provider,
        )
        return _merge_search_results(fts_results, semantic_results, top_k=query.top_k)


def _merge_search_results(
    fts_results: list[SearchResult],
    semantic_results: list[SearchResult],
    top_k: int,
) -> list[SearchResult]:
    """Combine keyword and semantic results using a simple weighted score."""
    if not fts_results:
        return semantic_results[:top_k]
    if not semantic_results:
        return fts_results[:top_k]

    fts_max = max(result.score for result in fts_results)
    fts_scores = {
        str(result.vault_path): result.score / fts_max if fts_max > 0 else 0.0
        for result in fts_results
    }
    semantic_max = max(result.score for result in semantic_results)
    semantic_scores = {
        str(result.vault_path): result.score / semantic_max if semantic_max > 0 else 0.0
        for result in semantic_results
    }

    merged: dict[str, SearchResult] = {}
    for result in fts_results:
        merged[str(result.vault_path)] = result
    for result in semantic_results:
        if str(result.vault_path) not in merged:
            merged[str(result.vault_path)] = result

    combined: list[SearchResult] = []
    for vault_path_key, result in merged.items():
        score = 0.5 * fts_scores.get(vault_path_key, 0.0) + 0.5 * semantic_scores.get(
            vault_path_key, 0.0
        )
        combined.append(result.model_copy(update={"score": score}))

    combined.sort(key=lambda item: item.score, reverse=True)
    return combined[:top_k]
