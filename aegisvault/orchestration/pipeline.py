"""End-to-end file processing pipeline: Inbox -> Classify -> Encrypt -> Vault."""

import logging
import os
from pathlib import Path
from uuid import UUID

from aegisvault.api.schemas import (
    ClassificationResult,
    EncryptResult,
    FileEvent,
    TaskStatus,
)
from aegisvault.config import AegisConfig
from aegisvault.execution.vault import VaultManager
from aegisvault.model.classifier import Classifier
from aegisvault.orchestration.state_machine import StateMachine, TaskState
from aegisvault.orchestration.task_store import TaskStore
from aegisvault.security.policy import SecurityPolicyError, require_trusted_local_connection

logger = logging.getLogger(__name__)


class ProcessingPipeline:
    """Orchestrate the full lifecycle of an Inbox file."""

    def __init__(
        self,
        config: AegisConfig,
        classifier: Classifier,
        task_store: TaskStore,
        vault_key: bytes,
        vault_manager: VaultManager | None = None,
    ) -> None:
        self.config = config
        self.classifier = classifier
        self.task_store = task_store
        self.vault_manager = vault_manager or VaultManager(config.paths.vault, vault_key)

    async def process(self, event: FileEvent) -> TaskStatus:
        """Process a file event from creation to Vault storage."""
        task_id = event.event_id
        sm = StateMachine(task_id, TaskState.IDLE)

        self.task_store.create(task_id, event.source_path)
        sm.transition(TaskState.CLASSIFYING)
        self.task_store.update_state(task_id, TaskState.CLASSIFYING)

        try:
            classification = await self._classify(event.source_path)
            self.task_store.update_classification(task_id, classification)

            sm.transition(TaskState.ENCRYPTING)
            self.task_store.update_state(task_id, TaskState.ENCRYPTING)

            result = self._encrypt(event.source_path, classification, task_id)
            self.task_store.update_vault_result(
                task_id, result.vault_path, result.salt, result.nonce
            )

            sm.transition(TaskState.INDEXING)
            self.task_store.update_state(task_id, TaskState.INDEXING)
            self._index(classification, result)

            sm.transition(TaskState.COMPLETED)
            status = self.task_store.update_state(task_id, TaskState.COMPLETED)
            self._secure_delete(event.source_path)
            return status

        except SecurityPolicyError as exc:
            sm.transition(TaskState.QUARANTINED)
            return self.task_store.update_state(task_id, TaskState.QUARANTINED, str(exc))
        except Exception as exc:  # noqa: BLE001
            sm.transition(TaskState.FAILED)
            logger.exception("Pipeline failed for task %s", task_id)
            return self.task_store.update_state(task_id, TaskState.FAILED, str(exc))

    async def _classify(self, source_path: Path) -> ClassificationResult:
        """Classify the file using the configured model connection."""
        return await self.classifier.classify(source_path)

    def _encrypt(
        self,
        source_path: Path,
        classification: ClassificationResult,
        task_id: UUID,
    ) -> EncryptResult:
        """Encrypt file into Vault after validating the connection is trusted local."""
        require_trusted_local_connection(self.classifier.connection)
        encrypt_result = self.vault_manager.encrypt(
            source_path,
            classification,
            str(task_id),
        )
        return EncryptResult(
            task_id=task_id,
            vault_path=encrypt_result.vault_path,
            salt=encrypt_result.salt,
            nonce=encrypt_result.nonce,
            tag=encrypt_result.tag,
        )

    def _index(
        self,
        classification: ClassificationResult,
        result: EncryptResult,
    ) -> None:
        """Index metadata for later retrieval (stub)."""
        index_dir = self.config.paths.index
        index_dir.mkdir(parents=True, exist_ok=True)
        # Phase 3: implement vector + metadata index.

    def _secure_delete(self, source_path: Path) -> None:
        """Overwrite and delete original Inbox file.

        On systems with full-disk encryption this is a best-effort wipe;
        rely on FDE for the underlying security boundary.
        """
        if not source_path.exists():
            return
        size = source_path.stat().st_size
        with source_path.open("r+b") as f:
            f.write(os.urandom(size))
            f.flush()
        source_path.unlink()
