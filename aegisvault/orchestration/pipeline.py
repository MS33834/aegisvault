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
from aegisvault.model.embedding import LocalEmbeddingProvider
from aegisvault.orchestration.state_machine import StateMachine, TaskState
from aegisvault.orchestration.task_store import TaskStore
from aegisvault.security.audit_log import AuditLogger
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
        audit_logger: AuditLogger | None = None,
        embedding_provider: LocalEmbeddingProvider | None = None,
    ) -> None:
        self.config = config
        self.classifier = classifier
        self.task_store = task_store
        self.audit_logger = audit_logger
        self.embedding_provider = embedding_provider
        self.vault_manager = vault_manager or VaultManager(
            config.paths.vault,
            vault_key,
            audit_logger=audit_logger,
        )

    async def process(self, event: FileEvent) -> TaskStatus:
        """Process a file event from creation to Vault storage."""
        task_id = event.event_id
        sm = StateMachine(task_id, TaskState.IDLE)

        self.task_store.create(task_id, event.source_path)
        sm.transition(TaskState.CLASSIFYING)
        self.task_store.update_state(task_id, TaskState.CLASSIFYING)

        if self.audit_logger is not None:
            self.audit_logger.log(
                "file_ingested",
                {
                    "task_id": str(task_id),
                    "source_path": str(event.source_path),
                },
            )

        try:
            classification = await self._classify(event.source_path)
            self.task_store.update_classification(task_id, classification)
            if self.audit_logger is not None:
                self.audit_logger.log(
                    "classified",
                    {
                        "task_id": str(task_id),
                        "sensitivity": classification.sensitivity.value,
                        "category": classification.category,
                    },
                )

            sm.transition(TaskState.ENCRYPTING)
            self.task_store.update_state(task_id, TaskState.ENCRYPTING)

            result = self._encrypt(event.source_path, classification, task_id)
            self.task_store.update_vault_result(
                task_id, result.vault_path, result.salt, result.nonce
            )

            sm.transition(TaskState.INDEXING)
            self.task_store.update_state(task_id, TaskState.INDEXING)
            self._index(classification, result)

            # Secure delete before marking complete so failures don't cause state regression
            try:
                self._secure_delete(event.source_path)
            except OSError as exc:
                logger.warning("Secure delete failed for %s: %s", event.source_path, exc)

            sm.transition(TaskState.COMPLETED)
            status = self.task_store.update_state(task_id, TaskState.COMPLETED)
            return status

        except SecurityPolicyError as exc:
            if self.audit_logger is not None:
                self.audit_logger.log(
                    "policy_violation",
                    {
                        "task_id": str(task_id),
                        "error": str(exc),
                    },
                )
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
        require_trusted_local_connection(
            self.classifier.connection,
            audit_logger=self.audit_logger,
            operation="encrypt",
        )
        encrypt_result = self.vault_manager.encrypt(
            source_path,
            classification,
            str(task_id),
        )
        if self.audit_logger is not None:
            self.audit_logger.log(
                "encrypted",
                {
                    "task_id": str(task_id),
                    "vault_path": str(encrypt_result.vault_path),
                },
            )
        return EncryptResult(
            task_id=task_id,
            vault_path=encrypt_result.vault_path,
            salt=encrypt_result.salt,
            nonce=encrypt_result.nonce,
        )

    def _index(
        self,
        classification: ClassificationResult,
        result: EncryptResult,
    ) -> None:
        """Index classification metadata for full-text and semantic search."""
        self.task_store.index_classification(
            task_id=result.task_id,
            classification=classification,
            vault_path=result.vault_path,
        )
        if self.embedding_provider is not None:
            self.task_store.index_embedding(
                task_id=result.task_id,
                vault_path=result.vault_path,
                classification=classification,
                provider=self.embedding_provider,
            )

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
