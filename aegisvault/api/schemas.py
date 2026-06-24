"""Pydantic schemas for inter-layer messaging."""

from enum import StrEnum
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, Field


class SensitivityLevel(StrEnum):
    """Content sensitivity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FileEvent(BaseModel):
    """File system event from Inbox watcher."""

    event_id: UUID
    source_path: Path
    event_type: str = "created"


class ClassificationResult(BaseModel):
    """Model output for a file classification."""

    sensitivity: SensitivityLevel
    category: str
    tags: list[str] = Field(default_factory=list)
    summary: str = ""
    disguise_name: str
    disguise_extension: str


class EncryptRequest(BaseModel):
    """Request to encrypt a file."""

    task_id: UUID
    source_path: Path
    classification: ClassificationResult


class EncryptResult(BaseModel):
    """Result of an encryption operation."""

    task_id: UUID
    vault_path: Path
    salt: bytes
    nonce: bytes


class TaskStatus(BaseModel):
    """Agent task status."""

    task_id: UUID
    state: str
    message: str = ""


class TaskSummary(BaseModel):
    """Lightweight task summary for UI lists."""

    task_id: UUID
    state: str
    message: str = ""
    source_path: Path | None = None


class SearchQuery(BaseModel):
    """Natural language search query."""

    query: str
    top_k: int = 5


class SearchResult(BaseModel):
    """Single search result."""

    vault_path: Path
    category: str
    summary: str
    score: float
