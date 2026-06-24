"""API schemas and protocol definitions for AegisVault."""

from aegisvault.api.protocol import JsonRpcRequest, JsonRpcResponse
from aegisvault.api.schemas import (
    ClassificationResult,
    EncryptResult,
    FileEvent,
    SearchQuery,
    SearchResult,
    SensitivityLevel,
    TaskStatus,
    TaskSummary,
)

__all__ = [
    "ClassificationResult",
    "EncryptResult",
    "FileEvent",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "SearchQuery",
    "SearchResult",
    "SensitivityLevel",
    "TaskStatus",
    "TaskSummary",
]
