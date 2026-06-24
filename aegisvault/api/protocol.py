"""JSON-RPC 2.0 style internal protocol."""

from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator


class JsonRpcRequest(BaseModel):
    """Internal JSON-RPC request envelope."""

    jsonrpc: str = "2.0"
    id: str = Field(default_factory=lambda: str(uuid4()))
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class JsonRpcResponse(BaseModel):
    """Internal JSON-RPC response envelope."""

    jsonrpc: str = "2.0"
    id: str
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _result_or_error_exclusive(self) -> "JsonRpcResponse":
        """Enforce JSON-RPC 2.0 rule that result and error are mutually exclusive."""
        if self.result is not None and self.error is not None:
            raise ValueError("result and error are mutually exclusive")
        if self.result is None and self.error is None:
            raise ValueError("response must contain either result or error")
        return self

    @classmethod
    def success(cls, request_id: str | UUID, result: dict[str, Any]) -> "JsonRpcResponse":
        """Create a success response."""
        return cls(id=str(request_id), result=result)

    @classmethod
    def failure(cls, request_id: str | UUID, code: int, message: str) -> "JsonRpcResponse":
        """Create an error response."""
        return cls(id=str(request_id), error={"code": code, "message": message})
