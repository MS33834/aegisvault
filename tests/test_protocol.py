"""Tests for the internal JSON-RPC style protocol."""

from uuid import UUID

import pytest

from aegisvault.api.protocol import JsonRpcRequest, JsonRpcResponse


def test_request_default_values() -> None:
    """JsonRpcRequest fills sensible defaults."""
    req = JsonRpcRequest(method="ping")
    assert req.jsonrpc == "2.0"
    assert req.method == "ping"
    assert req.params == {}
    assert isinstance(UUID(req.id), UUID)


def test_request_with_custom_params() -> None:
    """JsonRpcRequest accepts custom id and params."""
    req = JsonRpcRequest(id="req-1", method="encrypt", params={"path": "/tmp/file"})
    assert req.id == "req-1"
    assert req.params == {"path": "/tmp/file"}


def test_response_success_factory() -> None:
    """JsonRpcResponse.success builds a result response."""
    resp = JsonRpcResponse.success("req-1", {"status": "ok"})
    assert resp.jsonrpc == "2.0"
    assert resp.id == "req-1"
    assert resp.result == {"status": "ok"}
    assert resp.error is None


def test_response_failure_factory() -> None:
    """JsonRpcResponse.failure builds an error response."""
    resp = JsonRpcResponse.failure("req-1", code=-32600, message="Invalid request")
    assert resp.id == "req-1"
    assert resp.error == {"code": -32600, "message": "Invalid request"}
    assert resp.result is None


def test_response_accepts_uuid_id() -> None:
    """Factory methods accept UUID objects."""
    task_id = UUID("12345678-1234-1234-1234-123456789abc")
    resp = JsonRpcResponse.success(task_id, {"done": True})
    assert resp.id == str(task_id)


def test_response_rejects_both_result_and_error() -> None:
    """A response cannot contain both result and error."""
    with pytest.raises(ValueError, match="mutually exclusive"):
        JsonRpcResponse(id="req-1", result={"ok": True}, error={"code": -1})


def test_response_requires_result_or_error() -> None:
    """A response must contain either result or error."""
    with pytest.raises(ValueError, match="either result or error"):
        JsonRpcResponse(id="req-1")
