"""Tests for the AegisVault API server."""

import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from aegisvault.api.server import is_available


def test_is_available_checks_fastapi_presence() -> None:
    """is_available returns True when FastAPI is importable."""
    result = is_available()
    assert isinstance(result, bool)


def test_server_module_imports_without_fastapi() -> None:
    """The server module can be imported even without FastAPI installed."""
    import aegisvault.api.server  # noqa: F401

    assert aegisvault.api.server.is_available is not None


def test_resolve_token_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """_resolve_token reads AEGISVAULT_API_TOKEN from environment."""
    from aegisvault.api.server import _resolve_token

    monkeypatch.setenv("AEGISVAULT_API_TOKEN", "secret-token-42")
    assert _resolve_token() == "secret-token-42"

    monkeypatch.delenv("AEGISVAULT_API_TOKEN", raising=False)
    assert _resolve_token() is None


def test_check_available_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """_check_available raises ImportError when FastAPI is None."""
    import aegisvault.api.server as mod

    original = mod._FASTAPI_AVAILABLE
    try:
        mod._FASTAPI_AVAILABLE = False
        with pytest.raises(ImportError, match="FastAPI is required"):
            mod._check_available()
    finally:
        mod._FASTAPI_AVAILABLE = original


def test_run_server_without_fastapi(monkeypatch: pytest.MonkeyPatch) -> None:
    """run_server raises ImportError when FastAPI is not installed."""
    import aegisvault.api.server as mod

    monkeypatch.setattr(mod, "_FASTAPI_AVAILABLE", False)
    with pytest.raises(ImportError, match="FastAPI is required"):
        mod._check_available()


# ── FastAPI-dependent tests (only run when FastAPI is available) ──────


@pytest.mark.skipif(
    not is_available(),
    reason="FastAPI is not installed (optional dependency)",
)
class TestFastAPIIntegration:
    """Integration tests that require a running FastAPI app."""

    @pytest.fixture
    def config_with_inbox(self, tmp_path: Path) -> Any:
        from aegisvault.config import AegisConfig

        config = AegisConfig()
        config.paths.inbox = tmp_path / "Inbox"
        config.paths.vault = tmp_path / "Vault"
        config.paths.index = tmp_path / "Index"
        config.paths.logs = tmp_path / "Logs"
        config.paths.connections = tmp_path / "Config" / "connections.json"
        for p in [
            config.paths.inbox,
            config.paths.vault,
            config.paths.index,
            config.paths.logs,
        ]:
            p.mkdir(parents=True, exist_ok=True)
        config.paths.connections.parent.mkdir(parents=True, exist_ok=True)
        return config

    @pytest.fixture
    def mock_agent(self) -> MagicMock:
        agent = MagicMock()
        agent.task_store.list_recent.return_value = []
        agent.task_store.list_vault_files.return_value = []
        agent.task_store.get.return_value = None
        agent.master_key_provider = MagicMock()
        agent.master_key_provider.get_key.return_value = os.urandom(32)
        # Remove _sync_engine so sync endpoints see it as unavailable.
        del agent._sync_engine
        # Make search async-compatible by returning a coroutine-wrapped list.
        del agent.search  # remove auto-mock

        async def _search(*args: object, **kwargs: object) -> list[Any]:
            return []

        agent.search = _search
        return agent

    @pytest.fixture
    def app_client(self, config_with_inbox: Any, mock_agent: MagicMock) -> Any:
        from fastapi.testclient import TestClient

        from aegisvault.api.server import create_app

        app = create_app(config_with_inbox, mock_agent)
        return TestClient(app)

    def test_health_endpoint(self, app_client: Any) -> None:
        """GET /health returns status ok."""
        response = app_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_vault_status_unauthenticated(self, app_client: Any) -> None:
        """GET /vault/status works without auth when no token is configured."""
        response = app_client.get("/vault/status")
        assert response.status_code == 200
        data = response.json()
        assert "inbox_files" in data
        assert "vault_files" in data
        assert "categories" in data
        assert "recent_tasks" in data

    def test_vault_status_authenticated_required(
        self,
        config_with_inbox: Any,
        mock_agent: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """GET /vault/status returns 401 when token is configured but missing."""
        monkeypatch.setenv("AEGISVAULT_API_TOKEN", "my-secret-token")
        from fastapi.testclient import TestClient

        from aegisvault.api.server import create_app

        app = create_app(config_with_inbox, mock_agent)
        client = TestClient(app)
        response = client.get("/vault/status")
        assert response.status_code == 401

    def test_vault_status_with_valid_token(
        self,
        config_with_inbox: Any,
        mock_agent: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """GET /vault/status works with valid Bearer token."""
        monkeypatch.setenv("AEGISVAULT_API_TOKEN", "my-secret-token")
        from fastapi.testclient import TestClient

        from aegisvault.api.server import create_app

        app = create_app(config_with_inbox, mock_agent)
        client = TestClient(app)
        response = client.get(
            "/vault/status",
            headers={"Authorization": "Bearer my-secret-token"},
        )
        assert response.status_code == 200

    def test_vault_files_list(self, app_client: Any) -> None:
        """GET /vault/files returns paginated file list."""
        response = app_client.get("/vault/files")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "offset" in data
        assert "limit" in data
        assert "files" in data

    def test_vault_files_list_with_params(self, app_client: Any) -> None:
        """GET /vault/files supports category, offset, limit parameters."""
        response = app_client.get("/vault/files?category=documents&offset=0&limit=10")
        assert response.status_code == 200
        data = response.json()
        assert data["offset"] == 0
        assert data["limit"] == 10

    def test_vault_files_list_invalid_limit(self, app_client: Any) -> None:
        """GET /vault/files rejects limit > 500."""
        response = app_client.get("/vault/files?limit=600")
        assert response.status_code == 422

    def test_vault_files_list_invalid_offset(self, app_client: Any) -> None:
        """GET /vault/files rejects negative offset."""
        response = app_client.get("/vault/files?offset=-1")
        assert response.status_code == 422

    def test_vault_file_metadata_not_found(self, app_client: Any) -> None:
        """GET /vault/files/{id} returns 404 for unknown ID."""
        import uuid

        unknown_id = str(uuid.uuid4())
        response = app_client.get(f"/vault/files/{unknown_id}")
        assert response.status_code == 404

    def test_vault_file_metadata_invalid_id(self, app_client: Any) -> None:
        """GET /vault/files/{id} returns 400 for invalid UUID."""
        response = app_client.get("/vault/files/not-a-uuid")
        assert response.status_code == 400

    def test_search_endpoint(self, app_client: Any) -> None:
        """POST /vault/search runs search via the agent."""
        response = app_client.post(
            "/vault/search",
            json={"query": "test", "top_k": 5, "semantic": False},
        )
        assert response.status_code == 200
        assert response.json() == []

    def test_search_endpoint_validation(self, app_client: Any) -> None:
        """POST /vault/search validates request body."""
        response = app_client.post("/vault/search", json={})
        assert response.status_code == 422

    def test_sync_status_no_engine(self, app_client: Any) -> None:
        """GET /sync/status reports unavailable when no sync engine."""
        response = app_client.get("/sync/status")
        assert response.status_code == 200
        data = response.json()
        assert data["available"] is False

    def test_sync_trigger_no_engine(self, app_client: Any) -> None:
        """POST /sync/trigger returns 400 when no sync engine."""
        response = app_client.post("/sync/trigger")
        assert response.status_code == 400

    def test_cors_headers_present(self, app_client: Any) -> None:
        """Response includes CORS headers for localhost origins."""
        response = app_client.options(
            "/health",
            headers={"Origin": "http://localhost:3000"},
        )
        assert response.status_code in (200, 405)
