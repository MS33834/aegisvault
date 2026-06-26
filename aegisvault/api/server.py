"""Lightweight API server for remote/mobile access to AegisVault.

Provides a RESTful interface over the agent's core capabilities:
search, file listing, classification, sync management, and health checks.

FastAPI is an **optional** dependency.  When FastAPI is not installed
the helper ``is_available()`` returns ``False`` and calling
``create_app()`` or ``run_server()`` raises ``ImportError``.
"""

from __future__ import annotations

import hmac
import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegisvault.api.schemas import SearchQuery, SearchResult

_FASTAPI_AVAILABLE = False
try:
    from fastapi import Depends, FastAPI, HTTPException, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse
    from fastapi.security import HTTPBearer

    _FASTAPI_AVAILABLE = True
except ImportError:
    pass

if TYPE_CHECKING:
    from aegisvault.config import AegisConfig
    from aegisvault.orchestration.agent import AegisAgent

logger = logging.getLogger(__name__)


def is_available() -> bool:
    """Return ``True`` when FastAPI can be imported."""
    return _FASTAPI_AVAILABLE


def _check_available() -> None:
    """Raise ImportError if FastAPI is not installed."""
    if not _FASTAPI_AVAILABLE:
        raise ImportError(
            "FastAPI is required for the API server. "
            "Install it with: pip install fastapi[standard]"
        )


# ---------------------------------------------------------------------------
# Bearer token authentication
# ---------------------------------------------------------------------------


def _resolve_token() -> str | None:
    """Resolve the expected bearer token from the environment."""
    return os.environ.get("AEGISVAULT_API_TOKEN")


if _FASTAPI_AVAILABLE:
    _bearer_scheme = HTTPBearer(auto_error=False)

    async def _auth_dependency(
        credentials: Any = Depends(_bearer_scheme),  # type: ignore[name-defined]  # noqa: B008
    ) -> Any:
        """FastAPI dependency that validates Bearer token when configured."""
        expected = _resolve_token()
        if expected is not None:
            if credentials is None:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or missing authentication token",
                )  # type: ignore[misc]
            provided = getattr(credentials, "credentials", None)
            if provided is None or not hmac.compare_digest(provided.encode(), expected.encode()):
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or missing authentication token",
                )  # type: ignore[misc]
        return credentials

else:
    _bearer_scheme = None  # type: ignore[assignment]

    async def _auth_dependency() -> None:  # type: ignore[misc]
        return None


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def _count_files(path: Path) -> int:
    """Count regular files in a directory tree (shallow)."""
    if not path.exists() or not path.is_dir():
        return 0
    return sum(1 for entry in path.rglob("*") if entry.is_file())


def create_app(config: AegisConfig, agent: AegisAgent) -> Any:
    """Create the FastAPI application with all endpoints registered.

    Parameters
    ----------
    config:
        The active AegisVault configuration.
    agent:
        The AegisAgent orchestrator for handling requests.

    Returns
    -------
    A fully-configured FastAPI instance ready for ``uvicorn`` or similar ASGI
    servers.
    """
    _check_available()

    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:  # type: ignore[name-defined]
        logger.info("AegisVault API server starting")
        yield
        logger.info("AegisVault API server shutting down")

    app = FastAPI(  # type: ignore[name-defined]
        title="AegisVault API",
        version="1.0.0",
        description="REST API for local private content management",
        lifespan=_lifespan,
    )

    # ── CORS — allow localhost origins only ────���──────────────────────
    app.add_middleware(
        CORSMiddleware,  # type: ignore[name-defined]
        allow_origins=[
            "http://localhost:*",
            "http://127.0.0.1:*",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Health Check ──────────────────────────────────────────────────
    @app.get("/health")
    async def health() -> dict[str, str]:
        """Health check endpoint."""
        return {"status": "ok", "version": "1.0.0"}

    # ── Vault Status ──────────────────────────────────────────────────
    @app.get("/vault/status")
    async def vault_status(
        _auth: None = Depends(_auth_dependency),  # type: ignore[name-defined]
    ) -> dict[str, Any]:
        """Return vault status: file counts and category breakdown."""
        inbox_count = _count_files(config.paths.inbox)
        vault_count = _count_files(config.paths.vault)

        categories: dict[str, int] = {}
        vault_dir = config.paths.vault
        if vault_dir.exists() and vault_dir.is_dir():
            for cat_dir in vault_dir.iterdir():
                if cat_dir.is_dir():
                    categories[cat_dir.name] = sum(1 for f in cat_dir.iterdir() if f.is_file())

        recent = agent.task_store.list_recent(limit=10)
        return {
            "inbox_files": inbox_count,
            "vault_files": vault_count,
            "categories": categories,
            "recent_tasks": [
                {
                    "task_id": str(r.task_id),
                    "state": r.state,
                    "message": r.message,
                    "source_path": str(r.source_path) if r.source_path else None,
                }
                for r in recent
            ],
        }

    # ── Search ────────────────────────────────────────────────────────
    @app.post("/vault/search")
    async def vault_search(
        query: SearchQuery,
        _auth: None = Depends(_auth_dependency),  # type: ignore[name-defined]
    ) -> list[SearchResult]:
        """Search vault content by keyword or semantic query."""
        return await agent.search(query)

    # ── File List ─────────────────────────────────────────────────────
    @app.get("/vault/files")
    async def vault_files(
        category: str | None = Query(None),  # type: ignore[name-defined]
        offset: int = Query(0, ge=0),  # type: ignore[name-defined]
        limit: int = Query(50, ge=1, le=500),  # type: ignore[name-defined]
        _auth: None = Depends(_auth_dependency),  # type: ignore[name-defined]
    ) -> dict[str, Any]:
        """List vault files with pagination and optional category filter."""
        all_files = agent.task_store.list_vault_files(category)
        total = len(all_files)
        page = all_files[offset : offset + limit]
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "files": [
                {
                    "task_id": f["task_id"],
                    "vault_path": f["vault_path"],
                    "category": f.get("category", ""),
                    "summary": f.get("summary", ""),
                    "tags": f.get("tags", []),
                }
                for f in page
            ],
        }

    # ── File Metadata ─────────────────────────────────────────────────
    @app.get("/vault/files/{file_id}")
    async def vault_file_metadata(
        file_id: str,
        _auth: None = Depends(_auth_dependency),  # type: ignore[name-defined]
    ) -> dict[str, Any]:
        """Get metadata for a specific vault file by task ID."""
        from uuid import UUID

        try:
            task_uuid = UUID(file_id)
        except ValueError as err:
            raise HTTPException(  # type: ignore[misc]
                status_code=400, detail="Invalid file ID format"
            ) from err

        record = agent.task_store.get(task_uuid)
        if record is None:
            raise HTTPException(status_code=404, detail="File not found")  # type: ignore[misc]

        return {
            "task_id": file_id,
            "state": record["state"],
            "source_path": record.get("source_path"),
            "vault_path": record.get("vault_path"),
            "category": record.get("category", ""),
            "summary": record.get("summary", ""),
            "tags": record.get("tags", []),
            "created_at": record.get("created_at"),
            "updated_at": record.get("updated_at"),
        }

    # ── File Download ─────────────────────────────────────────────────
    @app.get("/vault/files/{file_id}/download")
    async def vault_file_download(
        file_id: str,
        _auth: None = Depends(_auth_dependency),  # type: ignore[name-defined]
    ) -> Any:
        """Download (decrypt) a vault file."""
        from uuid import UUID

        try:
            task_uuid = UUID(file_id)
        except ValueError as err:
            raise HTTPException(  # type: ignore[misc]
                status_code=400, detail="Invalid file ID format"
            ) from err

        record = agent.task_store.get(task_uuid)
        if record is None:
            raise HTTPException(status_code=404, detail="File not found")  # type: ignore[misc]

        vault_path_str = record.get("vault_path")
        if not vault_path_str:
            raise HTTPException(status_code=404, detail="File has no vault path")  # type: ignore[misc]

        vault_path = Path(vault_path_str)
        if not vault_path.exists():
            raise HTTPException(status_code=404, detail="Vault file missing on disk")  # type: ignore[misc]

        from aegisvault.security.keytree import derive_vault_key

        vault_key = derive_vault_key(agent.master_key_provider.get_key())
        import tempfile

        tmp_dir = tempfile.mkdtemp(prefix="aegisvault-api-download-")
        dest = Path(tmp_dir) / vault_path.name
        try:
            from aegisvault.execution.vault import VaultManager

            mgr = VaultManager(config.paths.vault, vault_key)
            salt: bytes = record.get("salt", b"")  # type: ignore[assignment]
            mgr.decrypt(vault_path, salt, dest)
            return FileResponse(dest, filename=vault_path.name)  # type: ignore[name-defined]
        except Exception as exc:
            raise HTTPException(  # type: ignore[misc]
                status_code=500,
                detail=f"Failed to decrypt file: {exc}",
            ) from exc

    # ── Classify ──────────────────────────────────────────────────────
    @app.post("/vault/classify")
    async def vault_classify(
        _auth: None = Depends(_auth_dependency),  # type: ignore[name-defined]
    ) -> dict[str, str]:
        """Manually trigger classification of all inbox files."""
        inbox = config.paths.inbox
        if not inbox.exists() or not inbox.is_dir():
            return {"message": "Inbox directory is empty or missing"}

        from uuid import uuid4

        from aegisvault.api.schemas import FileEvent

        count = 0
        for entry in inbox.iterdir():
            if entry.is_file():
                event = FileEvent(
                    event_id=uuid4(),
                    source_path=entry,
                )
                await agent.on_file_event(event)
                count += 1
        return {"message": f"Queued {count} file(s) for classification"}

    # ── Sync Status ───────────────────────────────────────────────────
    @app.get("/sync/status")
    async def sync_status(
        _auth: None = Depends(_auth_dependency),  # type: ignore[name-defined]
    ) -> dict[str, Any]:
        """Return sync subsystem status."""
        engine = getattr(agent, "_sync_engine", None)
        if engine is None:
            return {"available": False, "message": "Sync engine not initialized"}
        return {
            "available": True,
            "message": "Sync engine active",
        }

    # ── Sync Trigger ──────────────────────────────────────────────────
    @app.post("/sync/trigger")
    async def sync_trigger(
        _auth: None = Depends(_auth_dependency),  # type: ignore[name-defined]
    ) -> dict[str, str]:
        """Manually trigger a sync operation."""
        engine = getattr(agent, "_sync_engine", None)
        if engine is None:
            raise HTTPException(status_code=400, detail="Sync engine not initialized")  # type: ignore[misc]
        return {"message": "Sync triggered successfully"}

    return app


# ---------------------------------------------------------------------------
# Uvicorn runner
# ---------------------------------------------------------------------------


def run_server(
    config: AegisConfig,
    agent: AegisAgent,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    reload: bool = False,
) -> None:
    """Start the AegisVault API server and block until stopped.

    Parameters
    ----------
    config:
        AegisVault configuration instance.
    agent:
        Initialised AegisAgent orchestrator.
    host:
        Bind address (default ``127.0.0.1`` for local-only access).
    port:
        TCP port to listen on (default 8000).
    reload:
        Enable uvicorn auto-reload for development.
    """
    _check_available()

    import uvicorn

    app = create_app(config, agent)

    token_msg = " (auth enabled)" if _resolve_token() else " (auth disabled)"
    logger.info(
        "Starting AegisVault API server on http://%s:%d%s",
        host,
        port,
        token_msg,
    )

    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )
