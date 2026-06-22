"""Connection manager for platform configurations."""

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID

from aegisvault.model import ModelProvider
from aegisvault.platform.models import Connection, PlatformType
from aegisvault.platform.secure_storage import seal_dict, unseal_dict

SENSITIVE_FIELDS = {"api_key", "password"}


class ConnectionManager:
    """CRUD + test platform connections."""

    def __init__(
        self,
        storage_path: Path,
        provider_factory: Callable[[Connection], ModelProvider] | None = None,
    ) -> None:
        self.storage_path = storage_path
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._connections: dict[UUID, Connection] = {}
        self._provider_factory = provider_factory
        self._load()

    def add(self, connection: Connection) -> Connection:
        """Add a new connection."""
        self._connections[connection.id] = connection
        self._save()
        return connection

    def get(self, connection_id: UUID) -> Connection | None:
        """Get a connection by ID."""
        return self._connections.get(connection_id)

    def list_all(self) -> list[Connection]:
        """Return all connections sorted by priority descending."""
        return sorted(self._connections.values(), key=lambda c: c.priority, reverse=True)

    def list_enabled(self) -> list[Connection]:
        """Return enabled connections only."""
        return [c for c in self.list_all() if c.is_enabled]

    def list_local(self) -> list[Connection]:
        """Return enabled local connections."""
        return [c for c in self.list_enabled() if c.is_trusted_local()]

    def update(self, connection: Connection) -> Connection:
        """Update an existing connection."""
        if connection.id not in self._connections:
            raise KeyError(f"Connection {connection.id} not found")
        self._connections[connection.id] = connection
        self._save()
        return connection

    def delete(self, connection_id: UUID) -> None:
        """Delete a connection."""
        self._connections.pop(connection_id, None)
        self._save()

    def get_default_chat_connection(self) -> Connection | None:
        """Return the highest-priority enabled connection capable of chat."""
        for conn in self.list_enabled():
            if "chat" in conn.capabilities:
                return conn
        return None

    def _create_provider(self, connection: Connection) -> ModelProvider:
        """Create a model provider for the given connection.

        Uses the injected factory if available; otherwise falls back to the
        global provider registry. The lazy import keeps the platform layer
        decoupled from the model layer when a factory is supplied.
        """
        if self._provider_factory is not None:
            return self._provider_factory(connection)
        from aegisvault.model import create_provider

        return create_provider(connection)

    def test_connection(self, connection_id: UUID) -> tuple[bool, str]:
        """Test a connection synchronously.

        Returns (success, message).
        """
        conn = self.get(connection_id)
        if conn is None:
            return False, "Connection not found"

        provider = self._create_provider(conn)
        try:
            healthy = asyncio.run(provider.health())
            if healthy:
                return True, f"Connected to {conn.base_url}"
            return False, f"No response from {conn.base_url}"
        except Exception as exc:  # noqa: BLE001
            return False, f"Error: {exc}"
        finally:
            asyncio.run(provider.close())

    def _load(self) -> None:
        if not self.storage_path.exists():
            # Seed default local Ollama connection.
            default = Connection(
                name="Local Ollama",
                platform_type=PlatformType.OLLAMA,
                base_url="http://127.0.0.1:11434/v1",
                model_name="qwen2.5:7b",
                is_local=True,
                priority=10,
            )
            self._connections[default.id] = default
            self._save()
            return

        raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
        for item in raw.get("connections", []):
            decrypted = unseal_dict(item, SENSITIVE_FIELDS)
            conn = Connection.model_validate(decrypted)
            self._connections[conn.id] = conn

    def _save(self) -> None:
        data: dict[str, Any] = {
            "version": 1,
            "connections": [
                seal_dict(conn.model_dump(), SENSITIVE_FIELDS)
                for conn in self._connections.values()
            ],
        }
        self.storage_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
