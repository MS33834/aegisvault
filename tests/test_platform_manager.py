"""Tests for platform connection manager."""

from pathlib import Path

import pytest

from aegisvault.platform.manager import ConnectionManager
from aegisvault.platform.models import Connection, PlatformType


@pytest.fixture
def manager(tmp_path: Path) -> ConnectionManager:
    """Fixture with isolated connection storage."""
    return ConnectionManager(tmp_path / "connections.json")


def test_default_connection_seeded(manager: ConnectionManager) -> None:
    """Manager seeds a default local Ollama connection."""
    conns = manager.list_all()
    assert len(conns) == 1
    assert conns[0].platform_type == PlatformType.OLLAMA
    assert conns[0].is_trusted_local()


def test_add_and_list_connection(manager: ConnectionManager) -> None:
    """Add a connection and verify persistence."""
    conn = Connection(
        name="Cloud OpenAI",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        model_name="gpt-4o",
        is_local=False,
        is_cloud_authorized=True,
    )
    manager.add(conn)

    all_conns = manager.list_all()
    assert len(all_conns) == 2
    assert any(c.name == "Cloud OpenAI" for c in all_conns)


def test_cloud_connection_not_trusted_local(manager: ConnectionManager) -> None:
    """Cloud connections must not be trusted for sensitive tasks."""
    conn = Connection(
        name="Cloud OpenAI",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
    )
    manager.add(conn)

    local_conns = manager.list_local()
    assert conn not in local_conns


@pytest.mark.parametrize(
    ("base_url", "expected"),
    [
        ("http://127.0.0.1:11434", True),
        ("http://[::1]:11434", True),
        ("http://localhost:11434", True),
        ("http://192.168.1.10:11434", False),
        ("https://api.openai.com/v1", False),
        ("ftp://127.0.0.1:11434", False),
        ("http://0177.0.0.1:11434", False),
    ],
)
def test_is_trusted_local_variants(base_url: str, expected: bool) -> None:
    """Local trust covers loopback, localhost, and rejects non-local hosts."""
    conn = Connection(
        name="Local variant",
        platform_type=PlatformType.OLLAMA,
        base_url=base_url,
        is_local=True,
    )
    assert conn.is_trusted_local() is expected


def test_update_connection(manager: ConnectionManager) -> None:
    """Update an existing connection."""
    conn = manager.list_all()[0]
    updated = conn.model_copy(update={"model_name": "qwen2.5:14b"})
    manager.update(updated)

    reloaded = ConnectionManager(manager.storage_path)
    assert reloaded.get(conn.id).model_name == "qwen2.5:14b"  # type: ignore[union-attr]
