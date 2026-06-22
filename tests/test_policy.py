"""Tests for sensitive operation security policy."""

import pytest

from aegisvault.platform.models import Connection, PlatformType
from aegisvault.security.policy import (
    SecurityPolicyError,
    require_trusted_local_connection,
    sensitive_operation,
)


def test_local_connection_passes() -> None:
    """Trusted local connection passes policy check."""
    conn = Connection(
        name="Local Ollama",
        platform_type=PlatformType.OLLAMA,
        base_url="http://127.0.0.1:11434/v1",
    )
    require_trusted_local_connection(conn)  # should not raise


def test_cloud_connection_fails() -> None:
    """Cloud connection is rejected for sensitive tasks."""
    conn = Connection(
        name="Cloud OpenAI",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
    )
    with pytest.raises(SecurityPolicyError):
        require_trusted_local_connection(conn)


def test_decorator_blocks_cloud() -> None:
    """Decorator rejects cloud connection."""

    @sensitive_operation
    def _sensitive_work(conn: Connection) -> str:
        return "done"

    cloud = Connection(
        name="Cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
    )
    with pytest.raises(SecurityPolicyError):
        _sensitive_work(cloud)


def test_decorator_allows_localhost() -> None:
    """Decorator allows localhost connection."""

    @sensitive_operation
    def _sensitive_work(conn: Connection) -> str:
        return "done"

    local = Connection(
        name="Local",
        platform_type=PlatformType.OLLAMA,
        base_url="http://localhost:11434/v1",
    )
    assert _sensitive_work(local) == "done"


def test_decorator_supports_keyword_connection() -> None:
    """Decorator validates a Connection passed as a keyword argument."""

    @sensitive_operation
    def _sensitive_work(*, connection: Connection) -> str:
        return "done"

    local = Connection(
        name="Local",
        platform_type=PlatformType.OLLAMA,
        base_url="http://127.0.0.1:11434/v1",
    )
    assert _sensitive_work(connection=local) == "done"


def test_decorator_rejects_cloud_keyword_connection() -> None:
    """Decorator rejects a cloud Connection passed as a keyword argument."""

    @sensitive_operation
    def _sensitive_work(*, connection: Connection) -> str:
        return "done"

    cloud = Connection(
        name="Cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
    )
    with pytest.raises(SecurityPolicyError):
        _sensitive_work(connection=cloud)
