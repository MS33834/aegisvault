"""Tests for sensitive operation security policy."""

from pathlib import Path

import pytest

from aegisvault.config import AegisConfig
from aegisvault.connections.models import Connection, PlatformType
from aegisvault.security.audit_log import AuditLogger
from aegisvault.security.policy import (
    SecurityPolicyError,
    SensitiveContext,
    enforce_sensitive_policy,
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


def test_decorator_rejects_mixed_local_and_cloud() -> None:
    """Decorator rejects when any Connection argument is not trusted local."""

    @sensitive_operation
    def _sensitive_work(local: Connection, remote: Connection) -> str:
        return "done"

    local = Connection(
        name="Local",
        platform_type=PlatformType.OLLAMA,
        base_url="http://127.0.0.1:11434/v1",
    )
    cloud = Connection(
        name="Cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
    )
    with pytest.raises(SecurityPolicyError):
        _sensitive_work(local, cloud)


def test_policy_violation_is_audited(tmp_path: Path) -> None:
    """require_trusted_local_connection logs a policy_violation event."""
    config = AegisConfig()
    config.paths.logs = tmp_path / "logs"
    audit = AuditLogger(config, hmac_key=b"k" * 32)

    cloud = Connection(
        name="Cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
    )
    with pytest.raises(SecurityPolicyError):
        require_trusted_local_connection(cloud, audit_logger=audit, operation="test_op")

    records = audit.query(event_type="policy_violation")
    assert len(records) == 1
    assert records[0]["details"]["operation"] == "test_op"
    assert records[0]["details"]["connection_name"] == "Cloud"


def test_decorator_logs_policy_violation(tmp_path: Path) -> None:
    """The sensitive_operation decorator forwards audit loggers to the policy check."""
    config = AegisConfig()
    config.paths.logs = tmp_path / "logs"
    audit = AuditLogger(config, hmac_key=b"k" * 32)

    @sensitive_operation
    def _sensitive_work(conn: Connection, audit_logger: AuditLogger) -> str:
        return "done"

    cloud = Connection(
        name="Cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
    )
    with pytest.raises(SecurityPolicyError):
        _sensitive_work(cloud, audit)

    records = audit.query(event_type="policy_violation")
    assert len(records) == 1
    assert records[0]["details"]["connection_name"] == "Cloud"


def _audit_fixture(tmp_path: Path) -> AuditLogger:
    config = AegisConfig()
    config.paths.logs = tmp_path / "logs"
    return AuditLogger(config, hmac_key=b"k" * 32)


def test_enforce_sensitive_policy_allows_cloud_fallback_when_authorized(
    tmp_path: Path,
) -> None:
    """An authorised cloud connection is allowed when cloud fallback is enabled."""
    audit = _audit_fixture(tmp_path)
    config = AegisConfig()
    config.security.cloud_fallback_enabled = True

    cloud = Connection(
        name="Authorized Cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
        is_cloud_authorized=True,
    )
    enforce_sensitive_policy(
        SensitiveContext(connection=cloud, config=config, audit_logger=audit, operation="test")
    )

    records = audit.query(event_type="cloud_fallback_used")
    assert len(records) == 1
    assert records[0]["details"]["connection_name"] == "Authorized Cloud"


def test_enforce_sensitive_policy_rejects_unauthorized_cloud_fallback(
    tmp_path: Path,
) -> None:
    """Cloud fallback enabled but connection not authorised still raises."""
    audit = _audit_fixture(tmp_path)
    config = AegisConfig()
    config.security.cloud_fallback_enabled = True

    cloud = Connection(
        name="Unauthorized Cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
        is_cloud_authorized=False,
    )
    with pytest.raises(SecurityPolicyError):
        enforce_sensitive_policy(
            SensitiveContext(connection=cloud, config=config, audit_logger=audit, operation="test")
        )

    records = audit.query(event_type="policy_violation")
    assert len(records) == 1


def test_enforce_sensitive_policy_enforces_offline_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A trusted local connection fails when outbound traffic is detected."""
    audit = _audit_fixture(tmp_path)
    config = AegisConfig()
    config.security.enforce_offline_policy = True

    local = Connection(
        name="Local",
        platform_type=PlatformType.OLLAMA,
        base_url="http://127.0.0.1:11434/v1",
    )
    monkeypatch.setattr(
        "aegisvault.security.offline.has_outbound_connection",
        lambda **kwargs: True,
    )

    with pytest.raises(SecurityPolicyError, match="offline environment"):
        enforce_sensitive_policy(
            SensitiveContext(connection=local, config=config, audit_logger=audit, operation="test")
        )

    records = audit.query(event_type="offline_policy_violation")
    assert len(records) == 1


def test_enforce_sensitive_policy_allows_local_when_offline_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A trusted local connection passes when no outbound traffic is detected."""
    audit = _audit_fixture(tmp_path)
    config = AegisConfig()
    config.security.enforce_offline_policy = True

    local = Connection(
        name="Local",
        platform_type=PlatformType.OLLAMA,
        base_url="http://127.0.0.1:11434/v1",
    )
    monkeypatch.setattr(
        "aegisvault.security.offline.has_outbound_connection",
        lambda **kwargs: False,
    )

    enforce_sensitive_policy(
        SensitiveContext(connection=local, config=config, audit_logger=audit, operation="test")
    )
    assert audit.query(event_type="offline_policy_violation") == []


def test_decorator_uses_config_for_cloud_fallback() -> None:
    """The decorator picks up AegisConfig and applies cloud fallback rules."""
    config = AegisConfig()
    config.security.cloud_fallback_enabled = True

    @sensitive_operation
    def _sensitive_work(conn: Connection, cfg: AegisConfig) -> str:
        return "done"

    authorized_cloud = Connection(
        name="Authorized Cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
        is_cloud_authorized=True,
    )
    assert _sensitive_work(authorized_cloud, config) == "done"

    unauthorized_cloud = Connection(
        name="Unauthorized Cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
        is_cloud_authorized=False,
    )
    with pytest.raises(SecurityPolicyError):
        _sensitive_work(unauthorized_cloud, config)
