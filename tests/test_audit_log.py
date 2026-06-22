"""Tests for the append-only audit logger."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aegisvault.config import AegisConfig
from aegisvault.security.audit_log import ALLOWED_EVENT_TYPES, AuditLogger


@pytest.fixture
def config(tmp_path: Path) -> AegisConfig:
    """Test configuration with isolated log path."""
    cfg = AegisConfig()
    cfg.paths.logs = tmp_path / "logs"
    return cfg


@pytest.fixture
def logger(config: AegisConfig) -> AuditLogger:
    """Audit logger with a deterministic HMAC key."""
    return AuditLogger(config, hmac_key=b"x" * 32)


def test_allowed_event_types_contains_required_events() -> None:
    """All required event types are allowed."""
    required = {
        "file_ingested",
        "classified",
        "encrypted",
        "decrypted",
        "connection_tested",
        "policy_violation",
        "login_attempt",
    }
    assert required <= ALLOWED_EVENT_TYPES


def test_log_appends_ndjson(config: AegisConfig, logger: AuditLogger) -> None:
    """Logging appends timestamped, HMAC-signed NDJSON records."""
    logger.log("file_ingested", {"task_id": "1"})
    logger.log("encrypted", {"task_id": "1"})

    log_path = config.paths.logs / "audit.log.ndjson"
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 2

    record = json.loads(lines[0])
    assert record["event_type"] == "file_ingested"
    assert "timestamp" in record
    assert "hmac" in record
    assert record["details"] == {"task_id": "1"}


def test_log_rejects_unknown_event(logger: AuditLogger) -> None:
    """Unknown event types are rejected."""
    with pytest.raises(ValueError, match="Unsupported audit event type"):
        logger.log("unknown_event")


def test_query_by_event_type(config: AegisConfig, logger: AuditLogger) -> None:
    """query filters by event_type."""
    logger.log("file_ingested", {"task_id": "1"})
    logger.log("encrypted", {"task_id": "1"})
    logger.log("file_ingested", {"task_id": "2"})

    results = logger.query(event_type="file_ingested")
    assert len(results) == 2
    assert all(r["event_type"] == "file_ingested" for r in results)


def test_query_since(config: AegisConfig, logger: AuditLogger) -> None:
    """query filters by minimum timestamp."""
    logger.log("file_ingested", {"task_id": "1"})

    future = datetime.now(UTC) + timedelta(hours=1)
    results = logger.query(since=future)
    assert results == []


def test_query_limit(config: AegisConfig, logger: AuditLogger) -> None:
    """query respects the limit parameter."""
    for i in range(5):
        logger.log("file_ingested", {"task_id": str(i)})

    results = logger.query(event_type="file_ingested", limit=2)
    assert len(results) == 2


def test_verify_valid_records(logger: AuditLogger) -> None:
    """verify returns True for untampered records."""
    logger.log("file_ingested", {"task_id": "1"})
    logger.log("encrypted", {"task_id": "1"})

    ok, invalid = logger.verify()
    assert ok is True
    assert invalid == []


def test_verify_detects_tampering(config: AegisConfig, logger: AuditLogger) -> None:
    """verify flags lines whose payload was modified."""
    logger.log("file_ingested", {"task_id": "1"})

    log_path = config.paths.logs / "audit.log.ndjson"
    text = log_path.read_text()
    tampered = text.replace('"task_id": "1"', '"task_id": "2"')
    log_path.write_text(tampered)

    ok, invalid = logger.verify()
    assert ok is False
    assert invalid == [1]


def test_verify_detects_missing_hmac(config: AegisConfig) -> None:
    """verify flags lines missing the HMAC field."""
    log_path = config.paths.logs / "audit.log.ndjson"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "file_ingested",
        "details": {},
    }
    log_path.write_text(json.dumps(record) + "\n")

    logger = AuditLogger(config, hmac_key=b"x" * 32)
    ok, invalid = logger.verify()
    assert ok is False
    assert invalid == [1]


def test_key_persistence(config: AegisConfig) -> None:
    """The HMAC key is persisted across AuditLogger instances."""
    logger1 = AuditLogger(config)
    key1 = logger1.hmac_key
    logger2 = AuditLogger(config)
    assert logger2.hmac_key == key1
