"""Append-only audit logger with per-entry HMAC integrity checks.

The log is written as newline-delimited JSON (NDJSON) to
``<logs>/audit.log.ndjson``.  Each record contains an HMAC-SHA256 over the
canonical JSON of the record (excluding the ``hmac`` field itself) so that
tampering with the log file can be detected offline.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegisvault.config import AegisConfig

ALLOWED_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "file_ingested",
        "classified",
        "encrypted",
        "decrypted",
        "connection_tested",
        "policy_violation",
        "offline_policy_violation",
        "cloud_fallback_used",
        "login_attempt",
    }
)

_MAX_LOG_SIZE = 100 * 1024 * 1024  # 100 MB


class AuditLogger:
    """Append-only NDJSON audit logger with HMAC integrity checks."""

    def __init__(
        self,
        config: AegisConfig,
        hmac_key: bytes | None = None,
    ) -> None:
        self.log_path = config.paths.logs / "audit.log.ndjson"
        self.log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._hmac_key = hmac_key if hmac_key is not None else self._load_or_create_key()

    def _key_path(self) -> Path:
        return self.log_path.parent / ".audit.key"

    def _load_or_create_key(self) -> bytes:
        key_path = self._key_path()
        try:
            return key_path.read_bytes()
        except FileNotFoundError:
            pass
        key = os.urandom(32)
        try:
            fd = os.open(
                str(key_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            # Another process raced ahead and created the key.
            return key_path.read_bytes()
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        return key

    @property
    def hmac_key(self) -> bytes:
        """Return the HMAC key used for integrity checks."""
        return self._hmac_key

    @staticmethod
    def _canonical(record: dict[str, Any]) -> str:
        """Canonical JSON representation for stable HMAC computation."""
        return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)

    def _sign(self, record: dict[str, Any]) -> str:
        canonical = self._canonical(record)
        return hmac.new(
            self._hmac_key,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def log(self, event_type: str, details: dict[str, Any] | None = None) -> None:
        """Append an audit record to the log."""
        if event_type not in ALLOWED_EVENT_TYPES:
            raise ValueError(f"Unsupported audit event type: {event_type!r}")

        record: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "details": details or {},
        }
        record["hmac"] = self._sign(record)
        self._append(record)

    def _append(self, record: dict[str, Any]) -> None:
        """Append a record to the audit log file."""
        line = json.dumps(record, default=str) + "\n"
        # Rotate if the log file exceeds the max size
        if self.log_path.exists() and self.log_path.stat().st_size > _MAX_LOG_SIZE:
            rotated = self.log_path.with_suffix(".log.1.ndjson")
            self.log_path.replace(rotated)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

    def _iter_records(self) -> Iterator[tuple[int, dict[str, Any]]]:
        if not self.log_path.exists():
            return
        with self.log_path.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    logging.warning("Skipping corrupt audit log line %d", lineno)
                    continue
                yield lineno, record

    def query(
        self,
        since: datetime | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query audit records with optional filtering.

        Records are returned in chronological order.
        """
        results: list[dict[str, Any]] = []
        for _lineno, record in self._iter_records():
            if event_type is not None and record.get("event_type") != event_type:
                continue
            if since is not None:
                ts = record.get("timestamp")
                if ts:
                    try:
                        record_ts = datetime.fromisoformat(str(ts))
                    except ValueError:
                        continue
                    if record_ts < since:
                        continue
            results.append(record)
            if len(results) >= limit:
                break
        return results

    def verify(self) -> tuple[bool, list[int]]:
        """Verify the integrity of all logged records.

        Returns ``(ok, invalid_line_numbers)``.
        """
        invalid: list[int] = []
        for lineno, record in self._iter_records():
            record = record.copy()
            stored_hmac = record.pop("hmac", None)
            expected = self._sign(record)
            if not hmac.compare_digest(stored_hmac or "", expected):
                invalid.append(lineno)
        return not invalid, invalid
