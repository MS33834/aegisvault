"""Append-only audit logger with per-entry HMAC integrity checks.

The log is written as newline-delimited JSON (NDJSON) to
``<logs>/audit.log.ndjson``.  Each record contains an HMAC-SHA256 over the
canonical JSON of the record (excluding the ``hmac`` field itself) so that
tampering with the log file can be detected offline.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import logging
import os
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegisvault.config import AegisConfig

AlertCallback = Callable[[str, dict[str, Any]], None]

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
        "master_key_changed",
        "sandbox_escape_attempt",
        "audit_write_failed",
        "password_store_operation",
        "sandbox_run_failed",
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
        self._alert_callbacks: list[AlertCallback] = []
        self._decrypt_failures: dict[str, int] = {}
        self._first_cloud_connection = True

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

    def register_alert(self, callback: AlertCallback) -> None:
        """Register an alert callback.

        The callback receives ``(severity, event_type, details)`` when an
        alert rule fires.  Severity is one of ``CRITICAL``, ``HIGH``, or
        ``MEDIUM``.
        """
        self._alert_callbacks.append(callback)

    def _fire_alert(self, severity: str, event_type: str, details: dict[str, Any]) -> None:
        """Invoke all registered alert callbacks."""
        for cb in self._alert_callbacks:
            try:
                cb(severity, {"event_type": event_type, "details": details})
            except Exception:
                logging.exception("Alert callback raised an exception")

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

        details_resolved = details or {}
        record: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "details": details_resolved,
        }
        record["hmac"] = self._sign(record)

        try:
            self._append(record)
        except OSError:
            self._fire_alert("HIGH", event_type, details_resolved)
            raise

        self._check_alert_rules(event_type, details_resolved)

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

    def _check_alert_rules(self, event_type: str, details: dict[str, Any]) -> None:
        """Evaluate built-in alert rules and fire callbacks when triggered."""
        # ── CRITICAL ────────────────────────────────────────────────
        if event_type == "decrypted":
            success = details.get("success", True)
            if not success:
                task_key = details.get("task_id", "__default__")
                count = self._decrypt_failures.get(task_key, 0) + 1
                self._decrypt_failures[task_key] = count
                if count >= 3:
                    self._fire_alert("CRITICAL", event_type, details)
            else:
                task_key = details.get("task_id", "__default__")
                self._decrypt_failures.pop(task_key, None)

        if event_type == "master_key_changed":
            self._fire_alert("CRITICAL", event_type, details)

        if event_type == "sandbox_escape_attempt":
            self._fire_alert("CRITICAL", event_type, details)

        # ── HIGH ───────────────────────────────────────────────────
        if event_type == "cloud_fallback_used":
            self._fire_alert("HIGH", event_type, details)

        if event_type in ("policy_violation", "offline_policy_violation"):
            self._fire_alert("HIGH", event_type, details)

        # ── MEDIUM ─────────────────────────────────────────────────
        if event_type == "sandbox_run_failed":
            self._fire_alert("MEDIUM", event_type, details)

        if event_type == "password_store_operation":
            self._fire_alert("MEDIUM", event_type, details)

        if event_type == "connection_tested":
            is_local = details.get("is_local", True)
            if not is_local and self._first_cloud_connection:
                self._first_cloud_connection = False
                self._fire_alert("MEDIUM", event_type, details)

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

    def _validate_time_range(
        self,
        start_time: datetime | None,
        end_time: datetime | None,
    ) -> None:
        if start_time is not None and end_time is not None and start_time >= end_time:
            raise ValueError("start_time must be before end_time")

    def _record_in_range(
        self,
        record: dict[str, Any],
        start_time: datetime | None,
        end_time: datetime | None,
    ) -> bool:
        ts = record.get("timestamp")
        if not ts:
            return False
        try:
            record_ts = datetime.fromisoformat(str(ts))
        except ValueError:
            return False
        if start_time is not None and record_ts < start_time:
            return False
        if end_time is not None and record_ts >= end_time:
            return False
        return True

    def export_logs(
        self,
        dest_path: Path,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        format: str = "ndjson",
    ) -> None:
        """Export audit log records to *dest_path*.

        Parameters
        ----------
        dest_path:
            Destination file path.
        start_time:
            Only include records at or after this time (inclusive).
        end_time:
            Only include records before this time (exclusive).
        format:
            Output format: ``"ndjson"`` (raw NDJSON with HMAC) or ``"csv"``
            (timestamp, event_type, details as JSON).
        """
        self._validate_time_range(start_time, end_time)

        # Verify integrity before exporting.
        ok, invalid = self.verify()
        if not ok:
            raise RuntimeError(f"Audit log integrity check failed. Tampered lines: {invalid}")

        if format not in ("ndjson", "csv"):
            raise ValueError(f"Unsupported export format: {format!r}")

        records: list[dict[str, Any]] = []
        for _lineno, record in self._iter_records():
            if self._record_in_range(record, start_time, end_time):
                records.append(record)

        dest_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "ndjson":
            content = "\n".join(json.dumps(r, default=str) for r in records) + "\n"
            dest_path.write_text(content, encoding="utf-8")
        else:
            with dest_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "event_type", "details", "hmac"])
                for r in records:
                    writer.writerow(
                        [
                            r.get("timestamp", ""),
                            r.get("event_type", ""),
                            json.dumps(r.get("details", {}), default=str),
                            r.get("hmac", ""),
                        ]
                    )

    def statistics(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, Any]:
        """Return aggregate statistics for the audit log.

        Parameters
        ----------
        start_time:
            Only include records at or after this time (inclusive).
        end_time:
            Only include records before this time (exclusive).

        Returns
        -------
        dict with keys:
            ``total_events``, ``by_event_type``, ``by_severity``,
            ``active_periods``.
        """
        self._validate_time_range(start_time, end_time)

        total = 0
        by_event_type: dict[str, int] = {}
        by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}

        timestamps: list[datetime] = []

        severity_map: dict[str, str] = {
            "decrypted": "CRITICAL",
            "master_key_changed": "CRITICAL",
            "sandbox_escape_attempt": "CRITICAL",
            "cloud_fallback_used": "HIGH",
            "policy_violation": "HIGH",
            "offline_policy_violation": "HIGH",
            "sandbox_run_failed": "MEDIUM",
            "password_store_operation": "MEDIUM",
            "connection_tested": "MEDIUM",
        }

        for _lineno, record in self._iter_records():
            if not self._record_in_range(record, start_time, end_time):
                continue

            total += 1
            et = record.get("event_type", "unknown")
            by_event_type[et] = by_event_type.get(et, 0) + 1

            severity = severity_map.get(et)
            if severity:
                by_severity[severity] += 1

            ts = record.get("timestamp")
            if ts:
                try:
                    record_ts = datetime.fromisoformat(str(ts))
                    timestamps.append(record_ts)
                except ValueError:
                    pass

        # Compute active periods: group consecutive timestamps within 30 minutes.
        active_periods: list[dict[str, str]] = []
        if timestamps:
            timestamps.sort()
            period_start = timestamps[0]
            period_end = timestamps[0]
            gap = 30 * 60  # 30 minutes in seconds

            for t in timestamps[1:]:
                if (t - period_end).total_seconds() <= gap:
                    period_end = t
                else:
                    active_periods.append(
                        {
                            "start": period_start.isoformat(),
                            "end": period_end.isoformat(),
                        }
                    )
                    period_start = t
                    period_end = t
            active_periods.append(
                {
                    "start": period_start.isoformat(),
                    "end": period_end.isoformat(),
                }
            )

        return {
            "total_events": total,
            "by_event_type": by_event_type,
            "by_severity": by_severity,
            "active_periods": active_periods,
        }
