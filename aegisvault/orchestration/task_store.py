"""SQLite-backed task context persistence."""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from aegisvault.api.schemas import ClassificationResult, TaskStatus, TaskSummary
from aegisvault.orchestration.state_machine import TaskState


class TaskStore:
    """Persist task state and context across crashes."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(
        self, row_factory: type[sqlite3.Row] | None = None
    ) -> Generator[sqlite3.Connection, None, None]:
        """Open a SQLite connection and ensure it is closed.

        The std-lib ``sqlite3.connect`` context manager only handles
        transactions; it does *not* close the connection on exit.
        """
        conn = sqlite3.connect(self.db_path)
        if row_factory is not None:
            conn.row_factory = row_factory
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create tasks table if not exists and migrate schema."""
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    source_path TEXT,
                    classification TEXT,
                    vault_path TEXT,
                    salt BLOB,
                    nonce BLOB,
                    message TEXT DEFAULT '',
                    created_at TEXT DEFAULT '',
                    updated_at TEXT DEFAULT ''
                )
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(tasks)").fetchall()}
            if "created_at" not in columns:
                conn.execute("ALTER TABLE tasks ADD COLUMN created_at TEXT DEFAULT ''")
            if "updated_at" not in columns:
                conn.execute("ALTER TABLE tasks ADD COLUMN updated_at TEXT DEFAULT ''")
            conn.commit()

    @staticmethod
    def _now() -> str:
        """Return an ISO-8601 UTC timestamp string."""
        return datetime.now(timezone.utc).isoformat()  # noqa: UP017

    def create(self, task_id: UUID, source_path: Path) -> TaskStatus:
        """Create a new task record."""
        now = self._now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO tasks
                    (task_id, state, source_path, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(task_id), TaskState.IDLE.name, str(source_path), now, now),
            )
            conn.commit()
        return TaskStatus(task_id=task_id, state=TaskState.IDLE.name)

    def update_state(self, task_id: UUID, state: TaskState, message: str = "") -> TaskStatus:
        """Update task state."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET state = ?, message = ?, updated_at = ? WHERE task_id = ?",
                (state.name, message, self._now(), str(task_id)),
            )
            conn.commit()
        return TaskStatus(task_id=task_id, state=state.name, message=message)

    def update_classification(
        self,
        task_id: UUID,
        classification: ClassificationResult,
    ) -> None:
        """Store classification result."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET classification = ? WHERE task_id = ?",
                (classification.model_dump_json(), str(task_id)),
            )
            conn.commit()

    def update_vault_result(
        self,
        task_id: UUID,
        vault_path: Path,
        salt: bytes,
        nonce: bytes,
    ) -> None:
        """Store encryption result."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET vault_path = ?, salt = ?, nonce = ? WHERE task_id = ?",
                (str(vault_path), salt, nonce, str(task_id)),
            )
            conn.commit()

    def get(self, task_id: UUID) -> dict[str, Any] | None:
        """Fetch task record as a dictionary."""
        with self._connect(row_factory=sqlite3.Row) as conn:
            row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (str(task_id),)).fetchone()
        if row is None:
            return None
        return dict(row)

    def load_incomplete(self) -> list[dict[str, Any]]:
        """Return all tasks not in a terminal state."""
        terminal = {TaskState.COMPLETED.name, TaskState.FAILED.name, TaskState.QUARANTINED.name}
        with self._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE state NOT IN ({})".format(",".join("?" * len(terminal))),
                tuple(terminal),
            ).fetchall()
        return [dict(row) for row in rows]

    def counts_by_state(self) -> dict[str, int]:
        """Return task counts grouped by state."""
        with self._connect() as conn:
            rows = conn.execute("SELECT state, COUNT(*) FROM tasks GROUP BY state").fetchall()
        return dict(rows)

    def _active_order_clause(self) -> str:
        """Recency ordering that handles legacy rows without timestamps."""
        return """
            ORDER BY
                CASE WHEN updated_at = '' THEN 0 ELSE 1 END DESC,
                updated_at DESC,
                CASE WHEN created_at = '' THEN 0 ELSE 1 END DESC,
                created_at DESC,
                rowid DESC
        """

    def _rows_to_summaries(self, rows: list[sqlite3.Row]) -> list[TaskSummary]:
        """Convert database rows to TaskSummary objects."""
        summaries: list[TaskSummary] = []
        for row in rows:
            source = row["source_path"]
            summaries.append(
                TaskSummary(
                    task_id=UUID(row["task_id"]),
                    state=row["state"],
                    message=row["message"] or "",
                    source_path=Path(source) if source else None,
                )
            )
        return summaries

    def _fetch_by_states(
        self,
        states: set[str],
        limit: int,
    ) -> list[TaskSummary]:
        """Fetch summaries for tasks whose state is in ``states``."""
        if not states:
            return []
        with self._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                f"""
                SELECT task_id, state, message, source_path
                FROM tasks
                WHERE state IN ({','.join('?' * len(states))})
                {self._active_order_clause()}
                LIMIT ?
                """,
                (*states, limit),
            ).fetchall()
        return self._rows_to_summaries(rows)

    def list_active(self, limit: int = 5) -> list[TaskSummary]:
        """Return non-terminal active tasks ordered by most recent update."""
        active_states = {
            TaskState.IDLE.name,
            TaskState.CLASSIFYING.name,
            TaskState.ENCRYPTING.name,
            TaskState.INDEXING.name,
        }
        return self._fetch_by_states(active_states, limit)

    def list_attention(self, limit: int = 5) -> list[TaskSummary]:
        """Return FAILED/QUARANTINED tasks ordered by most recent update."""
        attention_states = {TaskState.FAILED.name, TaskState.QUARANTINED.name}
        return self._fetch_by_states(attention_states, limit)

    def list_recent(self, limit: int = 10) -> list[TaskSummary]:
        """Return the most recently updated task summaries.

        The result is ordered by recency (most recently updated first) and
        capped at ``limit`` entries. Legacy rows without timestamps are sorted
        to the end by rowid so the UI still receives a stable list.
        """
        with self._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                f"""
                SELECT task_id, state, message, source_path
                FROM tasks
                {self._active_order_clause()}
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return self._rows_to_summaries(rows)
