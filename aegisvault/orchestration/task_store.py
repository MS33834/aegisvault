"""SQLite-backed task context persistence."""

import hashlib
import json
import logging
import math
import random
import sqlite3
import struct
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from aegisvault.api.schemas import ClassificationResult, SearchResult, TaskStatus, TaskSummary
from aegisvault.model.embedding import LocalEmbeddingProvider
from aegisvault.orchestration.state_machine import TaskState

logger = logging.getLogger(__name__)


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
        conn = sqlite3.connect(self.db_path, timeout=30)
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
            self._init_fts(conn)
            self._init_vectors(conn)
            conn.commit()

    def _init_fts(self, conn: sqlite3.Connection) -> None:
        """Create the SQLite FTS index for vault metadata if supported."""
        self._fts5_enabled = self._has_fts5(conn)
        if self._fts5_enabled:
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS vault_fts USING fts5(
                    task_id UNINDEXED,
                    vault_path UNINDEXED,
                    category,
                    summary,
                    tags,
                    disguise_name,
                    created_at UNINDEXED
                )
                """
            )
        else:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_fts_fallback (
                    task_id TEXT PRIMARY KEY,
                    vault_path TEXT,
                    category TEXT,
                    summary TEXT,
                    tags TEXT,
                    disguise_name TEXT,
                    created_at TEXT
                )
                """
            )

    @staticmethod
    def _has_fts5(conn: sqlite3.Connection) -> bool:
        """Return True when the SQLite build supports FTS5."""
        try:
            rows = conn.execute("PRAGMA compile_options").fetchall()
        except sqlite3.Error:
            return False
        return any(str(row[0]) == "ENABLE_FTS5" for row in rows)

    @staticmethod
    def _init_vectors(conn: sqlite3.Connection) -> None:
        """Create the vector index table for semantic search.

        Vectors are stored as BLOB (struct-packed doubles) with a JSON text
        column kept for backwards-compatible reads on legacy databases.
        """
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_vectors (
                task_id TEXT PRIMARY KEY,
                vault_path TEXT,
                category TEXT,
                summary TEXT,
                vector TEXT,
                model TEXT,
                created_at TEXT
            )
            """
        )
        # Migrate: add vector_blob BLOB column.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(vault_vectors)").fetchall()}
        if "vector_blob" not in columns:
            conn.execute("ALTER TABLE vault_vectors ADD COLUMN vector_blob BLOB")
        if "content_hash" not in columns:
            conn.execute("ALTER TABLE vault_vectors ADD COLUMN content_hash TEXT")

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
            cursor = conn.execute(
                "UPDATE tasks SET state = ?, message = ?, updated_at = ? WHERE task_id = ?",
                (state.name, message, self._now(), str(task_id)),
            )
            if cursor.rowcount == 0:
                logger.warning("update_state: task %s not found", task_id)
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

    def delete(self, task_id: UUID) -> None:
        """Delete a task and its search index entries."""
        with self._connect() as conn:
            conn.execute("DELETE FROM tasks WHERE task_id = ?", (str(task_id),))
            if self._fts5_enabled:
                conn.execute("DELETE FROM vault_fts WHERE task_id = ?", (str(task_id),))
            else:
                conn.execute(
                    "DELETE FROM vault_fts_fallback WHERE task_id = ?",
                    (str(task_id),),
                )
            conn.commit()

    def index_classification(
        self,
        task_id: UUID,
        classification: ClassificationResult,
        vault_path: Path,
        created_at: str | None = None,
    ) -> None:
        """Index classification metadata for full-text search."""
        now = created_at or self._now()
        tags = " ".join(classification.tags)
        with self._connect() as conn:
            if self._fts5_enabled:
                conn.execute(
                    "DELETE FROM vault_fts WHERE task_id = ?",
                    (str(task_id),),
                )
                conn.execute(
                    """
                    INSERT INTO vault_fts
                        (task_id, vault_path, category, summary, tags, disguise_name, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(task_id),
                        str(vault_path),
                        classification.category,
                        classification.summary,
                        tags,
                        classification.disguise_name,
                        now,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO vault_fts_fallback
                        (task_id, vault_path, category, summary, tags, disguise_name, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(task_id),
                        str(vault_path),
                        classification.category,
                        classification.summary,
                        tags,
                        classification.disguise_name,
                        now,
                    ),
                )
            conn.commit()

    @staticmethod
    def _embedding_text(classification: ClassificationResult) -> str:
        """Build the text representation used for embedding generation."""
        text = f"{classification.summary} {' '.join(classification.tags)}".strip()
        if not text:
            text = classification.category
        return text

    @staticmethod
    def _content_hash_for(classification: ClassificationResult) -> str:
        """Return a stable content hash to detect classification changes."""
        text = TaskStore._embedding_text(classification)
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def index_embedding(
        self,
        task_id: UUID,
        vault_path: Path,
        classification: ClassificationResult,
        provider: LocalEmbeddingProvider,
        created_at: str | None = None,
    ) -> None:
        """Generate and store an embedding for summary/tags metadata.

        The vector is stored as a struct-packed BLOB for compact storage.
        A JSON column is kept for backwards-compatible reads on legacy databases.
        Incremental update: re-embeds only when the content hash has changed.
        """
        text = self._embedding_text(classification)
        if not text:
            return
        content_hash = self._content_hash_for(classification)

        # Check if re-embedding is necessary (incremental update).
        with self._connect() as conn:
            row = conn.execute(
                "SELECT content_hash FROM vault_vectors WHERE task_id = ?",
                (str(task_id),),
            ).fetchone()
        if row is not None and row[0] == content_hash:
            logger.debug("index_embedding: content unchanged for %s, skipping re-embed", task_id)
            return

        vector = provider.embed([text])[0]
        vector_blob = struct.pack(f"{len(vector)}d", *vector)
        model_name = getattr(provider, "model_name", "unknown")
        now = created_at or self._now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO vault_vectors
                    (task_id, vault_path, category, summary, vector, vector_blob,
                     content_hash, model, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(task_id),
                    str(vault_path),
                    classification.category,
                    classification.summary,
                    json.dumps(vector),
                    vector_blob,
                    content_hash,
                    model_name,
                    now,
                ),
            )
            conn.commit()

    def batch_index_embeddings(
        self,
        task_ids: list[UUID],
        provider: LocalEmbeddingProvider,
    ) -> None:
        """Batch-encode multiple task texts via a single provider call.

        Only tasks whose ``classification`` exists in the ``tasks`` table and
        whose content hash differs from the cached one are re-embedded, so this
        method is safe to call repeatedly (incremental update).
        """
        if not task_ids:
            return
        texts: list[str] = []
        valid_ids: list[str] = []
        new_hashes: list[str] = []
        vault_paths: list[str] = []
        categories: list[str] = []
        summaries: list[str] = []

        with self._connect(row_factory=sqlite3.Row) as conn:
            for tid in task_ids:
                row = conn.execute(
                    "SELECT classification, vault_path FROM tasks WHERE task_id = ?",
                    (str(tid),),
                ).fetchone()
                if row is None or not row["classification"]:
                    continue
                try:
                    cls_data = json.loads(row["classification"])
                except (json.JSONDecodeError, TypeError):
                    logger.debug("batch_index_embeddings: invalid classification for %s", tid)
                    continue

                try:
                    cls = ClassificationResult(
                        sensitivity=cls_data.get("sensitivity", "low"),
                        category=cls_data.get("category", "unknown"),
                        tags=cls_data.get("tags", []),
                        summary=cls_data.get("summary", ""),
                        disguise_name=cls_data.get("disguise_name", "unknown"),
                        disguise_extension=cls_data.get("disguise_extension", "dat"),
                    )
                except Exception:
                    logger.debug("batch_index_embeddings: classification parse error for %s", tid)
                    continue

                text = self._embedding_text(cls)
                if not text:
                    continue
                content_hash = self._content_hash_for(cls)

                # Check existing cache.
                vec_row = conn.execute(
                    "SELECT content_hash FROM vault_vectors WHERE task_id = ?",
                    (str(tid),),
                ).fetchone()
                if vec_row is not None and vec_row["content_hash"] == content_hash:
                    continue

                texts.append(text)
                valid_ids.append(str(tid))
                new_hashes.append(content_hash)
                vault_paths.append(row["vault_path"] or "")
                categories.append(cls.category)
                summaries.append(cls.summary)

        if not texts:
            return

        model_name = getattr(provider, "model_name", "unknown")
        now = self._now()
        vectors = provider.embed(texts)
        if len(vectors) != len(texts):
            raise RuntimeError(
                f"batch_index_embeddings: expected {len(texts)} vectors, got {len(vectors)}"
            )

        with self._connect() as conn:
            for vid, vec, chash, vp, cat, summ in zip(
                valid_ids,
                vectors,
                new_hashes,
                vault_paths,
                categories,
                summaries,
                strict=True,
            ):
                vector_blob = struct.pack(f"{len(vec)}d", *vec)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO vault_vectors
                        (task_id, vault_path, category, summary, vector, vector_blob,
                         content_hash, model, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (vid, vp, cat, summ, json.dumps(vec), vector_blob, chash, model_name, now),
                )
            conn.commit()

    def search(self, query: str, top_k: int = 5) -> list[SearchResult]:
        """Search indexed vault metadata for the given keywords."""
        if self._fts5_enabled:
            return self._search_fts(query, top_k)
        return self._search_fallback(query, top_k)

    def semantic_search(
        self,
        query: str,
        top_k: int,
        provider: LocalEmbeddingProvider,
    ) -> list[SearchResult]:
        """Search vector index by cosine similarity to the query embedding.

        Reads vectors from ``vector_blob`` BLOB column when available, falling
        back to the legacy JSON ``vector`` column for backwards compatibility.
        """
        query = query.strip()
        if not query:
            return []
        query_vector = provider.embed([query])[0]
        scored: list[tuple[float, sqlite3.Row]] = []
        with self._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                "SELECT vault_path, category, summary, vector, vector_blob FROM vault_vectors"
            ).fetchall()
        for row in rows:
            vector = self._read_vector(row)
            if vector is None:
                continue
            score = self._cosine_similarity(query_vector, vector)
            scored.append((score, row))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            SearchResult(
                vault_path=Path(row["vault_path"]),
                category=row["category"],
                summary=row["summary"],
                score=score,
            )
            for score, row in scored[:top_k]
        ]

    @staticmethod
    def _read_vector(row: sqlite3.Row) -> list[float] | None:
        """Read a vector from a DB row, preferring BLOB format with JSON fallback."""
        blob = row["vector_blob"]
        if blob is not None:
            try:
                return list(struct.unpack(f"{len(blob) // 8}d", blob))
            except (struct.error, MemoryError):
                pass
        text = row["vector"]
        if text is not None:
            try:
                result: list[float] = json.loads(text)
                return result
            except (json.JSONDecodeError, TypeError):
                pass
        return None

    def hybrid_search(
        self,
        query: str,
        top_k: int = 10,
        fts_weight: float = 0.3,
        semantic_weight: float = 0.7,
        provider: LocalEmbeddingProvider | None = None,
    ) -> list[SearchResult]:
        """Perform weighted hybrid search combining FTS and semantic vector results.

        FTS full-text results and semantic cosine-similarity results are both
        fetched, normalized to [0, 1], and combined via:
        ``final = fts_weight * norm_fts + semantic_weight * norm_semantic``.
        Results are deduplicated and sorted by descending final score.
        """
        query = query.strip()
        if not query:
            return []

        fts_raw = self.search(query, top_k=top_k * 2)
        semantic_raw: list[SearchResult] = []
        if provider is not None:
            semantic_raw = self.semantic_search(query, top_k=top_k * 2, provider=provider)

        return _hybrid_fuse(fts_raw, semantic_raw, top_k, fts_weight, semantic_weight)

    def find_similar(self, task_id: UUID, top_k: int = 5) -> list[dict[str, Any]]:
        """Return the top_k most similar documents to *task_id* by cosine similarity.

        Returns:
            list of ``{"task_id": str, "score": float, "category": str, "summary": str}``.
        """
        with self._connect(row_factory=sqlite3.Row) as conn:
            target_row = conn.execute(
                "SELECT task_id, vault_path, category, summary, vector, vector_blob "
                "FROM vault_vectors WHERE task_id = ?",
                (str(task_id),),
            ).fetchone()
        if target_row is None:
            return []

        target_vector = self._read_vector(target_row)
        if target_vector is None:
            return []

        scored: list[tuple[float, sqlite3.Row]] = []
        with self._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                "SELECT task_id, vault_path, category, summary, vector, vector_blob "
                "FROM vault_vectors WHERE task_id != ?",
                (str(task_id),),
            ).fetchall()
        for row in rows:
            vector = self._read_vector(row)
            if vector is None:
                continue
            score = self._cosine_similarity(target_vector, vector)
            scored.append((score, row))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            {
                "task_id": row["task_id"],
                "score": score,
                "category": row["category"] or "",
                "summary": row["summary"] or "",
            }
            for score, row in scored[:top_k]
        ]

    def cluster_vault(
        self,
        n_clusters: int = 5,
        max_iterations: int = 100,
        seed: int = 42,
    ) -> dict[int, list[dict[str, Any]]]:
        """Cluster all vault documents using pure-Python K-means on their embedding vectors.

        No numpy/scipy dependency — vectors are read from the ``vector_blob`` column
        (with JSON fallback) and clustering runs entirely in stdlib Python.

        Returns:
            ``{cluster_id: [{"task_id": str, "category": str, "summary": str}, ...]}``
        """
        # Load all vectors and metadata.
        vectors: list[list[float]] = []
        metas: list[dict[str, Any]] = []
        with self._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                "SELECT task_id, category, summary, vector, vector_blob FROM vault_vectors"
            ).fetchall()
        for row in rows:
            vec = self._read_vector(row)
            if vec is None:
                continue
            vectors.append(vec)
            metas.append(
                {
                    "task_id": row["task_id"] or "",
                    "category": row["category"] or "",
                    "summary": row["summary"] or "",
                }
            )

        if not vectors:
            return {}
        if n_clusters > len(vectors):
            n_clusters = len(vectors)

        cluster_ids = _kmeans(vectors, n_clusters, max_iterations, seed)

        result: dict[int, list[dict[str, Any]]] = {i: [] for i in range(n_clusters)}
        for idx, cid in enumerate(cluster_ids):
            result[cid].append(metas[idx])
        return result

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        """Compute cosine similarity between two vectors without numpy."""
        if len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b, strict=True))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def _search_fts(self, query: str, top_k: int) -> list[SearchResult]:
        """Execute an FTS5 search with prefix matching on each token."""
        tokens = [token for token in query.split() if token]
        if not tokens:
            return []
        # Quote each token and enable prefix matching.
        quote = '"'
        escaped_quote = '""'
        match_expr = " ".join(
            f"{quote}{token.replace(quote, escaped_quote)}{quote}*" for token in tokens
        )
        with self._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                """
                SELECT vault_path, category, summary, rank
                FROM vault_fts
                WHERE vault_fts MATCH ?
                ORDER BY rank
                LIMIT ?
                """,
                (match_expr, top_k),
            ).fetchall()
        return [
            SearchResult(
                vault_path=Path(row["vault_path"]),
                category=row["category"],
                summary=row["summary"],
                score=1.0 / (1.0 + abs(float(row["rank"]))),
            )
            for row in rows
        ]

    def _search_fallback(self, query: str, top_k: int) -> list[SearchResult]:
        """Fallback LIKE-based search when FTS5 is unavailable."""
        tokens = [token.lower() for token in query.split() if token]
        if not tokens:
            return []
        conditions = " OR ".join(
            "(LOWER(category) LIKE ? OR LOWER(summary) LIKE ? OR LOWER(tags) LIKE ?"
            " OR LOWER(disguise_name) LIKE ?)"
            for _ in tokens
        )
        params: list[str] = []
        for token in tokens:
            like = f"%{token}%"
            params.extend([like, like, like, like])
        params.append(str(top_k))
        with self._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                f"""
                SELECT vault_path, category, summary
                FROM vault_fts_fallback
                WHERE {conditions}
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [
            SearchResult(
                vault_path=Path(row["vault_path"]),
                category=row["category"],
                summary=row["summary"],
                score=1.0,
            )
            for row in rows
        ]

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
                WHERE state IN ({",".join("?" * len(states))})
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

    def list_vault_files(self, category: str | None = None) -> list[dict[str, Any]]:
        """Return completed vault file metadata, optionally filtered by category."""
        with self._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                "SELECT task_id, vault_path, classification FROM tasks "
                "WHERE vault_path IS NOT NULL AND state = ? "
                "ORDER BY updated_at DESC, created_at DESC",
                (TaskState.COMPLETED.name,),
            ).fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            classification_raw = row["classification"]
            if not classification_raw:
                continue
            try:
                cls_data = json.loads(classification_raw)
            except json.JSONDecodeError:
                continue
            cat = cls_data.get("category", "unknown")
            if category is not None and cat != category:
                continue
            results.append(
                {
                    "task_id": row["task_id"],
                    "vault_path": row["vault_path"],
                    "category": cat,
                    "summary": cls_data.get("summary", ""),
                    "tags": cls_data.get("tags", []),
                }
            )
        return results


# ---------------------------------------------------------------------------
# Module-level helpers for hybrid search fusion, rank fusion, and clustering
# ---------------------------------------------------------------------------


def _normalize_scores(results: list[SearchResult]) -> dict[str, float]:
    """Min-max normalize result scores to [0, 1], keyed by vault_path.

    Returns an empty dict when there are no results.
    """
    if not results:
        return {}
    scores = [r.score for r in results]
    smin, smax = scores[0], scores[0]
    for s in scores:
        if s < smin:
            smin = s
        if s > smax:
            smax = s
    denom = smax - smin
    if denom == 0:
        return {str(r.vault_path): 1.0 for r in results}
    return {str(r.vault_path): (r.score - smin) / denom for r in results}


def _hybrid_fuse(
    fts: list[SearchResult],
    semantic: list[SearchResult],
    top_k: int,
    fts_weight: float,
    semantic_weight: float,
) -> list[SearchResult]:
    """Fuse FTS and semantic results via weighted normalized-score combination.

    Returns the top_k results sorted by descending final score.
    """
    if not fts:
        return semantic[:top_k]
    if not semantic:
        return fts[:top_k]

    fts_norm = _normalize_scores(fts)
    sem_norm = _normalize_scores(semantic)

    merged: dict[str, SearchResult] = {}
    final_scores: dict[str, float] = {}

    for r in fts:
        key = str(r.vault_path)
        merged[key] = r
        s_fts = fts_norm.get(key, 0.0)
        s_sem = sem_norm.get(key, 0.0)
        final_scores[key] = fts_weight * s_fts + semantic_weight * s_sem

    for r in semantic:
        key = str(r.vault_path)
        if key not in merged:
            merged[key] = r
            s_fts = fts_norm.get(key, 0.0)
            s_sem = sem_norm.get(key, 0.0)
            final_scores[key] = fts_weight * s_fts + semantic_weight * s_sem

    combined = [merged[key].model_copy(update={"score": final_scores[key]}) for key in merged]
    combined.sort(key=lambda item: item.score, reverse=True)
    return combined[:top_k]


def rank_fusion(
    results_a: list[SearchResult],
    results_b: list[SearchResult],
    weight_a: float = 0.5,
    weight_b: float = 0.5,
    k: int = 60,
) -> list[SearchResult]:
    """Fuse two ranked result lists using Reciprocal Rank Fusion (RRF).

    Each result is assigned an RRF score of ``1 / (k + rank)`` where *rank*
    is its 0-based position in the list. The final score is the weighted sum
    of RRF scores from both lists. When only one list has results the other
    is treated as empty (its RRF contribution is 0).

    This is useful when merging results from different retrieval pipelines
    whose raw scores are not directly comparable.
    """
    # Edge case: one side is empty.
    if not results_a:
        return results_b
    if not results_b:
        return results_a

    # Compute RRF scores keyed by vault_path.
    rrf_a: dict[str, float] = {}
    for rank, r in enumerate(results_a):
        rrf_a[str(r.vault_path)] = 1.0 / (k + rank)

    rrf_b: dict[str, float] = {}
    for rank, r in enumerate(results_b):
        rrf_b[str(r.vault_path)] = 1.0 / (k + rank)

    # Merge and compute weighted final score.
    merged: dict[str, SearchResult] = {}
    for r in results_a:
        merged[str(r.vault_path)] = r
    for r in results_b:
        key = str(r.vault_path)
        if key not in merged:
            merged[key] = r

    scored: list[SearchResult] = []
    for key, result in merged.items():
        score = weight_a * rrf_a.get(key, 0.0) + weight_b * rrf_b.get(key, 0.0)
        scored.append(result.model_copy(update={"score": score}))

    scored.sort(key=lambda item: item.score, reverse=True)
    return scored


def _kmeans(
    vectors: list[list[float]],
    k: int,
    max_iterations: int,
    seed: int,
) -> list[int]:
    """Pure-Python K-means clustering returning cluster assignments.

    Uses the Forgy (random selection) centroid initialisation.  Convergence
    is detected when assignments stop changing or *max_iterations* is reached.
    """
    if k >= len(vectors):
        return list(range(k))

    # Initialise centroids by randomly selecting k distinct data points.
    rng = random.Random(seed)
    centroid_indices = rng.sample(range(len(vectors)), k)
    centroids = [vectors[i][:] for i in centroid_indices]

    def _dim() -> int:
        return len(vectors[0])

    def _argmin(distances: list[float]) -> int:
        best_idx = 0
        best_val = distances[0]
        for idx, val in enumerate(distances):
            if val < best_val:
                best_val = val
                best_idx = idx
        return best_idx

    dim = _dim()
    cluster_ids = [0] * len(vectors)
    prev_ids: list[int] | None = None

    for _iter in range(max_iterations):
        # Assignment step: assign each point to the nearest centroid.
        changed = False
        for i, vec in enumerate(vectors):
            distances = [
                math.sqrt(sum((vec[d] - centroids[c][d]) ** 2 for d in range(dim)))
                for c in range(k)
            ]
            cid = _argmin(distances)
            cluster_ids[i] = cid
            if prev_ids is not None and cid != prev_ids[i]:
                changed = True

        # Update step: recompute centroids as the mean of assigned points.
        centroids = [[0.0] * dim for _ in range(k)]
        counts = [0] * k
        for i, vec in enumerate(vectors):
            cid = cluster_ids[i]
            counts[cid] += 1
            for d in range(dim):
                centroids[cid][d] += vec[d]
        for c in range(k):
            if counts[c] > 0:
                for d in range(dim):
                    centroids[c][d] /= counts[c]

        if prev_ids is not None and not changed:
            break
        prev_ids = cluster_ids[:]

    return cluster_ids
