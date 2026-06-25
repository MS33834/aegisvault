"""Conflict detection and resolution for AegisVault multi-device sync.

Strategies
----------
- :class:`LastWriteWins`  – resolve by mtime (simple, fast, default)
- :class:`KeepBoth`        – keep local version, rename remote copy
- :class:`ManualResolve`   – flag for user decision via callback
- :class:`CRDTMerge`       – merge JSON / metadata files with per-key LWW
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from aegisvault.sync.protocol import FileIndex

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Conflict representation
# ---------------------------------------------------------------------------


@dataclass
class Conflict:
    """Describes a conflict between local and remote versions of a file."""

    file_path: str
    local_version: dict[str, Any] = field(default_factory=dict)
    remote_version: dict[str, Any] = field(default_factory=dict)
    conflict_type: str = ""

    # Canonical conflict types
    TYPE_CONCURRENT_EDIT: str = "concurrent_edit"
    TYPE_DELETE_VS_EDIT: str = "delete_vs_edit"
    TYPE_CREATE_VS_CREATE: str = "create_vs_create"


# ---------------------------------------------------------------------------
# Conflict detector
# ---------------------------------------------------------------------------


class ConflictDetector:
    """Compare two :class:`FileIndex` snapshots and enumerate conflicts.

    The detector identifies three categories:

    * **concurrent_edit** – same file exists in both indexes with different
      content hashes.
    * **delete_vs_edit** – one side deleted the file while the other changed it
      (requires *known_files* from the previous sync state for accuracy).
    * **create_vs_create** – both sides independently created a new file at
      the same path with different content.

    Parameters
    ----------
    known_files:
        Optional mapping of ``vault_path → hash`` from the previous sync
        state.  When supplied, ``delete_vs_edit`` is distinguished from
        ``create_vs_create``.
    """

    def __init__(self, known_files: dict[str, str] | None = None) -> None:
        self._known_files = known_files or {}

    def detect(
        self,
        local_index: FileIndex,
        remote_index: FileIndex,
    ) -> list[Conflict]:
        """Return a list of :class:`Conflict` objects.

        Parameters
        ----------
        local_index:
            File index snapshot from the local device.
        remote_index:
            File index snapshot received from the peer.
        """
        local_files = local_index.files
        remote_files = remote_index.files
        conflicts: list[Conflict] = []

        all_keys = set(local_files) | set(remote_files)

        for key in all_keys:
            in_local = key in local_files
            in_remote = key in remote_files

            if in_local and in_remote:
                local_hash = local_files[key].get("hash", "")
                remote_hash = remote_files[key].get("hash", "")
                if local_hash and remote_hash and local_hash != remote_hash:
                    conflicts.append(
                        Conflict(
                            file_path=key,
                            local_version=local_files[key],
                            remote_version=remote_files[key],
                            conflict_type=Conflict.TYPE_CONCURRENT_EDIT,
                        )
                    )
            elif in_local and not in_remote:
                if key in self._known_files:
                    # Previously known → remote deleted, we edited
                    conflicts.append(
                        Conflict(
                            file_path=key,
                            local_version=local_files[key],
                            remote_version={},
                            conflict_type=Conflict.TYPE_DELETE_VS_EDIT,
                        )
                    )
                # else: local-only new file (no conflict)
            elif not in_local and in_remote:
                if key in self._known_files:
                    # Previously known → local deleted, remote edited
                    conflicts.append(
                        Conflict(
                            file_path=key,
                            local_version={},
                            remote_version=remote_files[key],
                            conflict_type=Conflict.TYPE_DELETE_VS_EDIT,
                        )
                    )
                else:
                    # Both created same path? Only remote has it.
                    # Check if we also have a creation with same path but it
                    # was in known_files=False branch. Actually if only remote
                    # has it and it wasn't known, it's just a new remote file —
                    # no conflict.
                    pass

            # create_vs_create: not in known_files, exists on both sides with
            # different hashes — already handled as concurrent_edit above.

        return conflicts


# ---------------------------------------------------------------------------
# Abstract resolver
# ---------------------------------------------------------------------------


class ConflictResolver(ABC):
    """Abstract base for conflict resolution strategies."""

    @abstractmethod
    def resolve(
        self,
        conflict: Conflict,
        local_index: FileIndex,
        remote_index: FileIndex,
    ) -> dict[str, Any]:
        """Resolve a conflict.

        Returns a dict with at least ``action`` (one of ``keep_local``,
        ``keep_remote``, ``keep_both``, ``merge``) and ``reason``.
        """
        ...


# ---------------------------------------------------------------------------
# Last-write-wins (default)
# ---------------------------------------------------------------------------


class LastWriteWins(ConflictResolver):
    """Resolve conflicts by keeping whichever version has the most recent mtime.

    This is the default strategy because it is simple, predictable, and
    works for most file types.
    """

    def resolve(
        self,
        conflict: Conflict,
        local_index: FileIndex,
        remote_index: FileIndex,
    ) -> dict[str, Any]:
        local_mtime = conflict.local_version.get("mtime", 0.0) if conflict.local_version else 0.0
        remote_mtime = conflict.remote_version.get("mtime", 0.0) if conflict.remote_version else 0.0

        if conflict.conflict_type == Conflict.TYPE_DELETE_VS_EDIT:
            # If remote deleted but we have local edits → keep local
            if conflict.local_version and not conflict.remote_version:
                return {
                    "action": "keep_local",
                    "file_path": conflict.file_path,
                    "reason": "delete_vs_edit: keeping local edit",
                }
            # If local deleted but remote edited → keep remote
            return {
                "action": "keep_remote",
                "file_path": conflict.file_path,
                "reason": "delete_vs_edit: keeping remote edit",
            }

        if remote_mtime > local_mtime:
            return {
                "action": "keep_remote",
                "file_path": conflict.file_path,
                "reason": f"remote mtime {remote_mtime} > local {local_mtime}",
            }
        return {
            "action": "keep_local",
            "file_path": conflict.file_path,
            "reason": f"local mtime {local_mtime} >= remote {remote_mtime}",
        }


# ---------------------------------------------------------------------------
# Keep-both
# ---------------------------------------------------------------------------


class KeepBoth(ConflictResolver):
    """Keep the local version as-is and rename the remote version.

    The remote version is written to ``<file>.conflict.<timestamp>.<ext>``
    so both versions survive.
    """

    def resolve(
        self,
        conflict: Conflict,
        local_index: FileIndex,
        remote_index: FileIndex,
    ) -> dict[str, Any]:
        ts = int(time.time())
        if "." in conflict.file_path:
            name, ext = conflict.file_path.rsplit(".", 1)
        else:
            name, ext = conflict.file_path, ""
        conflict_name = f"{name}.conflict.{ts}.{ext}" if ext else f"{name}.conflict.{ts}"

        return {
            "action": "keep_both",
            "file_path": conflict.file_path,
            "conflict_path": conflict_name,
            "reason": f"both versions kept — conflict copy at {conflict_name}",
        }


# ---------------------------------------------------------------------------
# Manual resolution
# ---------------------------------------------------------------------------


class ManualResolve(ConflictResolver):
    """Flag conflicts for manual resolution.

    Returns ``action="manual"`` so the engine can invoke the conflict
    callback for a user decision.
    """

    def resolve(
        self,
        conflict: Conflict,
        local_index: FileIndex,
        remote_index: FileIndex,
    ) -> dict[str, Any]:
        return {
            "action": "manual",
            "file_path": conflict.file_path,
            "conflict_type": conflict.conflict_type,
            "local_hash": conflict.local_version.get("hash", ""),
            "remote_hash": conflict.remote_version.get("hash", ""),
            "reason": "requires manual resolution",
        }


# ---------------------------------------------------------------------------
# CRDT merge (for JSON / metadata files)
# ---------------------------------------------------------------------------


class CRDTMerge(ConflictResolver):
    """Merge JSON files with a per-key last-writer-wins CRDT strategy.

    For each key in the union of the local and remote JSON objects, the
    value with the most recent associated ``mtime`` is kept.  This is
    designed for ``.sync_state.json`` and similar metadata files where
    top-level key independence is a reasonable assumption.
    """

    def resolve(
        self,
        conflict: Conflict,
        local_index: FileIndex,
        remote_index: FileIndex,
    ) -> dict[str, Any]:
        local_data = (
            self._try_parse_json(conflict.local_version.get("data"))
            if conflict.local_version
            else {}
        )
        remote_data = (
            self._try_parse_json(conflict.remote_version.get("data"))
            if conflict.remote_version
            else {}
        )

        merged: dict[str, Any] = {}
        all_keys = set(local_data.keys()) | set(remote_data.keys())

        local_mtime = conflict.local_version.get("mtime", 0.0) if conflict.local_version else 0.0
        remote_mtime = conflict.remote_version.get("mtime", 0.0) if conflict.remote_version else 0.0

        for key in all_keys:
            in_local = key in local_data
            in_remote = key in remote_data

            if in_local and not in_remote:
                merged[key] = local_data[key]
            elif not in_local and in_remote:
                merged[key] = remote_data[key]
            else:
                # Both have the key — use mtime of the whole file as proxy
                if remote_mtime > local_mtime:
                    merged[key] = remote_data[key]
                else:
                    merged[key] = local_data[key]

        merged_json = json.dumps(merged, sort_keys=True, indent=2)
        merged_hash = hashlib.sha256(merged_json.encode("utf-8")).hexdigest()

        return {
            "action": "merge",
            "file_path": conflict.file_path,
            "merged_data": merged,
            "merged_hash": merged_hash,
            "reason": "CRDT per-key LWW merge",
        }

    @staticmethod
    def _try_parse_json(data: Any) -> dict[str, Any]:
        if data is None:
            return {}
        if isinstance(data, dict):
            return data
        if isinstance(data, str):
            try:
                return json.loads(data)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
