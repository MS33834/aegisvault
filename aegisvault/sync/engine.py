"""Incremental sync engine for AegisVault multi-device P2P sync.

Transports encrypted blobs only – no plaintext payloads leave the device.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import struct
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aegisvault.sync.auth import DeviceAuth
from aegisvault.sync.conflict import Conflict, ConflictDetector, ConflictResolver
from aegisvault.sync.discovery import DeviceDiscovery
from aegisvault.sync.protocol import FileIndex, SecureSyncProtocol, SyncMessage, SyncState

logger = logging.getLogger(__name__)

CHUNK_SIZE = 64 * 1024  # 64 KB
SYNC_STATE_FILE = ".sync_state.json"
HEADER_FMT = "!I"  # 4-byte big-endian unsigned int for length prefix
FILE_META_MARKER = 0x00
FILE_CHUNK_MARKER = 0x01
FILE_END_MARKER = 0x02

DEFAULT_SYNC_PORT = 9527


# ── Wire helpers ─────────────────────────────────────────────────────────────


async def _recv_exactly(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)


async def _send_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    """Send a length-prefixed frame."""
    writer.write(struct.pack(HEADER_FMT, len(data)) + data)
    await writer.drain()


async def _recv_frame(reader: asyncio.StreamReader) -> bytes:
    """Receive a length-prefixed frame."""
    header = await _recv_exactly(reader, 4)
    length = struct.unpack(HEADER_FMT, header)[0]
    return await _recv_exactly(reader, length)


async def _send_message(writer: asyncio.StreamWriter, msg: SyncMessage) -> None:
    """Pack and send a SyncMessage as a length-prefixed JSON frame."""
    await _send_frame(writer, SecureSyncProtocol.pack(msg))


async def _recv_message(reader: asyncio.StreamReader) -> SyncMessage:
    """Receive and unpack a length-prefixed JSON frame into a SyncMessage."""
    raw = await _recv_frame(reader)
    return SecureSyncProtocol.unpack(raw)


# ── Sync Engine ──────────────────────────────────────────────────────────────


class SyncEngine:
    """Incremental P2P file synchronisation engine.

    Parameters
    ----------
    vault_path:
        Root directory of the vault whose contents are synchronised.
    protocol:
        Pre-configured :class:`SecureSyncProtocol` for message signing
        and transport encryption.
    discovery:
        Device discovery instance used to locate peers on the LAN.
    auth:
        Device authorisation manager that holds per-peer shared secrets.
    vault_key:
        32-byte AES-256 key used to encrypt ``.sync_state.json`` at rest.
        Defaults to the protocol's shared secret if omitted.
    """

    def __init__(
        self,
        vault_path: Path,
        protocol: SecureSyncProtocol,
        discovery: DeviceDiscovery,
        auth: DeviceAuth,
        vault_key: bytes | None = None,
    ) -> None:
        self.vault_path = vault_path
        self.vault_path.mkdir(parents=True, exist_ok=True)
        self.protocol = protocol
        self.discovery = discovery
        self.auth = auth
        self.vault_key = vault_key if vault_key is not None else protocol.shared_secret

        self._sync_state: SyncState = SyncState()
        self._state_path = vault_path / SYNC_STATE_FILE
        self._load_state()

        self._server: asyncio.AbstractServer | None = None
        self._running = False
        self._conflict_callback: Callable[[Conflict], str | None] | None = None
        self._conflict_resolver: ConflictResolver | None = None

        # Stat cache to avoid repeated I/O during diff computation.
        self._stat_cache: dict[str, tuple[float, int]] = {}

    # ------------------------------------------------------------------
    # Conflict resolution callback
    # ------------------------------------------------------------------

    def set_conflict_callback(self, callback: Callable[[Conflict], str | None]) -> None:
        """Register a callback invoked for each unresolved conflict.

        The callback receives a :class:`Conflict` and may return one of
        ``"keep_local"``, ``"keep_remote"``, ``"keep_both"``, ``"merge"``,
        or ``None`` to defer to the configured strategy.
        """
        self._conflict_callback = callback

    def set_conflict_resolver(self, resolver: ConflictResolver) -> None:
        """Set the default conflict resolution strategy."""
        self._conflict_resolver = resolver

    # ------------------------------------------------------------------
    # File index
    # ------------------------------------------------------------------

    async def build_index(self) -> FileIndex:
        """Walk the vault and produce a :class:`FileIndex` snapshot."""

        def _scan() -> dict[str, dict[str, Any]]:
            files: dict[str, dict[str, Any]] = {}
            for root, _, filenames in os.walk(self.vault_path):
                for name in filenames:
                    if name == SYNC_STATE_FILE:
                        continue
                    full = Path(root) / name
                    try:
                        st = full.stat()
                    except OSError:
                        continue
                    try:
                        data = full.read_bytes()
                    except OSError:
                        continue
                    file_hash = hashlib.sha256(data).hexdigest()
                    rel = str(full.relative_to(self.vault_path))
                    files[rel] = {
                        "hash": file_hash,
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                        "device_id": self.protocol.device_id,
                    }
                    self._stat_cache[rel] = (st.st_mtime, st.st_size)
            return files

        files = await asyncio.to_thread(_scan)
        return FileIndex(
            files=files,
            snapshot_time=time.time(),
            device_id=self.protocol.device_id,
        )

    async def detect_changes(
        self, old_index: FileIndex, new_index: FileIndex
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
        """Return ``(added, modified, deleted)`` lists.

        Comparison is based on content hash (SHA-256), not mtime, to avoid
        clock-skew false positives.
        """
        old_files = old_index.files
        new_files = new_index.files

        old_keys = set(old_files)
        new_keys = set(new_files)

        added: list[dict[str, Any]] = []
        modified: list[dict[str, Any]] = []
        deleted: list[str] = list(old_keys - new_keys)

        for key in new_keys & old_keys:
            if new_files[key]["hash"] != old_files[key]["hash"]:
                modified.append(new_files[key])
        for key in new_keys - old_keys:
            added.append(new_files[key])

        return added, modified, deleted

    # ------------------------------------------------------------------
    # Sync server
    # ------------------------------------------------------------------

    async def start_sync_server(self, host: str = "0.0.0.0", port: int = DEFAULT_SYNC_PORT) -> None:
        """Start an asyncio TCP server that handles incoming sync requests."""
        self._server = await asyncio.start_server(self._handle_peer_connection, host, port)
        self._running = True
        logger.info("Sync server listening on %s:%d", host, port)

    async def stop_sync_server(self) -> None:
        """Stop the sync server."""
        self._running = False
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_peer_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle an incoming peer connection."""
        peer_addr = writer.get_extra_info("peername")
        logger.info("Incoming sync connection from %s", peer_addr)
        try:
            await self._sync_as_server(reader, writer)
        except Exception:
            logger.exception("Error handling peer connection")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _sync_as_server(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Server-side sync: receive peer index, push changes, pull updates."""

        # 1. Receive peer hello
        hello_msg = await _recv_message(reader)
        peer_id = hello_msg.sender_device_id

        # Verify auth
        if not self.auth.is_authorized(peer_id):
            logger.warning("Rejected unauthorised peer %s", peer_id)
            return

        peer_secret = self.auth.get_shared_secret(peer_id)
        if peer_secret is None:
            logger.warning("No shared secret for peer %s", peer_id)
            return

        peer_proto = SecureSyncProtocol(peer_id, peer_secret)
        if not peer_proto.verify_message(hello_msg):
            logger.warning("Hello message signature invalid from %s", peer_id)
            return

        # 2. Send our hello
        our_hello = self.protocol.create_hello()
        await _send_message(writer, our_hello)

        # 3. Receive peer index
        index_msg = await _recv_message(reader)
        if not peer_proto.verify_message(index_msg):
            logger.warning("Index signature invalid from %s", peer_id)
            return

        peer_index_data: dict[str, Any] = index_msg.payload
        peer_index = FileIndex.from_dict(peer_index_data)
        local_index = await self.build_index()

        # 4. Send our index
        our_index_msg = self.protocol.create_hello()
        our_index_msg.message_type = "sync_response"
        our_index_msg.payload = local_index.to_dict()
        self.protocol.sign_message(our_index_msg)
        await _send_message(writer, our_index_msg)

        # 5. Compute diffs and detect conflicts
        added, modified, deleted = await self.detect_changes(peer_index, local_index)
        detector = ConflictDetector()
        conflicts = detector.detect(local_index, peer_index)

        # Resolve conflicts
        for conflict in conflicts:
            self._resolve_conflict(conflict, local_index, peer_index)

        # 6. Receive pushed files from peer
        ack = self.protocol.create_ack(peer_proto.device_id)
        await _send_message(writer, ack)

        # Peer pushes files that are new/modified on their side
        while True:
            meta_raw = await _recv_frame(reader)
            if len(meta_raw) == 1 and meta_raw[0] == FILE_END_MARKER:
                break
            file_meta = json.loads(meta_raw)
            vault_path = file_meta["vault_path"]
            try:
                await self._receive_file(reader, vault_path, file_meta["hash"])
                logger.info("Received file: %s", vault_path)
            except Exception:
                logger.exception("Failed to receive file %s", vault_path)

        # 7. Push our changes to peer
        for entry in added + modified:
            full_path = self.vault_path / entry.get("vault_path", "")
            await self._send_file(writer, full_path, entry.get("vault_path", ""))

        # Mark end of pushes
        writer.write(struct.pack(HEADER_FMT, 1) + bytes([FILE_END_MARKER]))
        await writer.drain()

        # 8. Update sync state
        self._sync_state.last_sync_time[peer_id] = time.time()
        self.auth.touch_device(peer_id)
        self._save_state()

    # ------------------------------------------------------------------
    # Peer sync (client side)
    # ------------------------------------------------------------------

    async def sync_with_peer(self, peer_addr: tuple[str, int]) -> dict[str, Any]:
        """Perform a full sync with a remote peer.

        Returns a summary dict with ``status``, ``pulled``, ``pushed``,
        and ``conflicts`` keys.
        """
        summary: dict[str, Any] = {
            "status": "error",
            "pulled": 0,
            "pushed": 0,
            "conflicts": 0,
        }

        try:
            reader, writer = await asyncio.open_connection(*peer_addr)
        except OSError as exc:
            logger.error("Failed to connect to %s:%d: %s", *peer_addr, exc)
            summary["error"] = str(exc)
            return summary

        try:
            # 1. Send hello
            hello = self.protocol.create_hello()
            await _send_message(writer, hello)

            # 2. Receive peer hello
            peer_hello = await _recv_message(reader)
            peer_id = peer_hello.sender_device_id

            if not self.auth.is_authorized(peer_id):
                logger.warning("Peer %s not authorised", peer_id)
                summary["error"] = "unauthorised"
                return summary

            peer_secret = self.auth.get_shared_secret(peer_id)
            if peer_secret is None:
                summary["error"] = "no_shared_secret"
                return summary

            peer_proto = SecureSyncProtocol(peer_id, peer_secret)
            if not peer_proto.verify_message(peer_hello):
                summary["error"] = "invalid_signature"
                return summary

            # 3. Send our index
            local_index = await self.build_index()
            our_index_msg = self.protocol.create_hello()
            our_index_msg.message_type = "sync_response"
            our_index_msg.payload = local_index.to_dict()
            self.protocol.sign_message(our_index_msg)
            await _send_message(writer, our_index_msg)

            # 4. Receive peer index
            peer_index_msg = await _recv_message(reader)
            if not peer_proto.verify_message(peer_index_msg):
                summary["error"] = "invalid_signature"
                return summary

            peer_index_data: dict[str, Any] = peer_index_msg.payload
            peer_index = FileIndex.from_dict(peer_index_data)

            # 5. Compute diffs and conflicts
            added, modified, deleted = await self.detect_changes(local_index, peer_index)
            detector = ConflictDetector()
            conflicts = detector.detect(local_index, peer_index)

            for conflict in conflicts:
                self._resolve_conflict(conflict, local_index, peer_index)

            summary["conflicts"] = len(conflicts)

            # 6. Wait for ACK then pull new files from peer
            try:
                await _recv_message(reader)
            except Exception:
                pass

            # 7. Pull files that exist on peer but not locally (remote has, we don't)
            remote_added, _, _ = await self.detect_changes(local_index, peer_index)
            pulled = 0
            for entry in remote_added:
                vault_path = entry.get("vault_path", "")
                try:
                    success = await self.pull_file(peer_addr, vault_path)
                    if success:
                        pulled += 1
                except Exception:
                    logger.exception("Failed to pull %s", vault_path)
            summary["pulled"] = pulled

            # 8. Push local changes to peer
            pushed = 0
            for entry in added + modified:
                full_path = self.vault_path / entry.get("vault_path", "")
                try:
                    success = await self.push_file(peer_addr, full_path)
                    if success:
                        pushed += 1
                except Exception:
                    logger.exception("Failed to push %s", entry.get("vault_path"))
            summary["pushed"] = pushed

            # Mark end of pushes
            writer.write(struct.pack(HEADER_FMT, 1) + bytes([FILE_END_MARKER]))
            await writer.drain()

            # 9. Update sync state
            self._sync_state.last_sync_time[peer_id] = time.time()
            self.auth.touch_device(peer_id)
            self._save_state()

            summary["status"] = "ok"

        except Exception as exc:
            logger.exception("Sync with %s:%d failed", *peer_addr)
            summary["error"] = str(exc)
        finally:
            writer.close()
            await writer.wait_closed()

        return summary

    # ------------------------------------------------------------------
    # File push / pull
    # ------------------------------------------------------------------

    async def push_file(self, peer_addr: tuple[str, int], vault_path: Path) -> bool:
        """Push a single file to a peer device."""

        try:
            reader, writer = await asyncio.open_connection(*peer_addr)
        except OSError:
            return False

        try:
            rel_path = str(vault_path.relative_to(self.vault_path))
            result = await self._send_file(writer, vault_path, rel_path)
            return result
        finally:
            writer.close()
            await writer.wait_closed()

    async def _send_file(
        self, writer: asyncio.StreamWriter, full_path: Path, rel_path: str
    ) -> bool:
        """Send file content in encrypted chunks."""
        try:
            data = full_path.read_bytes()
        except OSError:
            return False

        file_hash = hashlib.sha256(data).hexdigest()

        # Send metadata
        meta = json.dumps(
            {
                "vault_path": rel_path,
                "hash": file_hash,
                "size": len(data),
            }
        ).encode("utf-8")
        await _send_frame(writer, meta)

        # Send chunks
        for offset in range(0, len(data), CHUNK_SIZE):
            chunk = data[offset : offset + CHUNK_SIZE]
            encrypted = self.protocol.encrypt_transport(chunk, self.vault_key)
            await _send_frame(writer, encrypted)

        # Send zero-length frame as end-of-file marker
        await _send_frame(writer, b"")
        return True

    async def pull_file(self, peer_addr: tuple[str, int], vault_path: str) -> bool:
        """Pull a single file from a peer and write it atomically."""
        try:
            reader, writer = await asyncio.open_connection(*peer_addr)
        except OSError:
            return False

        try:
            # Request the file
            request = self.protocol.create_sync_request(peer_device_id="", since=0.0)
            request.payload = {"action": "pull", "vault_path": vault_path}
            self.protocol.sign_message(request)
            await _send_message(writer, request)

            # Receive metadata
            meta_raw = await _recv_frame(reader)
            file_meta = json.loads(meta_raw)
            expected_hash = file_meta["hash"]

            # Receive and reassemble chunks
            chunks: list[bytes] = []
            while True:
                chunk_raw = await _recv_frame(reader)
                if not chunk_raw:
                    break
                chunk = self.protocol.decrypt_transport(chunk_raw, self.vault_key)
                chunks.append(chunk)

            body = b"".join(chunks)
            actual_hash = hashlib.sha256(body).hexdigest()
            if actual_hash != expected_hash:
                logger.error(
                    "Hash mismatch for %s: expected %s, got %s",
                    vault_path,
                    expected_hash,
                    actual_hash,
                )
                return False

            # Atomic write
            dest = self.vault_path / vault_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(dest.suffix + ".tmp")
            tmp.write_bytes(body)
            tmp.replace(dest)
            return True

        finally:
            writer.close()
            await writer.wait_closed()

    async def _receive_file(
        self,
        reader: asyncio.StreamReader,
        vault_path: str,
        expected_hash: str,
    ) -> bool:
        """Receive a file from a stream and write it atomically."""
        chunks: list[bytes] = []
        while True:
            chunk_raw = await _recv_frame(reader)
            if not chunk_raw:
                break
            chunk = self.protocol.decrypt_transport(chunk_raw, self.vault_key)
            chunks.append(chunk)

        body = b"".join(chunks)
        actual_hash = hashlib.sha256(body).hexdigest()
        if actual_hash != expected_hash:
            logger.error(
                "Hash mismatch for %s: expected %s, got %s",
                vault_path,
                expected_hash,
                actual_hash,
            )
            return False

        dest = self.vault_path / vault_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        tmp.write_bytes(body)
        tmp.replace(dest)
        return True

    # ------------------------------------------------------------------
    # Auto-sync
    # ------------------------------------------------------------------

    async def auto_sync(self, interval: float = 300.0) -> None:
        """Run periodic discovery + sync loop."""
        logger.info(
            "Auto-sync started (interval=%.1fs, device=%s)",
            interval,
            self.protocol.device_id,
        )
        while self._running:
            try:
                peers = self.discovery.get_peers()
                for peer in peers:
                    if not self.auth.is_authorized(peer["device_id"]):
                        continue
                    addr = (peer["ip"], peer["port"])
                    logger.info("Auto-syncing with %s (%s)", peer["device_name"], addr)
                    await self.sync_with_peer(addr)
            except Exception:
                logger.exception("Auto-sync iteration failed")
            await asyncio.sleep(interval)

    # ------------------------------------------------------------------
    # Conflict resolution helper
    # ------------------------------------------------------------------

    def _resolve_conflict(
        self,
        conflict: Conflict,
        local_index: FileIndex,
        remote_index: FileIndex,
    ) -> dict[str, Any]:
        """Resolve a single conflict, consulting the callback and strategy."""
        # First ask the conflict callback
        if self._conflict_callback is not None:
            decision = self._conflict_callback(conflict)
            if decision is not None:
                return {"action": decision, "file_path": conflict.file_path}

        # Fall back to configured resolver or default to LWW
        if self._conflict_resolver is not None:
            return self._conflict_resolver.resolve(conflict, local_index, remote_index)

        from aegisvault.sync.conflict import LastWriteWins

        return LastWriteWins().resolve(conflict, local_index, remote_index)

    # ------------------------------------------------------------------
    # SyncState persistence
    # ------------------------------------------------------------------

    def _encrypt_state(self, state: SyncState) -> bytes:
        """Serialize and encrypt SyncState."""
        raw = json.dumps(
            {
                "last_sync_time": state.last_sync_time,
                "known_files": state.known_files,
                "pending_changes": state.pending_changes,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        return self.protocol.encrypt_transport(raw, self.vault_key)

    def _decrypt_state(self, data: bytes) -> SyncState:
        """Decrypt and deserialize SyncState."""
        plaintext = self.protocol.decrypt_transport(data, self.vault_key)
        obj = json.loads(plaintext.decode("utf-8"))
        return SyncState(
            last_sync_time=obj.get("last_sync_time", {}),
            known_files=obj.get("known_files", {}),
            pending_changes=obj.get("pending_changes", []),
        )

    def _save_state(self) -> None:
        """Persist SyncState to ``vault/.sync_state.json``."""
        try:
            encrypted = self._encrypt_state(self._sync_state)
            tmp = self._state_path.with_suffix(".sync_state.json.tmp")
            tmp.write_bytes(encrypted)
            tmp.replace(self._state_path)
        except Exception:
            logger.exception("Failed to save sync state")

    def _load_state(self) -> None:
        """Load SyncState from ``vault/.sync_state.json``."""
        if not self._state_path.exists():
            return
        try:
            data = self._state_path.read_bytes()
            self._sync_state = self._decrypt_state(data)
        except Exception:
            logger.warning("Failed to load sync state, starting fresh")
            self._sync_state = SyncState()
