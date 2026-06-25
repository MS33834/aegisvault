"""P2P LAN device discovery for AegisVault multi-device sync.

Provides two discovery backends:
- **mDNS/DNS-SD** via ``zeroconf`` (preferred when available).
- **UDP broadcast** as a fallback for environments where mDNS is
  unavailable (e.g. Docker containers, restrictive networks).

Both backends advertise the same service type ``_aegisvault._tcp.local.``
and share a common peer data format.
"""

import json
import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, ClassVar

logger = logging.getLogger(__name__)

# ── Peer representation ──────────────────────────────────────────────────────


@dataclass
class PeerInfo:
    """Information about a discovered peer device."""

    device_id: str
    device_name: str
    ip: str
    port: int
    last_seen: float = 0.0


# ── Constants ────────────────────────────────────────────────────────────────

SERVICE_TYPE = "_aegisvault._tcp.local."
BROADCAST_PORT = 9528
HEARTBEAT_INTERVAL = 30  # seconds
PEER_TIMEOUT = 120  # seconds – mark peer as offline after no heartbeat


# ── Base discovery interface ─────────────────────────────────────────────────


class DeviceDiscovery:
    """P2P LAN device discovery with mDNS and UDP-broadcast fallback.

    Parameters
    ----------
    device_name: Human-readable name for this device.
    port: TCP port on which the sync service runs.
    device_id: Unique identifier for this device.  If empty, a random
               UUID is generated.
    """

    SERVICE_TYPE: ClassVar[str] = SERVICE_TYPE
    BROADCAST_PORT: ClassVar[int] = BROADCAST_PORT

    def __init__(
        self,
        device_name: str,
        port: int = 9527,
        device_id: str = "",
    ) -> None:
        import uuid

        self.device_name = device_name
        self.port = port
        self.device_id = device_id or str(uuid.uuid4())
        self._peers: dict[str, PeerInfo] = {}
        self._lock = threading.Lock()
        self._running = False

        # Threads
        self._heartbeat_thread: threading.Thread | None = None
        self._mdns_thread: threading.Thread | None = None
        self._udp_listen_thread: threading.Thread | None = None

        # Backend state
        self._mdns_available = False
        self._zeroconf_service_info: Any = None  # zeroconf.ServiceInfo
        self._zeroconf_obj: Any = None  # zeroconf.Zeroconf

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Register the service and begin discovering peers."""
        if self._running:
            return
        self._running = True

        # Try mDNS first
        self._mdns_available = self._try_start_mdns()

        # Always start UDP fallback (works even when mDNS is active)
        self._start_udp()

        # Heartbeat for peer expiry
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="discv-heartbeat"
        )
        self._heartbeat_thread.start()

        logger.info(
            "DeviceDiscovery started (id=%s, mdns=%s, udp=%s)",
            self.device_id,
            self._mdns_available,
            True,
        )

    def stop(self) -> None:
        """Stop advertising and browsing."""
        self._running = False
        self._stop_mdns()
        # UDP listeners are daemon threads – they exit on `_running == False`

    def get_peers(self) -> list[dict[str, Any]]:
        """Return a list of currently visible peers.

        Each peer dict contains: ``device_id``, ``device_name``, ``ip``,
        ``port``, ``last_seen``.
        """
        with self._lock:
            return [
                {
                    "device_id": p.device_id,
                    "device_name": p.device_name,
                    "ip": p.ip,
                    "port": p.port,
                    "last_seen": p.last_seen,
                }
                for p in self._peers.values()
            ]

    # ------------------------------------------------------------------
    # mDNS backend (zeroconf)
    # ------------------------------------------------------------------

    def _try_start_mdns(self) -> bool:
        """Attempt to start mDNS/DNS-SD via zeroconf. Returns True on success."""
        try:
            import socket as _socket

            from zeroconf import ServiceInfo, Zeroconf
        except ImportError:
            logger.debug("zeroconf not available – using UDP fallback only")
            return False

        try:
            local_ip = self._get_local_ip()

            self._zeroconf_obj = Zeroconf()

            properties: dict[str, str] = {
                "device_id": self.device_id.encode("utf-8").hex(),
                "device_name": self.device_name.encode("utf-8").hex(),
                "protocol": "aegisvault-sync-v1",
            }

            self._zeroconf_service_info = ServiceInfo(
                type_=SERVICE_TYPE,
                name=f"{self.device_name}.{SERVICE_TYPE}",
                addresses=[_socket.inet_aton(local_ip)],
                port=self.port,
                properties=properties,
            )

            zc = self._zeroconf_obj
            info = self._zeroconf_service_info
            zc.register_service(info)

            # Start browser in a thread.
            def _browse() -> None:
                from zeroconf import ServiceBrowser

                class _Listener:
                    @staticmethod
                    def add_service(zc_obj: Any, svc_type: str, name: str) -> None:  # noqa: ARG004
                        pass

                    @staticmethod
                    def remove_service(zc_obj: Any, svc_type: str, name: str) -> None:  # noqa: ARG004
                        info_obj = zc_obj.get_service_info(svc_type, name)
                        if info_obj is None:
                            return
                        self._remove_peer_from_mdns(info_obj)

                    @staticmethod
                    def update_service(zc_obj: Any, svc_type: str, name: str) -> None:  # noqa: ARG004
                        info_obj = zc_obj.get_service_info(svc_type, name)
                        if info_obj is None:
                            return
                        self._add_peer_from_mdns(info_obj)

                self._zc_listener = _Listener()
                self._zc_browser = ServiceBrowser(zc, SERVICE_TYPE, self._zc_listener)

            self._mdns_thread = threading.Thread(target=_browse, daemon=True, name="discv-mdns")
            self._mdns_thread.start()

            logger.info("mDNS discovery started on %s:%d", local_ip, self.port)
            return True

        except Exception:
            logger.debug("Failed to start mDNS discovery", exc_info=True)
            self._stop_mdns()
            return False

    def _stop_mdns(self) -> None:
        """Unregister and close zeroconf resources."""
        try:
            if self._zeroconf_obj is not None:
                self._zeroconf_obj.unregister_service(self._zeroconf_service_info)
                self._zeroconf_obj.close()
        except Exception:
            logger.debug("Error during mDNS cleanup", exc_info=True)
        finally:
            self._zeroconf_obj = None
            self._zeroconf_service_info = None

    def _add_peer_from_mdns(self, info: Any) -> None:
        """Add or update a peer discovered via mDNS."""
        try:
            props = info.properties
            device_id_hex = props.get(b"device_id", b"").decode("utf-8")
            device_id = bytes.fromhex(device_id_hex).decode("utf-8")
            device_name_hex = props.get(b"device_name", b"unknown").decode("utf-8")
            device_name = bytes.fromhex(device_name_hex).decode("utf-8")

            addr = socket.inet_ntoa(info.addresses[0])
            port = info.port

            if device_id == self.device_id:
                return  # skip self

            with self._lock:
                self._peers[device_id] = PeerInfo(
                    device_id=device_id,
                    device_name=device_name,
                    ip=addr,
                    port=port,
                    last_seen=time.time(),
                )
        except Exception:
            logger.debug("Failed to parse mDNS peer info", exc_info=True)

    def _remove_peer_from_mdns(self, info: Any) -> None:
        """Remove a peer that left mDNS."""
        try:
            props = info.properties
            device_id_hex = props.get(b"device_id", b"").decode("utf-8")
            device_id = bytes.fromhex(device_id_hex).decode("utf-8")
            with self._lock:
                self._peers.pop(device_id, None)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # UDP broadcast fallback
    # ------------------------------------------------------------------

    def _start_udp(self) -> None:
        """Start UDP broadcast advertiser and listener threads."""

        broadcast_thread = threading.Thread(
            target=self._broadcast_presence,
            daemon=True,
            name="discv-udp-bcast",
        )
        broadcast_thread.start()

        self._udp_listen_thread = threading.Thread(
            target=self._listen_for_peers,
            daemon=True,
            name="discv-udp-listen",
        )
        self._udp_listen_thread.start()

    def _broadcast_presence(self) -> None:
        """Periodically broadcast our presence via UDP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        local_ip = self._get_local_ip()
        msg = json.dumps(
            {
                "device_id": self.device_id,
                "device_name": self.device_name,
                "ip": local_ip,
                "port": self.port,
            }
        ).encode("utf-8")

        while self._running:
            try:
                sock.sendto(msg, ("255.255.255.255", BROADCAST_PORT))
            except OSError:
                logger.debug("UDP broadcast send failed", exc_info=True)
            time.sleep(HEARTBEAT_INTERVAL)

        sock.close()

    def _listen_for_peers(self) -> None:
        """Listen for UDP broadcast announcements from other devices."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", BROADCAST_PORT))
        except OSError:
            logger.warning("Could not bind UDP listen port %d", BROADCAST_PORT)
            sock.close()
            return

        sock.settimeout(1.0)

        while self._running:
            try:
                data, addr = sock.recvfrom(4096)
                self._handle_udp_message(data, addr[0])
            except TimeoutError:
                continue
            except OSError:
                if self._running:
                    logger.debug("UDP listen error", exc_info=True)
                break

        sock.close()

    def _handle_udp_message(self, data: bytes, source_ip: str) -> None:
        """Parse and store a UDP peer announcement."""
        try:
            obj = json.loads(data.decode("utf-8"))
            device_id = obj["device_id"]
            if device_id == self.device_id:
                return  # skip self
            with self._lock:
                self._peers[device_id] = PeerInfo(
                    device_id=device_id,
                    device_name=obj["device_name"],
                    ip=obj.get("ip", source_ip),
                    port=obj["port"],
                    last_seen=time.time(),
                )
        except (json.JSONDecodeError, KeyError):
            logger.debug("Malformed UDP discovery message from %s", source_ip)

    # ------------------------------------------------------------------
    # Heartbeat / peer expiry
    # ------------------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        """Periodically prune peers that haven't been seen recently."""
        while self._running:
            time.sleep(HEARTBEAT_INTERVAL)
            now = time.time()
            with self._lock:
                expired = [
                    did for did, p in self._peers.items() if now - p.last_seen > PEER_TIMEOUT
                ]
                for did in expired:
                    logger.info("Peer %s expired (no heartbeat for %.0fs)", did, PEER_TIMEOUT)
                    del self._peers[did]

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _get_local_ip() -> str:
        """Best-effort determination of the local network IP."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"


# ── UDP-only discovery (for explicit fallback) ───────────────────────────────


class UdpDiscovery(DeviceDiscovery):
    """UDP broadcast discovery only – skips mDNS entirely.

    Useful in environments where mDNS is known to be unavailable and
    you want to avoid the import attempt overhead.
    """

    def _try_start_mdns(self) -> bool:
        """UDP-only: never try mDNS."""
        return False
