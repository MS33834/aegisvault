"""Network isolation verification helpers.

These helpers inspect a process's TCP connections to assert that the
AegisVault core process has no outbound (client-side) connections.
"""

import ipaddress
import re
import socket
import sys
from pathlib import Path


def _is_local_address(ip: str) -> bool:
    """Return True for loopback or unspecified addresses.

    Handles IPv4-mapped IPv6 (::ffff:127.0.0.1) and link-local zone indices.
    """
    if ip in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
        return True
    try:
        parsed = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return parsed.is_loopback or parsed.is_unspecified


def _parse_linux_tcp(
    pid: int,
    procfs_root: Path | None = None,
) -> list[tuple[str, int, str, int]]:
    """Parse /proc/<pid>/net/tcp and /tcp6 into connection tuples."""
    if procfs_root is None:
        procfs_root = Path("/proc")
    connections: list[tuple[str, int, str, int]] = []
    for proto in ("tcp", "tcp6"):
        path = procfs_root / str(pid) / "net" / proto
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local_hex = parts[1]
            remote_hex = parts[2]
            state = int(parts[3], 16)
            # TCP_ESTABLISHED = 1, TCP_CLOSE_WAIT = 8
            if state not in {1, 8}:
                continue
            local_ip, local_port = _parse_proc_net_addr(local_hex)
            remote_ip, remote_port = _parse_proc_net_addr(remote_hex)
            if (
                local_ip is None
                or local_port is None
                or remote_ip is None
                or remote_port is None
            ):
                continue
            connections.append((local_ip, local_port, remote_ip, remote_port))
    return connections


def _parse_proc_net_addr(addr: str) -> tuple[str, int] | tuple[None, None]:
    """Parse '0100007F:1234' style address into (ip, port).

    Linux /proc stores addresses as little-endian 32-bit words. IPv4 addresses
    are 8 hex digits (one word). IPv6 addresses are 32 hex digits split into
    four words; each word is byte-reversed independently.
    """
    match = re.match(r"^([0-9A-Fa-f]+):([0-9A-Fa-f]+)$", addr)
    if not match:
        return None, None
    ip_hex, port_hex = match.groups()
    port = int(port_hex, 16)
    try:
        ip_bytes = bytes.fromhex(ip_hex.zfill(8))
    except ValueError:
        return None, None
    if len(ip_bytes) == 4:
        ip = socket.inet_ntop(socket.AF_INET, ip_bytes[::-1])
        return ip, port

    # IPv6: four 32-bit little-endian words.
    try:
        raw = bytes.fromhex(ip_hex.zfill(32))
    except ValueError:
        return None, None
    if len(raw) != 16:
        return None, None
    words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
    ip_bytes = b"".join(words)
    ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
    return ip, port


def get_outbound_connections(
    pid: int | None = None,
    procfs_root: Path | None = None,
) -> list[tuple[str, int, str, int]]:
    """Return established outbound connections for a process.

    If pid is None, inspect the current process.
    On Windows this currently returns an empty list as a placeholder.
    """
    if pid is None:
        pid = sys.modules["os"].getpid()
    if sys.platform == "linux":
        return _parse_linux_tcp(pid, procfs_root=procfs_root)
    if sys.platform == "win32":
        return _parse_windows_tcp(pid)
    return []


def _parse_windows_tcp(pid: int) -> list[tuple[str, int, str, int]]:
    """Placeholder for Windows TCP connection enumeration."""
    # Phase 2: use GetExtendedTcpTable or netstat -ano filtered by PID.
    return []


def has_outbound_connection(
    pid: int | None = None,
    procfs_root: Path | None = None,
) -> bool:
    """Return True if the process has any outbound (non-loopback) connection."""
    for _local_ip, _local_port, remote_ip, _remote_port in get_outbound_connections(
        pid, procfs_root=procfs_root
    ):
        if not _is_local_address(remote_ip):
            return True
    return False
