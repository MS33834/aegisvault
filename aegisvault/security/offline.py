"""Network isolation verification helpers.

These helpers inspect a process's TCP connections to assert that the
AegisVault core process has no outbound (client-side) connections.
"""

import ctypes
import ipaddress
import os
import re
import socket
import struct
import sys
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar


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
            if local_ip is None or local_port is None or remote_ip is None or remote_port is None:
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
    On Linux, parses /proc/<pid>/net/tcp{,6}.
    On Windows, uses GetExtendedTcpTable via ctypes.
    On other platforms, returns an empty list.
    """
    if pid is None:
        pid = os.getpid()
    if sys.platform == "linux":
        return _parse_linux_tcp(pid, procfs_root=procfs_root)
    if sys.platform == "win32":
        return _parse_windows_tcp(pid)
    return []


def _parse_windows_tcp(pid: int) -> list[tuple[str, int, str, int]]:
    """Enumerate TCP connections for *pid* using GetExtendedTcpTable.

    Returns a list of (local_ip, local_port, remote_ip, remote_port) tuples for
    established (state 1) and close-wait (state 8) connections. IPv4 and IPv6
    tables are both inspected.

    On non-Windows platforms this function returns an empty list so callers can
    run in mock/stub mode on Linux.
    """
    if sys.platform != "win32":
        return []

    from ctypes import wintypes

    _tcp_table_owner_pid_all = 5
    _af_inet = 2
    _af_inet6 = 23
    _error_insufficient_buffer = 122
    _error_success = 0

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):  # noqa: N801
        _fields_: ClassVar[list[tuple[str, type]]] = [
            ("dwState", wintypes.DWORD),
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwRemoteAddr", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):  # noqa: N801
        _fields_: ClassVar[list[tuple[str, type]]] = [
            ("dwNumEntries", wintypes.DWORD),
            ("table", MIB_TCPROW_OWNER_PID * 1),
        ]

    class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):  # noqa: N801
        _fields_: ClassVar[list[tuple[str, type]]] = [
            ("ucLocalAddr", wintypes.BYTE * 16),
            ("dwLocalScopeId", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("ucRemoteAddr", wintypes.BYTE * 16),
            ("dwRemoteScopeId", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
            ("dwState", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    class MIB_TCP6TABLE_OWNER_PID(ctypes.Structure):  # noqa: N801
        _fields_: ClassVar[list[tuple[str, type]]] = [
            ("dwNumEntries", wintypes.DWORD),
            ("table", MIB_TCP6ROW_OWNER_PID * 1),
        ]

    get_extended_tcp_table = ctypes.windll.iphlpapi.GetExtendedTcpTable
    get_extended_tcp_table.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
        wintypes.ULONG,
        wintypes.DWORD,
        wintypes.ULONG,
    ]
    get_extended_tcp_table.restype = wintypes.DWORD

    def _enum(
        af: int,
        row_size: int,
        parse: Callable[[bytes, int], tuple[int, int, str, int, str, int]],
    ) -> list[tuple[str, int, str, int]]:
        size = wintypes.DWORD(0)
        res = get_extended_tcp_table(None, ctypes.byref(size), 1, af, _tcp_table_owner_pid_all, 0)
        if res != _error_insufficient_buffer:
            return []
        buffer = ctypes.create_string_buffer(size.value)
        res = get_extended_tcp_table(buffer, ctypes.byref(size), 1, af, _tcp_table_owner_pid_all, 0)
        if res != _error_success:
            return []
        raw = bytes(buffer)
        num_entries = struct.unpack_from("<I", raw, 0)[0]
        results: list[tuple[str, int, str, int]] = []
        offset = 4
        for _ in range(num_entries):
            state, owning_pid, local_ip, local_port, remote_ip, remote_port = parse(raw, offset)
            if owning_pid == pid and state in {1, 8}:
                results.append((local_ip, local_port, remote_ip, remote_port))
            offset += row_size
        return results

    def _parse_v4(raw: bytes, offset: int) -> tuple[int, int, str, int, str, int]:
        state, laddr, lport, raddr, rport, owning_pid = struct.unpack_from("<IIIIII", raw, offset)
        local_ip = socket.inet_ntoa(struct.pack("<I", laddr))
        remote_ip = socket.inet_ntoa(struct.pack("<I", raddr))
        return (
            state,
            owning_pid,
            local_ip,
            socket.ntohs(lport),
            remote_ip,
            socket.ntohs(rport),
        )

    def _parse_v6(raw: bytes, offset: int) -> tuple[int, int, str, int, str, int]:
        laddr = raw[offset : offset + 16]
        _lscope, lport = struct.unpack_from("<II", raw, offset + 16)
        raddr = raw[offset + 24 : offset + 40]
        _rscope, rport, state, owning_pid = struct.unpack_from("<IIII", raw, offset + 40)
        local_ip = socket.inet_ntop(socket.AF_INET6, laddr)
        remote_ip = socket.inet_ntop(socket.AF_INET6, raddr)
        return (
            state,
            owning_pid,
            local_ip,
            socket.ntohs(lport),
            remote_ip,
            socket.ntohs(rport),
        )

    connections: list[tuple[str, int, str, int]] = []
    connections.extend(_enum(_af_inet, 24, _parse_v4))
    connections.extend(_enum(_af_inet6, 56, _parse_v6))
    return connections


def has_outbound_connection(
    pid: int | None = None,
    procfs_root: Path | None = None,
    *,
    exclude_well_known_ports: bool = True,
) -> bool:
    """Return True if the process has active outbound (client) connections.

    Connections whose local port is a well-known port (<= 1024) are treated as
    server-side listeners and ignored when *exclude_well_known_ports* is True.
    """
    for _local_ip, local_port, remote_ip, _remote_port in get_outbound_connections(
        pid, procfs_root=procfs_root
    ):
        if not _is_local_address(remote_ip):
            if exclude_well_known_ports and local_port <= 1024:
                continue
            return True
    return False


class NetworkIsolationError(RuntimeError):
    """Raised when the process is expected to be offline but has outbound connections."""


def assert_no_outbound_connection(
    pid: int | None = None,
    procfs_root: Path | None = None,
    *,
    exclude_well_known_ports: bool = True,
) -> None:
    """Raise *NetworkIsolationError* if the process has outbound connections."""
    if has_outbound_connection(
        pid,
        procfs_root=procfs_root,
        exclude_well_known_ports=exclude_well_known_ports,
    ):
        raise NetworkIsolationError(
            "Process has active outbound connections but network isolation was required."
        )
