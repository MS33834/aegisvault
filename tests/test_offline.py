# mypy: ignore-errors
"""Tests for offline/network isolation assertions."""

import ctypes
import socket
import struct
import sys
import types
from collections.abc import Callable
from pathlib import Path

import pytest

from aegisvault.security import offline as offline_module
from aegisvault.security.offline import (
    _is_local_address,
    _parse_linux_tcp,
    _parse_proc_net_addr,
    _parse_windows_tcp,
    get_outbound_connections,
    has_outbound_connection,
)

_AF_INET = 2
_AF_INET6 = 23


def _ipv4_dword(ip: str) -> int:
    """Little-endian DWORD representation used by MIB_TCPROW_OWNER_PID."""
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def _build_v4_table(
    rows: list[tuple[int, str, int, str, int, int]],
) -> bytes:
    """Build raw bytes for a MIB_TCPTABLE_OWNER_PID structure."""
    data = struct.pack("<I", len(rows))
    for state, local_ip, local_port, remote_ip, remote_port, pid in rows:
        data += struct.pack(
            "<IIIIII",
            state,
            _ipv4_dword(local_ip),
            socket.htons(local_port),
            _ipv4_dword(remote_ip),
            socket.htons(remote_port),
            pid,
        )
    return data


def _build_v6_table(
    rows: list[tuple[int, str, int, str, int, int]],
) -> bytes:
    """Build raw bytes for a MIB_TCP6TABLE_OWNER_PID structure."""
    data = struct.pack("<I", len(rows))
    for state, local_ip, local_port, remote_ip, remote_port, pid in rows:
        data += socket.inet_pton(socket.AF_INET6, local_ip)
        data += struct.pack("<I", 0)  # LocalScopeId
        data += struct.pack("<I", socket.htons(local_port))
        data += socket.inet_pton(socket.AF_INET6, remote_ip)
        data += struct.pack("<I", 0)  # RemoteScopeId
        data += struct.pack("<I", socket.htons(remote_port))
        data += struct.pack("<II", state, pid)
    return data


def _make_fake_get_extended_tcp_table(
    table_data: dict[int, bytes],
) -> Callable[..., int]:
    """Return a ctypes-compatible GetExtendedTcpTable mock."""
    dword = ctypes.c_uint32
    ulong = ctypes.c_uint32
    lpvoid = ctypes.c_void_p

    def _impl(
        table: object,
        size_ptr: ctypes.POINTER(ctypes.c_uint32),
        _order: int,
        af: int,
        _table_class: int,
        _reserved: int,
    ) -> int:
        if size_ptr.contents.value == 0:
            size_ptr.contents.value = max(4, len(table_data.get(af, b"")))
            return 122
        data = table_data.get(af, b"")
        if data:
            ctypes.memmove(table, data, len(data))
        return 0

    return ctypes.CFUNCTYPE(dword, lpvoid, ctypes.POINTER(dword), dword, ulong, dword, ulong)(_impl)


def _patch_windows_tcp_api(
    monkeypatch: pytest.MonkeyPatch,
    table_data: dict[int, bytes],
) -> None:
    """Replace ctypes/windll in offline.py so _parse_windows_tcp runs on Linux."""
    fake_ctypes = types.ModuleType("ctypes")
    for name in dir(ctypes):
        if not name.startswith("__"):
            setattr(fake_ctypes, name, getattr(ctypes, name))

    fake_wintypes = types.ModuleType("wintypes")
    fake_wintypes.DWORD = ctypes.c_uint32
    fake_wintypes.ULONG = ctypes.c_uint32
    fake_wintypes.LPVOID = ctypes.c_void_p
    fake_wintypes.BYTE = ctypes.c_ubyte
    fake_ctypes.wintypes = fake_wintypes

    windll = types.SimpleNamespace()
    windll.iphlpapi = types.SimpleNamespace()
    windll.iphlpapi.GetExtendedTcpTable = _make_fake_get_extended_tcp_table(table_data)
    fake_ctypes.windll = windll

    monkeypatch.setattr(offline_module, "ctypes", fake_ctypes)
    monkeypatch.setattr(offline_module, "sys", types.SimpleNamespace(platform="win32"))


@pytest.mark.parametrize(
    ("addr", "expected_ip", "expected_port"),
    [
        ("0100007F:1F90", "127.0.0.1", 8080),
        ("00000000:0000", "0.0.0.0", 0),
        # IPv6 loopback ::1 stored as four little-endian 32-bit words.
        ("00000000000000000000000001000000:1F90", "::1", 8080),
        # IPv6 unspecified ::
        ("00000000000000000000000000000000:0000", "::", 0),
        # IPv4-mapped IPv6 loopback ::ffff:127.0.0.1
        (
            "0000000000000000FFFF00000100007F:1F90",
            "::ffff:127.0.0.1",
            8080,
        ),
    ],
)
def test_parse_proc_net_addr(addr: str, expected_ip: str, expected_port: int) -> None:
    """Parsing /proc/net/tcp style addresses works."""
    ip, port = _parse_proc_net_addr(addr)
    assert ip == expected_ip
    assert port == expected_port


def test_is_local_address_handles_ipv6_variants() -> None:
    """_is_local_address accepts loopback and unspecified addresses."""
    from aegisvault.security.offline import _is_local_address

    assert _is_local_address("127.0.0.1")
    assert _is_local_address("::1")
    assert _is_local_address("::")
    assert _is_local_address("::ffff:127.0.0.1")
    assert _is_local_address("::1%lo0")
    assert _is_local_address("::%lo0")
    assert not _is_local_address("8.8.8.8")
    assert not _is_local_address("2001:4860:4860::8888")


def test_is_local_address_rejects_invalid_ip() -> None:
    """_is_local_address returns False for strings that are not valid IPs."""
    assert not _is_local_address("not-an-ip")
    assert not _is_local_address("127.0.0.1.1")


@pytest.mark.parametrize(
    "addr",
    [
        "not-an-address",
        "0100007F",  # missing port
        "0100007F:",  # empty port
        "GGGGGGGG:1F90",  # non-hex digits
        "123456789:1F90",  # odd IPv4 hex length -> ValueError
        "000000000000000000000000000000001:1F90",  # odd IPv6 hex length -> ValueError
        "0000000000000000000000000000000000:1F90",  # IPv6 raw length != 16
    ],
)
def test_parse_proc_net_addr_malformed(addr: str) -> None:
    """Malformed /proc/net/tcp addresses return (None, None)."""
    assert _parse_proc_net_addr(addr) == (None, None)


def test_parse_proc_net_addr_ipv6_fromhex_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ValueError while decoding IPv6 hex returns (None, None)."""

    class FakeBytes:
        calls = 0

        @staticmethod
        def fromhex(value: str) -> bytes:
            FakeBytes.calls += 1
            if FakeBytes.calls == 1:
                return b"\x00" * 16
            raise ValueError("bad hex")

    monkeypatch.setitem(offline_module.__dict__, "bytes", FakeBytes)
    assert _parse_proc_net_addr("00000000000000000000000000000000:1F90") == (None, None)


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux /proc parsing")
def test_parse_linux_tcp_skips_malformed_lines(tmp_path: Path) -> None:
    """Malformed rows, non-established states and bad addresses are skipped."""
    pid = 11111
    net_dir = tmp_path / str(pid) / "net"
    net_dir.mkdir(parents=True)
    header = (
        "  sl  local_address rem_address   st tx_queue rx_queue "
        "tr tm->when retrnsmt   uid  timeout inode\n"
    )
    lines = [
        "   0: 0100007F:1F90 0100007F:1F90 01 "
        "00000000:00000000 00:00000000 00000000  1000 0 12345 1\n",
        "   1: 0100007F:1F90\n",
        "   2: 0100007F:1F90 0100000A:01BB 02 "
        "00000000:00000000 00:00000000 00000000  1000 0 12346 1\n",
        "   3: 0100007F:1F90 BADADDR:01BB 01 "
        "00000000:00000000 00:00000000 00000000  1000 0 12347 1\n",
    ]
    net_dir.joinpath("tcp").write_text(header + "".join(lines))

    conns = _parse_linux_tcp(pid, procfs_root=tmp_path)
    assert conns == [("127.0.0.1", 8080, "127.0.0.1", 8080)]


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux /proc")
def test_get_outbound_connections_uses_current_process() -> None:
    """Default pid and procfs_root resolve to the current process."""
    conns = get_outbound_connections()
    assert isinstance(conns, list)
    for local_ip, local_port, remote_ip, remote_port in conns:
        assert isinstance(local_ip, str) and local_ip
        assert isinstance(local_port, int)
        assert isinstance(remote_ip, str) and remote_ip
        assert isinstance(remote_port, int)


def test_get_outbound_connections_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Windows branch delegates to _parse_windows_tcp."""
    monkeypatch.setattr(sys, "platform", "win32")
    fake = [("127.0.0.1", 1111, "8.8.8.8", 443)]
    monkeypatch.setattr(offline_module, "_parse_windows_tcp", lambda pid: fake)

    assert get_outbound_connections(pid=12345) == fake
    assert has_outbound_connection(pid=12345) is True


def test_get_outbound_connections_unsupported_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unsupported platforms fall back to an empty connection list."""
    monkeypatch.setattr(sys, "platform", "sunos")
    assert get_outbound_connections(pid=12345) == []
    assert has_outbound_connection(pid=12345) is False


def test_parse_windows_tcp_returns_empty_on_non_windows() -> None:
    """On non-Windows platforms the helper returns an empty list gracefully."""
    assert _parse_windows_tcp(12345) == []


def test_parse_windows_tcp_ipv4_on_linux_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux can exercise the IPv4 Windows code path with a mocked API."""
    table_data = {
        _AF_INET: _build_v4_table([(1, "127.0.0.1", 12345, "8.8.8.8", 443, 12345)]),
    }
    _patch_windows_tcp_api(monkeypatch, table_data)

    assert _parse_windows_tcp(12345) == [("127.0.0.1", 12345, "8.8.8.8", 443)]


def test_parse_windows_tcp_ipv6_on_linux_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux can exercise the IPv6 Windows code path with a mocked API."""
    table_data = {
        _AF_INET6: _build_v6_table([(1, "::1", 12345, "2001:4860:4860::8888", 443, 12345)]),
    }
    _patch_windows_tcp_api(monkeypatch, table_data)

    assert _parse_windows_tcp(12345) == [("::1", 12345, "2001:4860:4860::8888", 443)]


def test_parse_windows_tcp_filters_by_pid_and_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only rows matching the target PID and active states are returned."""
    table_data = {
        _AF_INET: _build_v4_table(
            [
                (1, "127.0.0.1", 1111, "8.8.8.8", 443, 12345),  # match
                (1, "127.0.0.1", 2222, "1.1.1.1", 443, 99999),  # wrong pid
                (2, "127.0.0.1", 3333, "9.9.9.9", 443, 12345),  # wrong state
                (8, "127.0.0.1", 4444, "1.0.0.1", 443, 12345),  # match (CLOSE_WAIT)
            ]
        ),
    }
    _patch_windows_tcp_api(monkeypatch, table_data)

    conns = _parse_windows_tcp(12345)
    assert conns == [
        ("127.0.0.1", 1111, "8.8.8.8", 443),
        ("127.0.0.1", 4444, "1.0.0.1", 443),
    ]


def test_parse_windows_tcp_ignores_empty_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty table with zero entries returns an empty list."""
    table_data = {_AF_INET: struct.pack("<I", 0)}
    _patch_windows_tcp_api(monkeypatch, table_data)

    assert _parse_windows_tcp(12345) == []


def test_parse_windows_tcp_graceful_on_api_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-success second GetExtendedTcpTable call returns [] instead of crashing."""
    fake_ctypes = types.ModuleType("ctypes")
    for name in dir(ctypes):
        if not name.startswith("__"):
            setattr(fake_ctypes, name, getattr(ctypes, name))

    fake_wintypes = types.ModuleType("wintypes")
    fake_wintypes.DWORD = ctypes.c_uint32
    fake_wintypes.ULONG = ctypes.c_uint32
    fake_wintypes.LPVOID = ctypes.c_void_p
    fake_wintypes.BYTE = ctypes.c_ubyte
    fake_ctypes.wintypes = fake_wintypes

    def _fail_impl(
        _table: object,
        size_ptr: ctypes.POINTER(ctypes.c_uint32),
        _order: int,
        _af: int,
        _table_class: int,
        _reserved: int,
    ) -> int:
        if size_ptr.contents.value == 0:
            size_ptr.contents.value = 1024
            return 122
        return 1  # arbitrary non-zero failure

    windll = types.SimpleNamespace()
    windll.iphlpapi = types.SimpleNamespace()
    windll.iphlpapi.GetExtendedTcpTable = ctypes.CFUNCTYPE(
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
    )(_fail_impl)
    fake_ctypes.windll = windll

    monkeypatch.setattr(offline_module, "ctypes", fake_ctypes)
    monkeypatch.setattr(offline_module, "sys", types.SimpleNamespace(platform="win32"))

    assert _parse_windows_tcp(12345) == []


@pytest.mark.skipif(sys.platform != "win32", reason="Windows integration branch")
def test_has_outbound_connection_windows() -> None:
    """Windows branch returns False when no outbound connection is present."""
    assert not has_outbound_connection(pid=12345)


@pytest.mark.skipif(
    sys.platform in {"linux", "win32"},
    reason="Unsupported platform branch",
)
def test_has_outbound_connection_unsupported() -> None:
    """Unsupported platforms return False."""
    assert not has_outbound_connection(pid=12345)
