"""Tests for offline/network isolation assertions."""

import sys
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


def test_parse_windows_tcp_returns_empty() -> None:
    """The Windows helper is currently a placeholder."""
    assert _parse_windows_tcp(12345) == []


@pytest.mark.skipif(sys.platform != "win32", reason="Windows placeholder branch")
def test_has_outbound_connection_windows() -> None:
    """Windows branch returns False until implemented."""
    assert not has_outbound_connection(pid=12345)


@pytest.mark.skipif(
    sys.platform in {"linux", "win32"},
    reason="Unsupported platform branch",
)
def test_has_outbound_connection_unsupported() -> None:
    """Unsupported platforms return False."""
    assert not has_outbound_connection(pid=12345)
