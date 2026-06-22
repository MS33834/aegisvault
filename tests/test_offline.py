"""Tests for offline/network isolation assertions."""

import sys
from pathlib import Path

import pytest

from aegisvault.security.offline import (
    _parse_proc_net_addr,
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
    assert not _is_local_address("8.8.8.8")
    assert not _is_local_address("2001:4860:4860::8888")


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux /proc parsing")
@pytest.mark.parametrize(
    ("remote_ip", "remote_port", "expected"),
    [
        ("0100007F", "1F90", False),  # 127.0.0.1:8080 loopback only
        ("0100000A", "01BB", True),  # 10.0.0.1:443 outbound
    ],
)
def test_has_outbound_connection_linux(
    tmp_path: Path,
    remote_ip: str,
    remote_port: str,
    expected: bool,
) -> None:
    """Outbound detection relies on mock /proc/<pid>/net/tcp data."""
    pid = 12345
    proc_root = tmp_path / "proc"
    net_dir = proc_root / str(pid) / "net"
    net_dir.mkdir(parents=True)
    header = (
        "  sl  local_address rem_address   st tx_queue rx_queue "
        "tr tm->when retrnsmt   uid  timeout inode\n"
    )
    net_dir.joinpath("tcp").write_text(
        header + f"   0: 0100007F:1F90 {remote_ip}:{remote_port} "
        "01 00000000:00000000 00:00000000 00000000  1000 0 12345 1\n"
    )

    assert has_outbound_connection(pid=pid, procfs_root=proc_root) is expected


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
