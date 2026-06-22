"""Tests for password store backends using monkeypatched command-line tools."""

import os
import stat
from pathlib import Path

import pytest

from aegisvault.config import AegisConfig
from aegisvault.security.password_store import (
    KeePassXCStore,
    PassStore,
    PasswordStoreError,
    create_password_store,
)


@pytest.fixture
def fake_keepassxc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Install a fake keepassxc-cli executable on PATH."""
    script = tmp_path / "keepassxc-cli"
    script.write_text(
        """#!/usr/bin/env python3
import sys

args = sys.argv[1:]
db_index = next((i for i, a in enumerate(args) if not a.startswith("-")), None)
if db_index is None:
    sys.exit(1)
subcommand = args[db_index + 1] if len(args) > db_index + 1 else ""
entry = args[db_index + 2] if len(args) > db_index + 2 else ""

if subcommand == "show":
    print(f"Entry: {entry}")
    print("Username: user")
    print("Password: secret123")
elif subcommand == "edit":
    sys.exit(0)
else:
    sys.exit(1)
"""
    )
    script.chmod(stat.S_IRWXU)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    return script


@pytest.fixture
def fake_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Install a fake pass executable on PATH with a backing state file."""
    state = tmp_path / "pass_state.json"
    state.write_text("{}")
    script = tmp_path / "pass"
    script.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ["FAKE_PASS_STATE"])
args = sys.argv[1:]
subcommand = args[0]
entry = args[-1]

state = {}
if state_path.exists():
    state = json.loads(state_path.read_text())

if subcommand == "insert":
    password = sys.stdin.readline().rstrip("\\n")
    state[entry] = password
    state_path.write_text(json.dumps(state))
elif subcommand == "show":
    if entry not in state:
        print(f"Error: {entry} is not in the password store.", file=sys.stderr)
        sys.exit(1)
    print(state[entry])
else:
    print(f"Unknown command: {subcommand}", file=sys.stderr)
    sys.exit(1)
"""
    )
    script.chmod(stat.S_IRWXU)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("FAKE_PASS_STATE", str(state))
    return script


def test_keepassxc_store_roundtrip(fake_keepassxc: Path) -> None:
    """KeePassXC store can store and retrieve a password via the fake CLI."""
    store = KeePassXCStore(database=Path("/vault.kdbx"), password="dbpass")
    store.store("test/entry", "mypass")
    assert store.retrieve("test/entry") == "secret123"


def test_keepassxc_store_missing_binary(tmp_path: Path) -> None:
    """KeePassXC store raises when the binary is not on PATH."""
    with pytest.raises(PasswordStoreError, match="not found on PATH"):
        KeePassXCStore(database=tmp_path / "vault.kdbx", binary="missing-keepassxc-cli")


def test_pass_store_roundtrip(fake_pass: Path) -> None:
    """pass store can store and retrieve a password via the fake CLI."""
    store = PassStore()
    store.store("test/entry", "mypass")
    assert store.retrieve("test/entry") == "mypass"


def test_pass_store_missing_entry(fake_pass: Path) -> None:
    """Retrieving a missing pass entry raises PasswordStoreError."""
    store = PassStore()
    with pytest.raises(PasswordStoreError, match="pass show failed"):
        store.retrieve("missing/entry")


def test_pass_store_missing_binary(tmp_path: Path) -> None:
    """Pass store raises when the binary is not on PATH."""
    with pytest.raises(PasswordStoreError, match="not found on PATH"):
        PassStore(binary="missing-pass")


def test_create_password_store_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """Factory creates a PassStore for the 'pass' backend."""
    monkeypatch.setattr(
        "aegisvault.security.password_store.shutil.which", lambda _binary: "/fake/pass"
    )
    store = create_password_store("pass")
    assert isinstance(store, PassStore)


def test_create_password_store_keepassxc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Factory creates a KeePassXCStore for the 'keepassxc' backend."""
    monkeypatch.setattr(
        "aegisvault.security.password_store.shutil.which",
        lambda _binary: "/fake/keepassxc-cli",
    )
    db = tmp_path / "vault.kdbx"
    store = create_password_store("keepassxc", database=db, password="dbpass")
    assert isinstance(store, KeePassXCStore)
    assert store.database == db


def test_create_password_store_keepassxc_requires_database() -> None:
    """Factory requires a database path for KeePassXC."""
    with pytest.raises(PasswordStoreError, match="database path is required"):
        create_password_store("keepassxc")


def test_create_password_store_from_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Factory reads configuration from AegisConfig."""
    monkeypatch.setattr(
        "aegisvault.security.password_store.shutil.which",
        lambda _binary: "/fake/keepassxc-cli",
    )
    config = AegisConfig()
    config.security.password_store_database = tmp_path / "vault.kdbx"
    config.security.password_store_password = "dbpass"
    store = create_password_store("keepassxc", config=config)
    assert isinstance(store, KeePassXCStore)
    assert store.database == tmp_path / "vault.kdbx"


def test_create_password_store_unsupported() -> None:
    """Factory rejects unknown backend names."""
    with pytest.raises(PasswordStoreError, match="Unsupported password store"):
        create_password_store("unknown")
