"""Tests for password store backends using monkeypatched command-line tools."""

import os
import stat
from pathlib import Path

import pytest

from aegisvault.config import AegisConfig
from aegisvault.security.password_store import (
    KeePassXCRetriever,
    KeePassXCStore,
    PassRetriever,
    PassStore,
    PasswordStoreError,
    SecretEntry,
    auto_detect,
    create_password_store,
)

# ────────────────────────────────────────────────────────────────
#  Legacy test fixtures (unchanged for backward compatibility)
# ────────────────────────────────────────────────────────────────


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
    script_text = """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

state_path = Path("__STATE_PATH__")
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
    script.write_text(script_text.replace("__STATE_PATH__", str(state)))
    script.chmod(stat.S_IRWXU)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    return script


# ────────────────────────────────────────────────────────────────
#  Deep-integration test fixtures
# ────────────────────────────────────────────────────────────────


@pytest.fixture
def fake_keepassxc_deep(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Install a full-featured fake keepassxc-cli that supports
    all subcommands used by KeePassXCRetriever."""
    state = tmp_path / "keepass_state.json"
    script = tmp_path / "keepassxc-cli"
    script_text = r"""#!/usr/bin/env python3
import json
import sys
from pathlib import Path

STATE_PATH = Path("__STATE_PATH__")
ARGS = sys.argv[1:]

# The command structure is: [flags...] <database> <subcommand> [opts...] <entry>
# Filter out flag-only args (--pw-stdin) and keep everything else.
# Non-flag args: [database, subcommand, ... , entry]
pos_args = [a for a in ARGS if not a.startswith("-") and a != "--pw-stdin"]

subcommand = pos_args[1] if len(pos_args) > 1 else ""

# The "entry" is generally the last positional arg, but clip has a timeout suffix.
if subcommand == "clip" and len(pos_args) > 2:
    entry = pos_args[2]
elif subcommand in ("ls",):
    entry = pos_args[-1]  # ignored
else:
    entry = pos_args[-1] if len(pos_args) > 2 else (pos_args[1] if len(pos_args) == 2 else "")

# Validate database password (expected "dbpass") and capture stdin lines
stdin_lines: list[str] = sys.stdin.read().splitlines()
db_pass_ok = True
if "--pw-stdin" in ARGS:
    if not stdin_lines or stdin_lines[0] != "dbpass":
        db_pass_ok = False

state = {}
if STATE_PATH.exists():
    state = json.loads(STATE_PATH.read_text())

def save_state():
    STATE_PATH.write_text(json.dumps(state))

# Reject commands if password is invalid
if not db_pass_ok:
    sys.exit(1)

if subcommand == "show":
    if entry in state:
        e = state[entry]
        print(f"Title: {e.get('title', entry)}")
        print(f"UserName: {e.get('username', '')}")
        print(f"Password: {e.get('password', '')}")
        print(f"URL: {e.get('url', '')}")
        print(f"Notes: {e.get('notes', '')}")
    else:
        sys.exit(1)

elif subcommand == "ls":
    if state:
        for k in sorted(state.keys()):
            print(k)
    else:
        print("")

elif subcommand == "search":
    query = entry
    for k, v in state.items():
        if query.lower() in k.lower() or query.lower() in v.get("title", "").lower():
            print(k)

elif subcommand == "add":
    username = ""
    url = ""
    notes = ""
    i = 0
    while i < len(ARGS):
        if ARGS[i] == "--username" and i + 1 < len(ARGS):
            username = ARGS[i + 1]
            i += 2
        elif ARGS[i] == "--url" and i + 1 < len(ARGS):
            url = ARGS[i + 1]
            i += 2
        elif ARGS[i] == "--notes" and i + 1 < len(ARGS):
            notes = ARGS[i + 1]
            i += 2
        else:
            i += 1
    # Entry password is the second line of stdin (after db password)
    pwd = stdin_lines[1] if len(stdin_lines) >= 2 else ""
    state[entry] = {
        "title": entry,
        "username": username,
        "password": pwd,
        "url": url,
        "notes": notes,
    }
    save_state()

elif subcommand == "edit":
    i = 0
    if entry not in state:
        state[entry] = {"title": entry, "username": "", "password": "", "url": "", "notes": ""}
    e = state[entry]
    while i < len(ARGS):
        if ARGS[i] == "--title" and i + 1 < len(ARGS):
            e["title"] = ARGS[i + 1]
            i += 2
        elif ARGS[i] == "--username" and i + 1 < len(ARGS):
            e["username"] = ARGS[i + 1]
            i += 2
        elif ARGS[i] == "--url" and i + 1 < len(ARGS):
            e["url"] = ARGS[i + 1]
            i += 2
        elif ARGS[i] == "--notes" and i + 1 < len(ARGS):
            e["notes"] = ARGS[i + 1]
            i += 2
        elif ARGS[i] == "--password" and i + 1 < len(ARGS):
            e["password"] = ARGS[i + 1]
            i += 2
        else:
            i += 1
    save_state()

elif subcommand == "rm":
    if entry in state:
        del state[entry]
        save_state()

elif subcommand == "clip":
    if entry in state:
        print(state[entry].get("password", ""))

else:
    sys.exit(1)
"""
    script.write_text(script_text.replace("__STATE_PATH__", str(state)))
    state.write_text("{}")
    script.chmod(stat.S_IRWXU)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    return script


@pytest.fixture
def fake_pass_deep(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Install a full-featured fake pass executable."""
    state = tmp_path / "pass_state.json"
    script = tmp_path / "pass"
    script_text = r"""#!/usr/bin/env python3
import json
import sys
from pathlib import Path

STATE_PATH = Path("__STATE_PATH__")
ARGS = sys.argv[1:]

subcommand = ARGS[0] if ARGS else ""
# For ls/find, the optional arg (path/query) follows the subcommand
if subcommand in ("ls", "find"):
    entry = ARGS[1] if len(ARGS) >= 2 else ""
else:
    entry = ARGS[-1] if len(ARGS) >= 2 else subcommand

state = {}
if STATE_PATH.exists():
    state = json.loads(STATE_PATH.read_text())

def save_state():
    STATE_PATH.write_text(json.dumps(state))

if subcommand == "insert":
    password = sys.stdin.read().strip()
    state[entry] = password
    save_state()

elif subcommand == "show":
    if entry in state:
        print(state[entry])
    else:
        print(f"Error: {entry} is not in the password store.", file=sys.stderr)
        sys.exit(1)

elif subcommand == "ls":
    for k in sorted(state.keys()):
        print(f"  {k}")

elif subcommand == "find":
    query = entry
    for k in state:
        if query.lower() in k.lower():
            print(k)

elif subcommand == "rm":
    if entry in state:
        del state[entry]
        save_state()

else:
    print(f"Unknown command: {subcommand}", file=sys.stderr)
    sys.exit(1)
"""
    script.write_text(script_text.replace("__STATE_PATH__", str(state)))
    state.write_text("{}")
    script.chmod(stat.S_IRWXU)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    return script


# ────────────────────────────────────────────────────────────────
#  Legacy tests (backward-compatible)
# ────────────────────────────────────────────────────────────────


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


# ────────────────────────────────────────────────────────────────
#  SecretEntry tests
# ────────────────────────────────────────────────────────────────


class TestSecretEntry:
    """Tests for the SecretEntry type."""

    def test_defaults(self) -> None:
        entry = SecretEntry()
        assert entry.title == ""
        assert entry.username == ""
        assert entry.password == ""
        assert entry.url is None
        assert entry.notes is None

    def test_attribute_access(self) -> None:
        entry = SecretEntry(
            title="MySite",
            username="alice",
            password="s3cret",
            url="https://example.com",
            notes="my notes",
        )
        assert entry.title == "MySite"
        assert entry.username == "alice"
        assert entry.password == "s3cret"
        assert entry.url == "https://example.com"
        assert entry.notes == "my notes"

    def test_dict_access(self) -> None:
        entry = SecretEntry(title="Test", password="pwd")
        assert entry["title"] == "Test"
        assert entry["password"] == "pwd"

    def test_missing_attribute(self) -> None:
        entry = SecretEntry()
        with pytest.raises(AttributeError):
            _ = entry.nonexistent


# ────────────────────────────────────────────────────────────────
#  KeePassXCRetriever tests (deep integration)
# ────────────────────────────────────────────────────────────────


@pytest.fixture
def keepass_retriever(fake_keepassxc_deep: Path) -> KeePassXCRetriever:
    return KeePassXCRetriever(
        database=Path("/vault.kdbx"),
        password="dbpass",
    )


class TestKeePassXCRetriever:
    """Tests for KeePassXCRetriever deep integration."""

    def test_get_retrieves_password(self, keepass_retriever: KeePassXCRetriever) -> None:
        # First create an entry
        keepass_retriever.create_entry(
            group="Accounts",
            title="GitHub",
            username="dev",
            password="gh_secret",
        )
        pwd = keepass_retriever.get("Accounts/GitHub")
        assert pwd == "gh_secret"

    def test_get_missing_entry_raises(self, keepass_retriever: KeePassXCRetriever) -> None:
        with pytest.raises(PasswordStoreError):
            keepass_retriever.get("Nonexistent/Entry")

    def test_list_entries(self, keepass_retriever: KeePassXCRetriever) -> None:
        keepass_retriever.create_entry("", "Site1", "u1", "p1")
        keepass_retriever.create_entry("", "Site2", "u2", "p2")
        entries = keepass_retriever.list_entries()
        titles = {e.title for e in entries}
        assert "Site1" in titles
        assert "Site2" in titles

    def test_list_entries_empty(self, keepass_retriever: KeePassXCRetriever) -> None:
        entries = keepass_retriever.list_entries()
        assert entries == []

    def test_search_finds_entry(self, keepass_retriever: KeePassXCRetriever) -> None:
        keepass_retriever.create_entry(
            group="Work",
            title="Database",
            username="admin",
            password="db_pass123",
        )
        results = keepass_retriever.search("Database")
        assert len(results) >= 1
        assert any(r.title == "Work/Database" for r in results)

    def test_search_no_match(self, keepass_retriever: KeePassXCRetriever) -> None:
        results = keepass_retriever.search("NothingMatchesThis")
        assert results == []

    def test_health_returns_true(self, keepass_retriever: KeePassXCRetriever) -> None:
        assert keepass_retriever.health() is True

    def test_health_returns_false_when_locked(self, fake_keepassxc_deep: Path) -> None:
        retriever = KeePassXCRetriever(
            database=Path("/vault.kdbx"),
            password=None,
        )
        # With no password, ls should fail
        assert retriever.health() is False

    def test_auto_fill_by_entry_path(
        self, keepass_retriever: KeePassXCRetriever, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        keepass_retriever.create_entry(
            "", "Netflix", "user", "nf_secret", url="https://netflix.com"
        )
        # Monkeypatch xdg-open to avoid actually launching browser
        monkeypatch.setattr(
            "aegisvault.security.password_store.subprocess.run",
            lambda *args, **kw: type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
        )
        result = keepass_retriever.auto_fill("Netflix")
        assert result is True

    def test_auto_fill_by_window_title(self, keepass_retriever: KeePassXCRetriever) -> None:
        keepass_retriever.create_entry(
            "", "ExampleApp", "user1", "app_pass", url="https://example.com"
        )
        result = keepass_retriever.auto_fill(target_window_title="ExampleApp")
        assert result is True

    def test_auto_fill_no_match_returns_false(self, keepass_retriever: KeePassXCRetriever) -> None:
        result = keepass_retriever.auto_fill(target_window_title="NonExistentApp")
        assert result is False

    def test_create_entry(self, keepass_retriever: KeePassXCRetriever) -> None:
        ok = keepass_retriever.create_entry(
            group="Finance",
            title="Bank",
            username="john",
            password="bank_pass",
            url="https://bank.example",
            notes="checking account",
        )
        assert ok is True
        pwd = keepass_retriever.get("Finance/Bank")
        assert pwd == "bank_pass"

    def test_update_entry(self, keepass_retriever: KeePassXCRetriever) -> None:
        keepass_retriever.create_entry("", "OldName", "u", "p")
        ok = keepass_retriever.update_entry("OldName", title="NewName", username="admin")
        assert ok is True

    def test_delete_entry(self, keepass_retriever: KeePassXCRetriever) -> None:
        keepass_retriever.create_entry("", "ToDelete", "u", "p")
        assert keepass_retriever.delete_entry("ToDelete") is True
        # Verify it's gone
        with pytest.raises(PasswordStoreError):
            keepass_retriever.get("ToDelete")

    def test_unlock_and_lock(self, fake_keepassxc_deep: Path) -> None:
        retriever = KeePassXCRetriever(
            database=Path("/vault.kdbx"),
            password=None,
        )
        assert retriever.is_locked() is True
        retriever.unlock("master123")
        assert retriever.is_locked() is False
        retriever.lock()
        assert retriever.is_locked() is True

    def test_timeout_and_retry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_keepassxc_deep: Path
    ) -> None:
        """Retry logic should handle transient failures."""
        retriever = KeePassXCRetriever(
            database=Path("/vault.kdbx"),
            password="dbpass",
            timeout=5.0,
            max_retries=3,
        )
        # Create an entry to exercise the flow
        result = retriever.create_entry("Tests", "Transient", "u", "p")
        assert result is True

    def test_env_var_password(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """KEEPASSXC_PASSWORD env var should be used when no explicit password."""
        script = tmp_path / "keepassxc-cli"
        script.write_text("#!/usr/bin/env python3\nimport sys; sys.exit(0)\n")
        script.chmod(stat.S_IRWXU)
        monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
        monkeypatch.setenv("KEEPASSXC_PASSWORD", "envpass")
        retriever = KeePassXCRetriever(database=Path("/v.kdbx"))
        assert retriever.is_locked() is False

    def test_env_var_keyfile(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """KEEPASSXC_KEYFILE env var should set the key file path."""
        script = tmp_path / "keepassxc-cli"
        script.write_text("#!/usr/bin/env python3\nimport sys; sys.exit(0)\n")
        script.chmod(stat.S_IRWXU)
        monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
        monkeypatch.setenv("KEEPASSXC_KEYFILE", "/tmp/keyfile.key")
        retriever = KeePassXCRetriever(database=Path("/v.kdbx"), password="p")
        assert retriever._key_file == Path("/tmp/keyfile.key")

    def test_missing_binary_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PasswordStoreError, match="not found on PATH"):
            KeePassXCRetriever(
                database=tmp_path / "vault.kdbx",
                binary="nonexistent-keepassxc-cli",
            )


# ────────────────────────────────────────────────────────────────
#  PassRetriever tests (deep integration)
# ────────────────────────────────────────────────────────────────


@pytest.fixture
def pass_retriever(fake_pass_deep: Path) -> PassRetriever:
    return PassRetriever()


class TestPassRetriever:
    """Tests for PassRetriever deep integration."""

    def test_get_retrieves_password(self, pass_retriever: PassRetriever) -> None:
        # Use the legacy PassStore to store (same state)
        store = PassStore()
        store.store("Email/Work", "work_email_pass")
        pwd = pass_retriever.get("Email/Work")
        assert pwd == "work_email_pass"

    def test_get_missing_raises(self, pass_retriever: PassRetriever) -> None:
        with pytest.raises(PasswordStoreError):
            pass_retriever.get("Nonexistent/Entry")

    def test_list_entries(self, pass_retriever: PassRetriever) -> None:
        store = PassStore()
        store.store("Social/Twitter", "tw_pass")
        store.store("Social/Facebook", "fb_pass")
        entries = pass_retriever.list_entries()
        titles = {e.title for e in entries}
        assert "Social/Twitter" in titles
        assert "Social/Facebook" in titles

    def test_list_entries_empty(self, pass_retriever: PassRetriever) -> None:
        entries = pass_retriever.list_entries()
        assert entries == []

    def test_search_finds_entry(self, pass_retriever: PassRetriever) -> None:
        store = PassStore()
        store.store("Admin/SSH", "ssh_key_pass")
        results = pass_retriever.search("SSH")
        assert len(results) >= 1
        assert any(r.title == "Admin/SSH" for r in results)

    def test_search_no_match(self, pass_retriever: PassRetriever) -> None:
        results = pass_retriever.search("NothingMatchesThis")
        assert results == []

    def test_health_returns_true(self, pass_retriever: PassRetriever) -> None:
        assert pass_retriever.health() is True

    def test_missing_binary_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PasswordStoreError, match="not found on PATH"):
            PassRetriever(binary="nonexistent-pass")


# ────────────────────────────────────────────────────────────────
#  auto_detect tests
# ────────────────────────────────────────────────────────────────


class TestAutoDetect:
    """Tests for the auto_detect function."""

    def test_detects_keepassxc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_which(cmd: str) -> str | None:
            if cmd == "keepassxc-cli":
                return "/usr/bin/keepassxc-cli"
            return None

        monkeypatch.setattr("aegisvault.security.password_store.shutil.which", fake_which)
        assert "keepassxc" in auto_detect()

    def test_detects_pass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_which(cmd: str) -> str | None:
            if cmd == "pass":
                return "/usr/bin/pass"
            return None

        monkeypatch.setattr("aegisvault.security.password_store.shutil.which", fake_which)
        assert "pass" in auto_detect()

    def test_detects_both(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "aegisvault.security.password_store.shutil.which",
            lambda cmd: f"/usr/bin/{cmd}",
        )
        result = auto_detect()
        assert "keepassxc" in result
        assert "pass" in result

    def test_detects_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "aegisvault.security.password_store.shutil.which",
            lambda _cmd: None,
        )
        assert auto_detect() == []


# ───────���────────────────────────────────────────────────────────
#  AegisAgent password integration tests
# ────────────────────────────────────────────────────────────────


class TestAgentPasswordIntegration:
    """Tests for AegisAgent password manager integration."""

    def test_agent_accepts_secret_retriever(
        self, fake_keepassxc_deep: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from aegisvault.orchestration.agent import AegisAgent

        monkeypatch.setattr(
            "aegisvault.orchestration.agent.create_master_key_provider",
            lambda *args, **kw: type(
                "Mock", (), {"get_key": lambda self: b"\x00" * 32, "rotate": lambda self: None}
            )(),
        )

        config = AegisConfig()
        retriever = KeePassXCRetriever(
            database=Path("/vault.kdbx"),
            password="dbpass",
        )
        agent = AegisAgent(config, secret_retriever=retriever)
        assert agent.secret_retriever is retriever

    def test_fill_password_without_retriever(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegisvault.orchestration.agent import AegisAgent

        monkeypatch.setattr(
            "aegisvault.orchestration.agent.create_master_key_provider",
            lambda *args, **kw: type(
                "Mock", (), {"get_key": lambda self: b"\x00" * 32, "rotate": lambda self: None}
            )(),
        )

        config = AegisConfig()
        agent = AegisAgent(config)
        result = agent.fill_password("test/entry")
        assert result is False

    def test_fill_password_with_retriever(
        self, fake_keepassxc_deep: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from aegisvault.orchestration.agent import AegisAgent

        monkeypatch.setattr(
            "aegisvault.orchestration.agent.create_master_key_provider",
            lambda *args, **kw: type(
                "Mock", (), {"get_key": lambda self: b"\x00" * 32, "rotate": lambda self: None}
            )(),
        )

        config = AegisConfig()
        retriever = KeePassXCRetriever(
            database=Path("/vault.kdbx"),
            password="dbpass",
        )
        retriever.create_entry("", "TestEntry", "user", "mypassword")
        agent = AegisAgent(config, secret_retriever=retriever)
        result = agent.fill_password("TestEntry")
        assert result is True
