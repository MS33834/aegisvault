"""Password store backends for AegisVault.

Backends invoke external command-line tools rather than pulling in extra
Python dependencies.  Both KeePassXC (keepassxc-cli) and password-store
(pass) are supported.

For deep integration, use the ``SecretRetriever``-based classes
(``KeePassXCRetriever`` / ``PassRetriever``) which provide entry
management, search, clipboard auto-fill, and database lifecycle control.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from aegisvault.config import AegisConfig

_logger = logging.getLogger(__name__)


class PasswordStoreError(Exception):
    """Raised when a password store operation fails."""


# ──────────────────────────────────────────────────────────────────────
#  Typed entry structure
# ──────────────────────────────────────────────────────────────────────


class SecretEntry(dict[str, str | None]):
    """A single credential entry from a password store.

    Accessible as both a dict and attribute-style (``entry["title"]`` and
    ``entry.title`` are equivalent).
    """

    __slots__ = ()

    def __init__(
        self,
        title: str = "",
        username: str = "",
        password: str = "",
        url: str | None = None,
        notes: str | None = None,
    ) -> None:
        super().__init__(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
        )

    def __getattr__(self, name: str) -> str | None:
        if name in self:
            return self[name]
        raise AttributeError(f"'SecretEntry' object has no attribute {name!r}")


# ──────────────────────────────────────────────────────────────────────
#  Abstract interfaces
# ──────────────────────────────────────────────────────────────────────


class PasswordStore(ABC):
    """Abstract interface for password storage backends."""

    @abstractmethod
    def store(self, entry: str, password: str, **attrs: Any) -> None:
        """Store *password* under *entry*."""

    @abstractmethod
    def retrieve(self, entry: str) -> str:
        """Retrieve the password stored under *entry*."""


class SecretRetriever(ABC):
    """Deep-integration interface for password manager backends.

    Unlike the simpler ``PasswordStore``, this interface exposes
    entry-level CRUD, search, health checks, and automatic credential
    discovery.  Implementations should handle sandboxed subprocess
    execution, timeouts, and retry logic internally.
    """

    @abstractmethod
    def get(self, entry_path: str) -> str:
        """Retrieve the plaintext password for *entry_path*."""

    @abstractmethod
    def list_entries(self, group: str = "") -> list[SecretEntry]:
        """Return metadata for every entry under *group* (or all entries)."""

    @abstractmethod
    def search(self, query: str) -> list[SecretEntry]:
        """Search entries by *query* and return matching ``SecretEntry`` objects."""

    @abstractmethod
    def health(self) -> bool:
        """Return ``True`` if the backend is reachable and functional."""


# ──────────────────────────────────────────────────────────────────────
#  KeePassXC helpers
# ──────────────────────────────────────────────────────────────────────


def _parse_keepassxc_show(output: str) -> SecretEntry:
    """Parse ``keepassxc-cli show`` output into a ``SecretEntry``."""
    entry = SecretEntry()
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Title: "):
            entry["title"] = line[len("Title: ") :]
        elif line.startswith("UserName: "):
            entry["username"] = line[len("UserName: ") :]
        elif line.startswith("Password: "):
            entry["password"] = line[len("Password: ") :]
        elif line.startswith("URL: "):
            entry["url"] = line[len("URL: ") :] or None
        elif line.startswith("Notes: "):
            entry["notes"] = line[len("Notes: ") :] or None
    return entry


# ──────────────────────────────────────────────────────────────────────
#  KeePassXCRetriever – deep KeePassXC integration
# ───────���──────────────────────────────────────────────────────────────


class KeePassXCRetriever(SecretRetriever):
    """KeePassXC backend with full credential lifecycle management.

    Uses ``keepassxc-cli`` under the hood.  Supports optional sandbox
    execution, configurable timeouts, and automatic retries.
    """

    # ------------------------------------------------------------------
    #  Construction and state
    # ------------------------------------------------------------------

    def __init__(
        self,
        database: Path,
        password: str | None = None,
        key_file: Path | None = None,
        binary: str = "keepassxc-cli",
        timeout: float = 30.0,
        max_retries: int = 3,
        sandbox_runner: Any = None,
    ) -> None:
        self.database = Path(database)
        self._password = password or os.environ.get("KEEPASSXC_PASSWORD")
        env_keyfile = os.environ.get("KEEPASSXC_KEYFILE")
        if key_file is not None:
            self._key_file: Path | None = key_file
        elif env_keyfile:
            self._key_file = Path(env_keyfile)
        else:
            self._key_file = None
        self._binary = binary
        self._timeout = timeout
        self._max_retries = max_retries
        self._sandbox_runner = sandbox_runner
        self._locked = self._password is None
        if not shutil.which(self._binary):
            raise PasswordStoreError(f"{self._binary} not found on PATH")

    # ------------------------------------------------------------------
    #  Internal helpers
    # ------------------------------------------------------------------

    def _base_args(self) -> list[str]:
        """Build the base argument list for keepassxc-cli."""
        args: list[str] = [self._binary, "--pw-stdin"]
        if self._key_file is not None:
            args.extend(["--key-file", str(self._key_file)])
        args.append(str(self.database))
        return args

    def _db_password_input(self) -> str:
        """Return the database password line for stdin."""
        return (self._password or "") + "\n"

    def _run(
        self,
        cmd: list[str],
        input_data: str = "",
        *,
        timeout: float | None = None,
    ) -> str:
        """Execute *cmd* with timeout management and retry logic."""
        effective_timeout = timeout if timeout is not None else self._timeout
        last_exc: Exception | None = None

        for attempt in range(self._max_retries):
            try:
                if self._sandbox_runner is not None:
                    result = self._sandbox_runner.run(
                        cmd,
                        timeout=effective_timeout,
                        check=False,
                        input_data=input_data.encode("utf-8") if input_data else None,
                    )
                else:
                    result = subprocess.run(
                        cmd,
                        input=input_data,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=effective_timeout,
                    )
            except subprocess.TimeoutExpired as exc:
                raise PasswordStoreError(
                    f"{self._binary} timed out after {effective_timeout}s"
                ) from exc
            except FileNotFoundError as exc:
                raise PasswordStoreError(f"{self._binary} not found: {exc}") from exc

            if result.returncode != 0:
                stderr = result.stderr.strip() if result.stderr else ""
                last_exc = PasswordStoreError(
                    f"{self._binary} failed (rc={result.returncode}): {stderr}"
                )
                if attempt < self._max_retries - 1:
                    _logger.warning(
                        "KeePassXC command failed (attempt %d/%d): %s",
                        attempt + 1,
                        self._max_retries,
                        stderr,
                    )
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise last_exc
            return result.stdout

        # Should not be reached, but satisfy the type checker.
        if last_exc is not None:
            raise last_exc
        return ""

    # ------------------------------------------------------------------
    #  SecretRetriever interface
    # ------------------------------------------------------------------

    def get(self, entry_path: str) -> str:
        """Retrieve the plaintext password for *entry_path*."""
        cmd = self._base_args() + ["show", "--show-protected", entry_path]
        output = self._run(cmd, self._db_password_input())
        entry = _parse_keepassxc_show(output)
        if not entry["password"]:
            raise PasswordStoreError(f"No password found for entry {entry_path!r}")
        return entry["password"]

    def list_entries(self, group: str = "") -> list[SecretEntry]:
        """List all entries under *group* (or root if empty)."""
        ls_cmd = self._base_args() + ["ls", "--recursive"]
        if group:
            ls_cmd.append(group)
        output = self._run(ls_cmd, self._db_password_input())

        paths: list[str] = []
        for line in output.splitlines():
            stripped = line.strip()
            if stripped and not stripped.endswith("/"):
                paths.append(stripped)

        entries: list[SecretEntry] = []
        for path in paths:
            try:
                show_cmd = self._base_args() + ["show", "--show-protected", path]
                show_output = self._run(show_cmd, self._db_password_input())
                entries.append(_parse_keepassxc_show(show_output))
            except PasswordStoreError:
                _logger.debug("Could not show entry %s", path, exc_info=True)
        return entries

    def search(self, query: str) -> list[SecretEntry]:
        """Search entries matching *query*."""
        cmd = self._base_args() + ["search", query]
        output = self._run(cmd, self._db_password_input())

        entries: list[SecretEntry] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # keepassxc-cli search outputs paths
            try:
                show_cmd = self._base_args() + ["show", "--show-protected", line]
                show_output = self._run(show_cmd, self._db_password_input())
                entries.append(_parse_keepassxc_show(show_output))
            except PasswordStoreError:
                _logger.debug("Could not show search result %s", line, exc_info=True)
        return entries

    def health(self) -> bool:
        """Check whether keepassxc-cli and the database are reachable."""
        try:
            cmd = self._base_args() + ["ls"]
            self._run(cmd, self._db_password_input(), timeout=10.0)
            return True
        except PasswordStoreError:
            return False

    # ------------------------------------------------------------------
    #  Auto-fill
    # ------------------------------------------------------------------

    def auto_fill(
        self,
        entry_path: str | None = None,
        *,
        target_window_title: str = "",
    ) -> bool:
        """Copy a credential to the clipboard and optionally open the URL.

        If *entry_path* is given that entry is used directly.  Otherwise
        the first entry matching *target_window_title* is selected via
        ``keepassxc-cli search``.

        Returns ``True`` when the password was successfully copied to the
        clipboard.
        """
        if entry_path is None:
            matches = self.search(target_window_title)
            if not matches:
                _logger.warning("No KeePassXC entry found for window '%s'", target_window_title)
                return False
            if len(matches) > 1:
                _logger.info(
                    "Multiple entries match '%s', using %r",
                    target_window_title,
                    matches[0].title,
                )
            entry = matches[0]
            entry_path = entry.title

        assert entry_path is not None  # narrowed above

        try:
            clip_cmd = self._base_args() + ["clip", entry_path, "15"]
            self._run(clip_cmd, self._db_password_input())

            # Attempt to open the URL if one exists.
            show_cmd = self._base_args() + ["show", "--show-protected", entry_path]
            show_output = self._run(show_cmd, self._db_password_input())
            parsed = _parse_keepassxc_show(show_output)
            if parsed.url:
                try:
                    subprocess.run(
                        ["xdg-open", parsed.url],
                        capture_output=True,
                        timeout=10.0,
                        check=False,
                    )
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    _logger.debug("xdg-open not available to open URL", exc_info=True)
            return True
        except PasswordStoreError:
            _logger.exception("Auto-fill failed for entry %s", entry_path)
            return False

    # ------------------------------------------------------------------
    #  Entry management (CRUD)
    # ------------------------------------------------------------------

    def create_entry(
        self,
        group: str,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
    ) -> bool:
        """Create a new entry under *group* in the KeePassXC database."""
        entry_path = f"{group}/{title}" if group else title
        cmd = self._base_args() + ["add"]
        if username:
            cmd += ["--username", username]
        if url:
            cmd += ["--url", url]
        if notes:
            cmd += ["--notes", notes]
        cmd.append(entry_path)

        input_data = self._db_password_input() + f"{password}\n{password}\n"
        self._run(cmd, input_data)
        return True

    def update_entry(self, entry_path: str, **fields: str) -> bool:
        """Update fields of an existing entry.

        Supported keyword arguments: ``title``, ``username``, ``password``,
        ``url``, ``notes``.
        """
        cmd = self._base_args() + ["edit"]
        if "title" in fields:
            cmd += ["--title", fields["title"]]
        if "username" in fields:
            cmd += ["--username", fields["username"]]
        if "url" in fields:
            cmd += ["--url", fields["url"]]
        if "notes" in fields:
            cmd += ["--notes", fields["notes"]]
        if "password" in fields:
            cmd += ["--password", fields["password"]]
        cmd.append(entry_path)

        self._run(cmd, self._db_password_input())
        return True

    def delete_entry(self, entry_path: str) -> bool:
        """Delete *entry_path* from the KeePassXC database."""
        cmd = self._base_args() + ["rm", entry_path]
        self._run(cmd, self._db_password_input())
        return True

    # ------------------------------------------------------------------
    #  Database lifecycle
    # ------------------------------------------------------------------

    def unlock(
        self,
        password: str,
        key_file: Path | None = None,
    ) -> bool:
        """Unlock the database with *password* and optional *key_file*."""
        if password:
            self._password = password
        if key_file is not None:
            self._key_file = key_file
        self._locked = False
        return self.health()

    def lock(self) -> bool:
        """Lock the database by clearing the in-memory password."""
        self._password = None
        self._locked = True
        return True

    def is_locked(self) -> bool:
        """Return ``True`` if the database password is not held in memory."""
        return self._locked


# ──────────────────────────────────────────────────────────────────────
#  PassRetriever – deep pass (password-store) integration
# ──────────────────────────────────────────────────────────────────────


class PassRetriever(SecretRetriever):
    """password-store (pass) backend with entry listing, search, and health."""

    def __init__(
        self,
        binary: str = "pass",
        store_dir: Path | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self._binary = binary
        self._store_dir = store_dir
        self._timeout = timeout
        self._max_retries = max_retries
        if not shutil.which(self._binary):
            raise PasswordStoreError(f"{binary} not found on PATH")

    def _env(self) -> dict[str, str]:
        env: dict[str, str] = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        home = os.environ.get("HOME")
        if home:
            env["HOME"] = home
        if self._store_dir is not None:
            env["PASSWORD_STORE_DIR"] = str(self._store_dir)
        return env

    def _run(
        self,
        cmd: list[str],
        *,
        input_data: str | None = None,
        timeout: float | None = None,
    ) -> str:
        effective_timeout = timeout if timeout is not None else self._timeout
        last_exc: Exception | None = None

        for attempt in range(self._max_retries):
            try:
                result = subprocess.run(
                    cmd,
                    input=input_data,
                    capture_output=True,
                    text=True,
                    check=False,
                    env=self._env(),
                    timeout=effective_timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise PasswordStoreError(
                    f"{self._binary} timed out after {effective_timeout}s"
                ) from exc
            except FileNotFoundError as exc:
                raise PasswordStoreError(f"{self._binary} not found: {exc}") from exc

            if result.returncode != 0:
                stderr = result.stderr.strip() if result.stderr else ""
                last_exc = PasswordStoreError(f"{self._binary} failed: {stderr}")
                if attempt < self._max_retries - 1:
                    _logger.warning(
                        "pass command failed (attempt %d/%d): %s",
                        attempt + 1,
                        self._max_retries,
                        stderr,
                    )
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise last_exc
            return result.stdout

        if last_exc is not None:
            raise last_exc
        return ""

    # ------------------------------------------------------------------
    #  SecretRetriever interface
    # ------------------------------------------------------------------

    def get(self, entry_path: str) -> str:
        """Retrieve the plaintext password for *entry_path*."""
        cmd = [self._binary, "show", entry_path]
        output = self._run(cmd)
        lines = output.splitlines()
        if not lines:
            raise PasswordStoreError(f"Empty password store entry {entry_path!r}")
        return lines[0].strip()

    def list_entries(self, group: str = "") -> list[SecretEntry]:
        """List all entries under *group* (or all entries if empty)."""
        cmd = [self._binary, "ls"]
        if group:
            cmd.append(group)
        output = self._run(cmd, timeout=10.0)

        entries: list[SecretEntry] = []
        for raw_line in output.splitlines():
            # pass ls output uses tree markers; strip the tree-drawing
            # characters and grab the entry path.
            import re

            match = re.search(r"([\w./-]+)\s*$", raw_line)
            if match is None:
                continue
            path = match.group(1)
            try:
                pwd = self.get(path)
                entries.append(SecretEntry(title=path, password=pwd))
            except PasswordStoreError:
                _logger.debug("Skipping entry %s", path, exc_info=True)
        return entries

    def search(self, query: str) -> list[SecretEntry]:
        """Search entries matching *query*."""
        cmd = [self._binary, "find", query]
        output = self._run(cmd, timeout=10.0)

        entries: list[SecretEntry] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            path_match = line.split("Search Terms: ")[-1] if "Search Terms:" in line else line
            path = path_match.strip()
            try:
                pwd = self.get(path)
                entries.append(SecretEntry(title=path, password=pwd))
            except PasswordStoreError:
                _logger.debug("Skipping search result %s", path, exc_info=True)
        return entries

    def health(self) -> bool:
        """Check whether pass is reachable."""
        try:
            self._run([self._binary, "ls"], timeout=10.0)
            return True
        except PasswordStoreError:
            return False


# ──────────────────────────────────────────────────────────────────────
#  Automatic discovery
# ──────────────────────────────────────────────────────────────────────


def auto_detect() -> list[str]:
    """Return a list of password manager backend names available on PATH.

    Possible values: ``"keepassxc"``, ``"pass"``.
    """
    available: list[str] = []
    if shutil.which("keepassxc-cli"):
        available.append("keepassxc")
    if shutil.which("pass"):
        available.append("pass")
    return available


# ──────────────────────────────────────────────────────────────────────
#  Legacy store classes (backward-compatible)
# ──────────────────────────────────────────────────────────────────────


class KeePassXCStore(PasswordStore):
    """KeePassXC backend using keepassxc-cli.

    The database password is supplied via stdin so it never appears in the
    process argument list.
    """

    def __init__(
        self,
        database: Path,
        password: str | None = None,
        key_file: Path | None = None,
        binary: str = "keepassxc-cli",
    ) -> None:
        self.database = Path(database)
        self.password = password
        self.key_file = key_file
        self.binary = binary
        if not shutil.which(self.binary):
            raise PasswordStoreError(f"{self.binary} not found on PATH")

    def _base_args(self) -> list[str]:
        args = [self.binary, "--pw-stdin"]
        if self.key_file is not None:
            args.extend(["--key-file", str(self.key_file)])
        args.append(str(self.database))
        return args

    def _run(self, cmd: list[str], input_data: str) -> str:
        try:
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        except subprocess.TimeoutExpired as exc:
            raise PasswordStoreError(f"{self.binary} timed out: {exc}") from exc
        except FileNotFoundError as exc:
            raise PasswordStoreError(f"{self.binary} not found: {exc}") from exc

        if result.returncode != 0:
            raise PasswordStoreError(f"{self.binary} failed: {result.stderr.strip()}")
        return result.stdout

    def store(self, entry: str, password: str, **attrs: Any) -> None:
        """Store *password* under *entry* in the KeePassXC database."""
        cmd = self._base_args() + ["edit", "-p", entry]
        # Sequence: database password, new password, confirmation.
        db_password = self.password or ""
        input_data = f"{db_password}\n{password}\n{password}\n"
        self._run(cmd, input_data)

    def retrieve(self, entry: str) -> str:
        """Retrieve the password for *entry* from the KeePassXC database."""
        cmd = self._base_args() + ["show", "--show-protected", entry]
        db_password = self.password or ""
        output = self._run(cmd, f"{db_password}\n")
        for line in output.splitlines():
            if line.startswith("Password: "):
                return line[len("Password: ") :].strip()
        raise PasswordStoreError(f"Password not found for entry {entry!r}")


class PassStore(PasswordStore):
    """password-store (pass) backend."""

    def __init__(self, binary: str = "pass", store_dir: Path | None = None) -> None:
        self.binary = binary
        self.store_dir = store_dir
        if not shutil.which(self.binary):
            raise PasswordStoreError(f"{binary} not found on PATH")

    def _env(self) -> dict[str, str]:
        """Minimal environment for the pass subprocess."""
        env: dict[str, str] = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        home = os.environ.get("HOME")
        if home:
            env["HOME"] = home
        if self.store_dir is not None:
            env["PASSWORD_STORE_DIR"] = str(self.store_dir)
        return env

    def store(self, entry: str, password: str, **attrs: Any) -> None:
        """Store *password* under *entry* in the password store."""
        cmd = [self.binary, "insert", "--echo", "--force", entry]
        try:
            result = subprocess.run(
                cmd,
                input=f"{password}\n",
                capture_output=True,
                text=True,
                check=False,
                env=self._env(),
                timeout=60,
            )
        except subprocess.TimeoutExpired as exc:
            raise PasswordStoreError(f"{self.binary} timed out: {exc}") from exc
        except FileNotFoundError as exc:
            raise PasswordStoreError(f"{self.binary} not found: {exc}") from exc
        if result.returncode != 0:
            raise PasswordStoreError(f"pass insert failed: {result.stderr.strip()}")

    def retrieve(self, entry: str) -> str:
        """Retrieve the password stored under *entry*."""
        cmd = [self.binary, "show", entry]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                env=self._env(),
                timeout=60,
            )
        except subprocess.TimeoutExpired as exc:
            raise PasswordStoreError(f"{self.binary} timed out: {exc}") from exc
        except FileNotFoundError as exc:
            raise PasswordStoreError(f"{self.binary} not found: {exc}") from exc
        if result.returncode != 0:
            raise PasswordStoreError(f"pass show failed: {result.stderr.strip()}")
        lines = result.stdout.splitlines()
        if not lines:
            raise PasswordStoreError(f"Empty password store entry {entry!r}")
        return lines[0]


def create_password_store(
    name: str,
    config: AegisConfig | None = None,
    **options: Any,
) -> PasswordStore:
    """Factory for password store backends.

    Supported names: ``keepassxc`` and ``pass`` (case-insensitive).  Options
    override values taken from *config*.
    """
    key = name.lower()

    if key in {"keepassxc", "keepass"}:
        database = options.get("database") or (
            config.security.password_store_database if config else None
        )
        if database is None:
            raise PasswordStoreError("KeePassXC database path is required")
        return KeePassXCStore(
            database=Path(database),
            password=options.get("password")
            or (config.security.password_store_password if config else None),
            key_file=options.get("key_file")
            or (config.security.password_store_key_file if config else None),
            binary=options.get("binary", "keepassxc-cli"),
        )

    if key in {"pass", "password-store", "passwordstore"}:
        return PassStore(
            binary=options.get("binary", "pass"),
            store_dir=options.get("store_dir")
            or (config.security.password_store_dir if config else None),
        )

    raise PasswordStoreError(f"Unsupported password store: {name!r}")
