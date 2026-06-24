"""Password store backends for AegisVault.

Backends invoke external command-line tools rather than pulling in extra
Python dependencies.  Both KeePassXC (keepassxc-cli) and password-store
(pass) are supported.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from aegisvault.config import AegisConfig


class PasswordStoreError(Exception):
    """Raised when a password store operation fails."""


class PasswordStore(ABC):
    """Abstract interface for password storage backends."""

    @abstractmethod
    def store(self, entry: str, password: str, **attrs: Any) -> None:
        """Store *password* under *entry*."""

    @abstractmethod
    def retrieve(self, entry: str) -> str:
        """Retrieve the password stored under *entry*."""


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
