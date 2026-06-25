"""Sandboxed execution for untrusted subprocesses.

The primary use case is wrapping external commands such as keepassxc-cli or
pass so they run with minimal privileges and limited filesystem access. The
abstraction supports both Linux (bubblewrap) and Windows (Win32 AppContainer
API via ctypes, with PowerShell fallback) sandboxes.
"""

from __future__ import annotations

import abc
import logging
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import ClassVar

from aegisvault.config import AegisConfig

_logger = logging.getLogger(__name__)

_RESERVED_ENV_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONHOME",
    }
)
_ENV_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class SandboxError(Exception):
    """Raised when a sandbox operation cannot be performed."""


class SandboxRunner(abc.ABC):
    """Abstract sandbox runner for isolated subprocess execution."""

    def __init__(self, config: AegisConfig) -> None:
        self.config = config
        self.vault_dir = config.paths.vault
        self.enabled = config.security.sandbox_enabled

    @abc.abstractmethod
    def run(
        self,
        command: list[str],
        *,
        timeout: float | None = None,
        check: bool = True,
        input_data: bytes | None = None,
        extra_readonly_paths: list[Path] | None = None,
        extra_writable_paths: list[Path] | None = None,
        env_vars: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run *command* inside the sandbox.

        The returned process uses text mode. Callers receive stdout/stderr as
        strings. The sandbox implementation must ensure the Vault directory is
        mounted read-only and an ephemeral temporary directory is writable.
        """

    def _ensure_vault_dir(self) -> None:
        """Create the Vault directory if it does not already exist."""
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_command(self, command: list[str]) -> list[str]:
        """Resolve the executable for *command* and return the final argv."""
        if not command:
            raise SandboxError("Command list must not be empty")
        executable = shutil.which(command[0])
        if executable is None:
            raise SandboxError(f"Sandboxed executable not found: {command[0]}")
        return [executable, *command[1:]]


class LinuxSandboxRunner(SandboxRunner):
    """Linux sandbox implementation using bubblewrap (bwrap).

    bwrap creates a minimal namespace with no network access, a read-only bind
    mount for the Vault directory, and a writable tmpfs for temporary files.

    Hardening features:
      - Minimal root filesystem via ``--tmpfs /`` with whitelisted read-only
        bind mounts for essential system paths (/usr, /lib, /lib64, /bin,
        /etc/ssl).
      - Full namespace isolation: network, IPC, UTS, PID, and user namespaces.
      - Process runs as PID 1 with ``--as-pid-1``.
      - Optional seccomp BPF profile via the ``seccomp_profile`` attribute.
      - Writable scratch space via ``--tmpfs /tmp``.
    """

    BWRAP: ClassVar[str] = "bwrap"

    # Essential system paths exposed read-only inside the sandbox.
    _ESSENTIAL_RO_PATHS: ClassVar[tuple[str, ...]] = (
        "/usr",
        "/lib",
        "/lib64",
        "/bin",
        "/etc/ssl",
    )

    def __init__(self, config: AegisConfig) -> None:
        super().__init__(config)
        self.seccomp_profile: Path | None = None
        """Path to a seccomp BPF filter file.  When set, ``--seccomp <path>``
        is added to the bwrap invocation."""

    def _build_bwrap_args(
        self,
        bwrap_path: str,
        command: list[str],
        temp_dir: Path,
        extra_readonly_paths: list[Path] | None,
        extra_writable_paths: list[Path] | None,
        env_vars: dict[str, str] | None,
    ) -> list[str]:
        """Construct the bwrap argument list with hardened isolation."""
        # ── Namespace isolation ───────────────────────────────────────
        args: list[str] = [
            bwrap_path,
            "--die-with-parent",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-pid",
            "--unshare-user",
            "--as-pid-1",
        ]

        # ── Minimal root filesystem ────────────────────────────────────
        args += ["--tmpfs", "/"]

        # Virtual filesystems.
        args += ["--proc", "/proc", "--dev", "/dev"]

        # Whitelisted system paths (read-only).
        for sys_path in self._ESSENTIAL_RO_PATHS:
            if Path(sys_path).exists():
                args += ["--ro-bind", sys_path, sys_path]

        # Vault directory (read-only).
        args += ["--ro-bind", str(self.vault_dir), str(self.vault_dir)]

        # Writable scratch space (isolated tmpfs).
        args += ["--tmpfs", "/tmp"]

        # ── Seccomp BPF filtering (optional) ─────��────────────────────
        if self.seccomp_profile is not None and self.seccomp_profile.exists():
            args += ["--seccomp", str(self.seccomp_profile)]

        # ── Extra filesystem permissions ──────────────────────────────
        if extra_readonly_paths:
            for path in extra_readonly_paths:
                if path.exists():
                    args += ["--ro-bind", str(path), str(path)]

        if extra_writable_paths:
            for path in extra_writable_paths:
                path.mkdir(parents=True, exist_ok=True)
                args += ["--bind", str(path), str(path)]

        # ── Environment ───────────────────────────────────────────────
        # HOME / TMPDIR point at the writable tmpfs so tools do not try
        # to write into the real home directory.
        args += [
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
        ]
        if env_vars:
            for key, value in env_vars.items():
                if key in _RESERVED_ENV_KEYS:
                    continue
                if not _ENV_KEY_PATTERN.match(key):
                    continue
                args += ["--setenv", key, value]

        # ── Command ───────────────────────────────────────────────────
        args += ["--", *command]
        return args

    def run(
        self,
        command: list[str],
        *,
        timeout: float | None = None,
        check: bool = True,
        input_data: bytes | None = None,
        extra_readonly_paths: list[Path] | None = None,
        extra_writable_paths: list[Path] | None = None,
        env_vars: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run *command* inside a bwrap sandbox."""
        if not self.enabled:
            raise SandboxError("Sandbox execution is disabled (security.sandbox_enabled=false)")

        bwrap_path = shutil.which(self.BWRAP)
        if bwrap_path is None:
            raise SandboxError(
                "bubblewrap (bwrap) is not installed. Install it to enable Linux sandboxing."
            )

        self._ensure_vault_dir()
        resolved = self._resolve_command(command)

        with tempfile.TemporaryDirectory(prefix="aegisvault-sandbox-") as tmp:
            temp_path = Path(tmp)
            argv = self._build_bwrap_args(
                bwrap_path,
                resolved,
                temp_path,
                extra_readonly_paths,
                extra_writable_paths,
                env_vars,
            )
            try:
                return subprocess.run(
                    argv,
                    input=input_data,
                    capture_output=True,
                    text=True,
                    check=check,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise SandboxError(
                    f"Sandboxed command timed out after {timeout}s: {' '.join(command)}"
                ) from exc
            except FileNotFoundError as exc:
                raise SandboxError(f"Sandbox binary not found: {bwrap_path}") from exc
            except subprocess.CalledProcessError as exc:
                raise SandboxError(
                    f"Sandboxed command failed ({exc.returncode}): {exc.stderr.strip()}"
                ) from exc


class WindowsSandboxRunner(SandboxRunner):
    """Windows sandbox implementation using Win32 AppContainer APIs.

    Prefers direct Win32 API calls (via the ``win32_appcontainer`` helper
    module) to create, run, and tear down AppContainer profiles.  On
    non-Windows hosts, or when the Win32 path raises ``NotImplementedError``
    or ``AppContainerError``, the runner falls back to a PowerShell-based
    implementation.

    The PowerShell fallback relies on the ``New-AppContainerProfile`` and
    ``Add-AppContainerAllowedPath`` cmdlets, which are **not** part of a
    stock Windows installation; when they are missing the fallback itself
    will fail at runtime.
    """

    _APPCONTAINER_NAME: str = "AegisVaultSandbox"

    @staticmethod
    def _ps_quote(value: str) -> str:
        """Single-quote a value for PowerShell with full special-character escaping.

        Escapes single-quotes (required within single-quoted strings) and
        additionally escapes backticks, dollar signs, double quotes and
        newlines as defense-in-depth against injection.
        """
        safe = value
        safe = safe.replace("`", "``")
        safe = safe.replace("$", "`$")
        safe = safe.replace('"', '`"')
        safe = safe.replace("\n", "`n")
        safe = safe.replace("'", "''")
        return "'" + safe + "'"

    def _ps_build_arg_list(self, args: list[str]) -> str:
        """Build a PowerShell array literal from command arguments."""
        return ", ".join(self._ps_quote(arg) for arg in args)

    def _ps_build_env_block(self, env_vars: dict[str, str] | None) -> str:
        """Build environment variable assignments for PowerShell."""
        if not env_vars:
            return ""
        entries = "; ".join(
            f"$env:{key} = {self._ps_quote(value)}" for key, value in env_vars.items()
        )
        return entries + "; "

    def _ps_build_path_list(self, paths: list[str]) -> str:
        """Build a PowerShell array literal from filesystem paths."""
        return ", ".join(self._ps_quote(path) for path in paths)

    # ── Win32 AppContainer integration ────────────────────────────────

    def _try_win32_appcontainer(
        self,
        resolved: list[str],
        temp_dir: Path,
        *,
        timeout: float | None,
        check: bool,
        env_vars: dict[str, str] | None,
    ) -> subprocess.CompletedProcess[str]:
        """Run *resolved* inside a Win32 AppContainer.

        Profile creation, process execution, and cleanup are handled by the
        ``win32_appcontainer`` helper module.  Raises ``SandboxError`` or
        the underlying ``AppContainerError``/``NotImplementedError`` on
        failure.
        """
        from aegisvault.security.win32_appcontainer import (
            AppContainerError,
            create_appcontainer_profile,
            delete_appcontainer_profile,
            run_in_appcontainer,
        )

        # Ensure any stale profile from a previous run is removed.
        try:
            delete_appcontainer_profile(self._APPCONTAINER_NAME)
        except (AppContainerError, NotImplementedError):
            pass

        sid = create_appcontainer_profile(
            self._APPCONTAINER_NAME,
            "Restricted execution profile for AegisVault",
        )
        try:
            # Build Windows command-line string.
            cmdline = subprocess.list2cmdline(resolved)

            # If caller supplied env vars, prepend SET commands for the
            # child process.  This is crude but sufficient for most tools.
            if env_vars:
                for key, value in env_vars.items():
                    if key in _RESERVED_ENV_KEYS:
                        continue
                    if not _ENV_KEY_PATTERN.match(key):
                        continue
                    cmdline = f"{key}={value} & " + cmdline

            timeout_ms = int(timeout * 1000) if timeout is not None else 0

            retcode, stdout, stderr = run_in_appcontainer(
                sid,
                cmdline,
                working_directory=str(temp_dir),
                timeout_ms=timeout_ms,
            )

            result = subprocess.CompletedProcess(
                args=resolved,
                returncode=retcode,
                stdout=stdout,
                stderr=stderr,
            )
            if check and retcode != 0:
                raise SandboxError(f"Sandboxed command failed ({retcode}): {stderr.strip()}")
            result.check = check  # type: ignore[attr-defined]
            return result
        finally:
            try:
                delete_appcontainer_profile(self._APPCONTAINER_NAME)
            except (AppContainerError, NotImplementedError):
                _logger.debug(
                    "Failed to clean up AppContainer profile '%s'",
                    self._APPCONTAINER_NAME,
                    exc_info=True,
                )

    # ── PowerShell fallback ───────────────────────────────────────────

    def _build_powershell_command(
        self,
        command: list[str],
        temp_dir: Path,
        extra_readonly_paths: list[Path] | None,
        extra_writable_paths: list[Path] | None,
        env_vars: dict[str, str] | None,
    ) -> str:
        """Build the PowerShell command that launches the sandboxed process."""
        vault = str(self.vault_dir.resolve())
        tmp = str(temp_dir.resolve())
        tmp_ps = tmp.replace("\\", "/")
        exe = command[0]
        args = command[1:]

        arg_list = self._ps_build_arg_list(args)
        env_block = self._ps_build_env_block(env_vars)

        capability_sids = "@()"

        readonly_paths = [vault]
        if extra_readonly_paths:
            readonly_paths.extend(str(p.resolve()) for p in extra_readonly_paths if p.exists())

        writable_paths = [tmp]
        if extra_writable_paths:
            writable_paths.extend(str(p.resolve()) for p in extra_writable_paths)
            for path in extra_writable_paths:
                path.mkdir(parents=True, exist_ok=True)

        readonly_list = self._ps_build_path_list(readonly_paths)
        writable_list = self._ps_build_path_list(writable_paths)

        ps = (
            f"$ErrorActionPreference = 'Stop'; "
            f"$vaultPaths = @({readonly_list}); "
            f"$writePaths = @({writable_list}); "
            f"$sid = New-AppContainerProfile -Name 'AegisVaultSandbox' "
            f"-DisplayName 'AegisVault Sandbox' "
            f"-Description 'Restricted execution profile for AegisVault' "
            f"-Capabilities {capability_sids}; "
            f"foreach ($path in $vaultPaths) {{ "
            f"Add-AppContainerAllowedPath -Path $path -AppContainerSid $sid "
            f"-Access ReadAndExecute }}; "
            f"foreach ($path in $writePaths) {{ "
            f"Add-AppContainerAllowedPath -Path $path -AppContainerSid $sid "
            f"-Access Modify }}; "
            f"{env_block}"
            f"Start-Process -FilePath {self._ps_quote(exe)} "
            f"-ArgumentList @({arg_list}) "
            f"-AppContainerName 'AegisVaultSandbox' "
            f"-WorkingDirectory {self._ps_quote(tmp)} -Wait -NoNewWindow "
            f"-RedirectStandardOutput {self._ps_quote(tmp_ps + '/stdout.txt')} "
            f"-RedirectStandardError {self._ps_quote(tmp_ps + '/stderr.txt')}; "
            f"Get-Content {self._ps_quote(tmp_ps + '/stdout.txt')}; "
            f"Write-Error (Get-Content {self._ps_quote(tmp_ps + '/stderr.txt')}) "
            f"-ErrorAction Continue"
        )
        return ps

    def _run_powershell(
        self,
        resolved: list[str],
        temp_dir: Path,
        *,
        timeout: float | None,
        check: bool,
        input_data: bytes | None,
        extra_readonly_paths: list[Path] | None,
        extra_writable_paths: list[Path] | None,
        env_vars: dict[str, str] | None,
    ) -> subprocess.CompletedProcess[str]:
        """Fallback: run *resolved* via a PowerShell AppContainer script."""
        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if pwsh is None:
            raise SandboxError("PowerShell is not available on this Windows system")

        ps_command = self._build_powershell_command(
            resolved,
            temp_dir,
            extra_readonly_paths,
            extra_writable_paths,
            env_vars,
        )
        try:
            result = subprocess.run(
                [pwsh, "-Command", ps_command],
                input=input_data,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
            if check and result.returncode != 0:
                raise SandboxError(
                    f"Sandboxed command failed ({result.returncode}): " f"{result.stderr.strip()}"
                )
            result.check = check  # type: ignore[attr-defined]
            return result
        except subprocess.TimeoutExpired as exc:
            raise SandboxError(
                f"Sandboxed command timed out after {timeout}s: " f"{' '.join(resolved)}"
            ) from exc
        except FileNotFoundError as exc:
            raise SandboxError(f"PowerShell binary not found: {pwsh}") from exc

    # ── Public API ────────────────────────────────────────────────────

    def run(
        self,
        command: list[str],
        *,
        timeout: float | None = None,
        check: bool = True,
        input_data: bytes | None = None,
        extra_readonly_paths: list[Path] | None = None,
        extra_writable_paths: list[Path] | None = None,
        env_vars: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run *command* inside a Windows AppContainer sandbox.

        The runner prefers direct Win32 API calls (``win32_appcontainer``
        helper module).  When the Win32 path is not available (e.g.
        non-Windows hosts) it falls back to a PowerShell-based
        implementation.
        """
        if not self.enabled:
            raise SandboxError("Sandbox execution is disabled (security.sandbox_enabled=false)")

        self._ensure_vault_dir()
        resolved = self._resolve_command(command)

        with tempfile.TemporaryDirectory(prefix="aegisvault-sandbox-") as tmp:
            temp_path = Path(tmp)

            # Prefer the Win32 AppContainer path on Windows when no stdin is
            # required (the Win32 helper currently does not support piped
            # stdin).
            if sys.platform == "win32" and input_data is None:
                from aegisvault.security.win32_appcontainer import AppContainerError

                try:
                    return self._try_win32_appcontainer(
                        resolved,
                        temp_path,
                        timeout=timeout,
                        check=check,
                        env_vars=env_vars,
                    )
                except (AppContainerError, NotImplementedError, ModuleNotFoundError, OSError):
                    _logger.debug(
                        "Win32 AppContainer failed; falling back to PowerShell",
                        exc_info=True,
                    )

            # PowerShell fallback (also used when stdin data is present).
            return self._run_powershell(
                resolved,
                temp_path,
                timeout=timeout,
                check=check,
                input_data=input_data,
                extra_readonly_paths=extra_readonly_paths,
                extra_writable_paths=extra_writable_paths,
                env_vars=env_vars,
            )


def get_sandbox_runner(config: AegisConfig) -> SandboxRunner:
    """Return a platform-appropriate sandbox runner for *config*."""
    if sys.platform == "win32":
        return WindowsSandboxRunner(config)
    return LinuxSandboxRunner(config)
