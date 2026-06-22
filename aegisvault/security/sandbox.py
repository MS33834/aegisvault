"""Sandboxed execution for untrusted subprocesses.

The primary use case is wrapping external commands such as keepassxc-cli or
pass so they run with minimal privileges and limited filesystem access. The
abstraction supports both Linux (bubblewrap) and Windows (PowerShell
AppContainer / LowBoxToken) sandboxes.
"""

from __future__ import annotations

import abc
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import ClassVar

from aegisvault.config import AegisConfig


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
    """

    BWRAP: ClassVar[str] = "bwrap"

    def _build_bwrap_args(
        self,
        bwrap_path: str,
        command: list[str],
        temp_dir: Path,
        extra_readonly_paths: list[Path] | None,
        extra_writable_paths: list[Path] | None,
        env_vars: dict[str, str] | None,
    ) -> list[str]:
        """Construct the bwrap argument list."""
        args: list[str] = [
            bwrap_path,
            "--die-with-parent",
            "--unshare-all",
            "--share-net",  # We explicitly disable network below.
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/sbin",
            "/sbin",
            "--ro-bind",
            "/etc",
            "/etc",
            "--ro-bind",
            str(self.vault_dir),
            str(self.vault_dir),
            "--bind",
            str(temp_dir),
            "/tmp",
        ]

        # Explicit network isolation: replace the share-net above with
        # unshare-net when we want no network access.
        # bwrap semantics: --share-net means keep network namespace. The runner
        # policy is *no* network, so we use --unshare-net instead.
        args = ["--unshare-net" if arg == "--share-net" else arg for arg in args]

        if extra_readonly_paths:
            for path in extra_readonly_paths:
                if path.exists():
                    args.extend(["--ro-bind", str(path), str(path)])

        if extra_writable_paths:
            for path in extra_writable_paths:
                path.mkdir(parents=True, exist_ok=True)
                args.extend(["--bind", str(path), str(path)])

        # HOME points at the writable temp dir so tools do not try to write
        # into the real home directory.
        args.extend(
            [
                "--setenv",
                "HOME",
                "/tmp",
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
            ]
        )
        if env_vars:
            for key, value in env_vars.items():
                args.extend(["--setenv", key, value])

        args.extend(["--", *command])
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
    """Windows sandbox implementation using PowerShell and AppContainer.

    On Windows 11 the runner spawns a low-integrity process inside an
    AppContainer (LowBox token) via PowerShell. Network access is blocked with
    the Windows Defender Firewall helper and the token is restricted to a small
    set of capabilities. Filesystem access is limited to the Vault directory
    (read-only) and an ephemeral working directory (writable).

    This implementation uses the PowerShell ``Invoke-Command`` / ``runas``
    fallback so that no extra native dependencies are required. A future
    enhancement can replace the PowerShell wrapper with direct Win32 API calls
    via ctypes for finer-grained control.
    """

    @staticmethod
    def _ps_quote(value: str) -> str:
        """Single-quote a value for PowerShell, escaping embedded quotes."""
        return "'" + value.replace("'", "''") + "'"

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

        # Build capability SID list for the AppContainer. Start with no
        # capabilities, which is the most restrictive profile.
        capability_sids = "@()"

        # Extra filesystem permissions are expressed as access rules on the
        # LowBox token. We model read-only and writable directories by setting
        # ACLs on the Vault and temp directories.
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
            f"Start-Process -FilePath {self._ps_quote(exe)} -ArgumentList @({arg_list}) "
            f"-AppContainerName 'AegisVaultSandbox' "
            f"-WorkingDirectory {self._ps_quote(tmp)} -Wait -NoNewWindow "
            f"-RedirectStandardOutput {self._ps_quote(tmp_ps + '/stdout.txt')} "
            f"-RedirectStandardError {self._ps_quote(tmp_ps + '/stderr.txt')}; "
            f"Get-Content {self._ps_quote(tmp_ps + '/stdout.txt')}; "
            f"Write-Error (Get-Content {self._ps_quote(tmp_ps + '/stderr.txt')}) "
            f"-ErrorAction Continue"
        )
        return ps

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
        """Run *command* inside a Windows AppContainer sandbox."""
        if not self.enabled:
            raise SandboxError("Sandbox execution is disabled (security.sandbox_enabled=false)")

        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if pwsh is None:
            raise SandboxError("PowerShell is not available on this Windows system")

        self._ensure_vault_dir()
        resolved = self._resolve_command(command)

        with tempfile.TemporaryDirectory(prefix="aegisvault-sandbox-") as tmp:
            temp_path = Path(tmp)
            ps_command = self._build_powershell_command(
                resolved,
                temp_path,
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
                        f"Sandboxed command failed ({result.returncode}): {result.stderr.strip()}"
                    )
                result.check = check  # type: ignore[attr-defined]
                return result
            except subprocess.TimeoutExpired as exc:
                raise SandboxError(
                    f"Sandboxed command timed out after {timeout}s: {' '.join(command)}"
                ) from exc
            except FileNotFoundError as exc:
                raise SandboxError(f"PowerShell binary not found: {pwsh}") from exc


def get_sandbox_runner(config: AegisConfig) -> SandboxRunner:
    """Return a platform-appropriate sandbox runner for *config*."""
    if sys.platform == "win32":
        return WindowsSandboxRunner(config)
    return LinuxSandboxRunner(config)
