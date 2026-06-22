"""Tests for the sandboxed subprocess runner.

The Linux implementation requires bubblewrap (bwrap), which is not expected in
most CI environments. These tests therefore mock ``subprocess.run`` and
``shutil.which`` to exercise the code paths without an actual sandbox binary.

Windows-specific AppContainer code is similarly mocked on non-Windows hosts.
"""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from aegisvault.config import AegisConfig
from aegisvault.security.sandbox import (
    LinuxSandboxRunner,
    SandboxError,
    SandboxRunner,
    WindowsSandboxRunner,
    get_sandbox_runner,
)


def _enabled_config(tmp_path: Path) -> AegisConfig:
    """Build a config with sandboxing enabled and isolated paths."""
    config = AegisConfig()
    config.security.sandbox_enabled = True
    config.paths.vault = tmp_path / "Vault"
    return config


def test_sandbox_runner_is_abstract() -> None:
    """SandboxRunner cannot be instantiated directly."""
    with pytest.raises(TypeError):
        SandboxRunner(AegisConfig())  # type: ignore[abstract]


def test_factory_returns_linux_runner_on_unix(tmp_path: Path) -> None:
    """get_sandbox_runner returns LinuxSandboxRunner on non-Windows platforms."""
    if sys.platform == "win32":
        pytest.skip("Platform-specific test")
    config = _enabled_config(tmp_path)
    runner = get_sandbox_runner(config)
    assert isinstance(runner, LinuxSandboxRunner)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows factory path")
def test_factory_returns_windows_runner_on_windows(tmp_path: Path) -> None:
    """get_sandbox_runner returns WindowsSandboxRunner on Windows."""
    config = _enabled_config(tmp_path)
    runner = get_sandbox_runner(config)
    assert isinstance(runner, WindowsSandboxRunner)


def test_linux_runner_disabled_raises(tmp_path: Path) -> None:
    """LinuxSandboxRunner refuses to run when sandbox_enabled is false."""
    config = _enabled_config(tmp_path)
    config.security.sandbox_enabled = False
    runner = LinuxSandboxRunner(config)
    with pytest.raises(SandboxError, match="disabled"):
        runner.run(["echo", "hello"])


def test_linux_runner_missing_bwrap_raises(tmp_path: Path) -> None:
    """LinuxSandboxRunner raises when bwrap is not on PATH."""
    config = _enabled_config(tmp_path)
    runner = LinuxSandboxRunner(config)
    with (
        patch("aegisvault.security.sandbox.shutil.which", return_value=None),
        pytest.raises(SandboxError, match="bubblewrap"),
    ):
        runner.run(["echo", "hello"])


def test_linux_runner_missing_executable_raises(tmp_path: Path) -> None:
    """LinuxSandboxRunner raises when the target executable is not found."""
    config = _enabled_config(tmp_path)
    runner = LinuxSandboxRunner(config)
    with (
        patch("aegisvault.security.sandbox.shutil.which", side_effect=["/bin/bwrap", None]),
        pytest.raises(SandboxError, match="not found"),
    ):
        runner.run(["definitely-not-real"])


def test_linux_runner_builds_expected_argv(tmp_path: Path) -> None:
    """The bwrap argument list contains the expected isolation flags."""
    config = _enabled_config(tmp_path)
    runner = LinuxSandboxRunner(config)
    argv = runner._build_bwrap_args(
        "/usr/bin/bwrap",
        ["/bin/echo", "hello"],
        tmp_path / "work",
        extra_readonly_paths=[tmp_path / "readonly"],
        extra_writable_paths=[tmp_path / "writable"],
        env_vars={"FOO": "bar"},
    )
    assert argv[0] == "/usr/bin/bwrap"
    assert "--unshare-net" in argv
    assert "--die-with-parent" in argv
    assert "--unshare-all" in argv
    assert "--ro-bind" in argv
    assert str(config.paths.vault) in argv
    assert "--setenv" in argv
    assert "FOO" in argv
    assert "/bin/echo" in argv
    assert "hello" in argv


def test_linux_runner_success_with_mocked_bwrap(tmp_path: Path) -> None:
    """A successful sandboxed command returns stdout from subprocess."""
    config = _enabled_config(tmp_path)
    runner = LinuxSandboxRunner(config)

    fake_result = subprocess.CompletedProcess(
        args=["bwrap"],
        returncode=0,
        stdout="hello\n",
        stderr="",
    )

    with (
        patch("aegisvault.security.sandbox.shutil.which", return_value="/bin/bwrap"),
        patch("aegisvault.security.sandbox.subprocess.run", return_value=fake_result) as mock_run,
    ):
        result = runner.run(["echo", "hello"])

    assert result.stdout == "hello\n"
    mock_run.assert_called_once()
    call_args = mock_run.call_args[0][0]
    assert call_args[0] == "/bin/bwrap"


def test_linux_runner_failure_raises_sandbox_error(tmp_path: Path) -> None:
    """A non-zero exit code from bwrap is converted to SandboxError."""
    config = _enabled_config(tmp_path)
    runner = LinuxSandboxRunner(config)

    fake_error = subprocess.CalledProcessError(
        returncode=1,
        cmd=["bwrap"],
        output="",
        stderr="permission denied\n",
    )

    with (
        patch("aegisvault.security.sandbox.shutil.which", return_value="/bin/bwrap"),
        patch("aegisvault.security.sandbox.subprocess.run", side_effect=fake_error),
        pytest.raises(SandboxError, match="permission denied"),
    ):
        runner.run(["some-command"])


def test_linux_runner_timeout_raises_sandbox_error(tmp_path: Path) -> None:
    """A subprocess timeout is converted to a clear SandboxError."""
    config = _enabled_config(tmp_path)
    runner = LinuxSandboxRunner(config)

    with (
        patch("aegisvault.security.sandbox.shutil.which", return_value="/bin/bwrap"),
        patch(
            "aegisvault.security.sandbox.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["bwrap"], timeout=5.0),
        ),
        pytest.raises(SandboxError, match="timed out"),
    ):
        runner.run(["sleep", "10"], timeout=5.0)


def test_windows_runner_disabled_raises_on_linux(tmp_path: Path) -> None:
    """WindowsSandboxRunner refuses to run when sandbox_enabled is false."""
    if sys.platform == "win32":
        pytest.skip("Uses mocked Windows APIs")
    config = _enabled_config(tmp_path)
    config.security.sandbox_enabled = False
    runner = WindowsSandboxRunner(config)
    with pytest.raises(SandboxError, match="disabled"):
        runner.run(["cmd", "/c", "echo hello"])


def test_windows_runner_missing_powershell_raises(tmp_path: Path) -> None:
    """WindowsSandboxRunner raises when PowerShell is not found."""
    if sys.platform == "win32":
        pytest.skip("Uses mocked Windows APIs")
    config = _enabled_config(tmp_path)
    runner = WindowsSandboxRunner(config)
    with (
        patch("aegisvault.security.sandbox.shutil.which", return_value=None),
        pytest.raises(SandboxError, match="PowerShell"),
    ):
        runner.run(["cmd", "/c", "echo hello"])


def test_windows_runner_builds_powershell_command(tmp_path: Path) -> None:
    """The Windows runner builds a PowerShell command containing key tokens."""
    if sys.platform == "win32":
        pytest.skip("Uses mocked Windows APIs")
    config = _enabled_config(tmp_path)
    runner = WindowsSandboxRunner(config)
    ps = runner._build_powershell_command(
        ["C:\\Windows\\System32\\cmd.exe", "/c", "echo hello"],
        tmp_path / "work",
        extra_readonly_paths=[tmp_path / "readonly"],
        extra_writable_paths=[tmp_path / "writable"],
        env_vars={"FOO": "bar"},
    )
    assert "New-AppContainerProfile" in ps
    assert "AegisVaultSandbox" in ps
    assert "Start-Process" in ps
    assert "cmd.exe" in ps
    assert "echo hello" in ps
    assert "$env:FOO = 'bar'" in ps


def test_windows_runner_success_with_mocked_powershell(tmp_path: Path) -> None:
    """A successful Windows sandbox run returns stdout from PowerShell."""
    if sys.platform == "win32":
        pytest.skip("Uses mocked Windows APIs")
    config = _enabled_config(tmp_path)
    runner = WindowsSandboxRunner(config)

    fake_result = subprocess.CompletedProcess(
        args=["powershell", "-Command", "..."],
        returncode=0,
        stdout="hello\n",
        stderr="",
    )

    with (
        patch("aegisvault.security.sandbox.shutil.which", return_value="/usr/bin/pwsh"),
        patch("aegisvault.security.sandbox.subprocess.run", return_value=fake_result) as mock_run,
    ):
        result = runner.run(["cmd", "/c", "echo hello"])

    assert result.stdout == "hello\n"
    mock_run.assert_called_once()
    call_args = mock_run.call_args[0][0]
    assert call_args[0] == "/usr/bin/pwsh"


def test_windows_runner_failure_raises_sandbox_error(tmp_path: Path) -> None:
    """A non-zero PowerShell exit code is converted to SandboxError."""
    if sys.platform == "win32":
        pytest.skip("Uses mocked Windows APIs")
    config = _enabled_config(tmp_path)
    runner = WindowsSandboxRunner(config)

    fake_result = subprocess.CompletedProcess(
        args=["powershell", "-Command", "..."],
        returncode=1,
        stdout="",
        stderr="access denied\n",
    )

    with (
        patch("aegisvault.security.sandbox.shutil.which", return_value="/usr/bin/pwsh"),
        patch("aegisvault.security.sandbox.subprocess.run", return_value=fake_result),
        pytest.raises(SandboxError, match="access denied"),
    ):
        runner.run(["cmd", "/c", "echo hello"])


def test_windows_runner_timeout_raises_sandbox_error(tmp_path: Path) -> None:
    """A Windows sandbox timeout is converted to a clear SandboxError."""
    if sys.platform == "win32":
        pytest.skip("Uses mocked Windows APIs")
    config = _enabled_config(tmp_path)
    runner = WindowsSandboxRunner(config)

    with (
        patch("aegisvault.security.sandbox.shutil.which", return_value="/usr/bin/pwsh"),
        patch(
            "aegisvault.security.sandbox.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["powershell"], timeout=2.0),
        ),
        pytest.raises(SandboxError, match="timed out"),
    ):
        runner.run(["cmd", "/c", "timeout 10"], timeout=2.0)
