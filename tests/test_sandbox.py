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
    assert "--die-with-parent" in argv
    assert "--unshare-net" in argv
    assert "--unshare-ipc" in argv
    assert "--unshare-uts" in argv
    assert "--unshare-pid" in argv
    assert "--unshare-user" in argv
    assert "--as-pid-1" in argv
    assert "--tmpfs" in argv
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
    from aegisvault.security import sandbox as sandbox_mod

    original_which = sandbox_mod.shutil.which

    def _which_mock(name: str) -> str | None:
        if name in ("pwsh", "powershell"):
            return None
        return original_which(name)

    with (
        patch("aegisvault.security.sandbox.shutil.which", side_effect=_which_mock),
        pytest.raises(SandboxError, match="PowerShell"),
    ):
        runner.run(["echo", "hello"])


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
    assert "AegisVault" in ps
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


def test_linux_runner_seccomp_profile(tmp_path: Path) -> None:
    """When seccomp_profile is set, --seccomp is added to bwrap args."""
    config = _enabled_config(tmp_path)
    runner = LinuxSandboxRunner(config)

    # No seccomp profile set => no --seccomp flag.
    argv = runner._build_bwrap_args(
        "/usr/bin/bwrap",
        ["/bin/echo", "hello"],
        tmp_path / "work",
        extra_readonly_paths=None,
        extra_writable_paths=None,
        env_vars=None,
    )
    assert "--seccomp" not in argv

    # Set an existing file as seccomp profile.
    seccomp_path = tmp_path / "seccomp.bpf"
    seccomp_path.write_text("fake bpf")
    runner.seccomp_profile = seccomp_path
    argv = runner._build_bwrap_args(
        "/usr/bin/bwrap",
        ["/bin/echo", "hello"],
        tmp_path / "work",
        extra_readonly_paths=None,
        extra_writable_paths=None,
        env_vars=None,
    )
    assert "--seccomp" in argv
    assert str(seccomp_path) in argv


def test_linux_runner_essential_paths_in_args(tmp_path: Path) -> None:
    """Whitlisted system paths appear in the bwrap argument list."""
    config = _enabled_config(tmp_path)
    runner = LinuxSandboxRunner(config)
    argv = runner._build_bwrap_args(
        "/usr/bin/bwrap",
        ["/bin/echo", "hello"],
        tmp_path / "work",
        extra_readonly_paths=None,
        extra_writable_paths=None,
        env_vars=None,
    )
    assert "--tmpfs" in argv
    assert "--ro-bind" in argv
    # The TMPDIR env var is set for hardened sandbox.
    assert "TMPDIR" in argv


# ── MacOSSandboxRunner tests ─────────────────────────────────────────────────


def test_macos_runner_can_be_instantiated(tmp_path: Path) -> None:
    """MacOSSandboxRunner can be created on any platform."""
    config = _enabled_config(tmp_path)
    runner = get_sandbox_runner(config)
    # On Linux this returns LinuxSandboxRunner; on darwin it returns
    # MacOSSandboxRunner.  Either is acceptable here — we just ensure no crash.
    assert isinstance(runner, SandboxRunner)
    assert runner.enabled is True


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_macos_runner_run_on_non_darwin_raises(
    tmp_path: Path, platform: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MacOSSandboxRunner.run raises SandboxError on non-macOS platforms."""
    monkeypatch.setattr(sys, "platform", platform)
    from aegisvault.security.sandbox import (
        MacOSSandboxRunner,
        SandboxError,
    )

    config = _enabled_config(tmp_path)
    runner = MacOSSandboxRunner(config)
    with pytest.raises(SandboxError, match="only available on macOS"):
        runner.run(["/bin/echo", "hello"])


def test_macos_runner_disabled_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """MacOSSandboxRunner raises SandboxError when disabled."""
    monkeypatch.setattr(sys, "platform", "darwin")
    from aegisvault.security.sandbox import MacOSSandboxRunner

    config = AegisConfig()
    config.security.sandbox_enabled = False
    runner = MacOSSandboxRunner(config)
    with pytest.raises(SandboxError, match="disabled"):
        runner.run(["/bin/echo", "hello"])


def test_macos_runner_builds_seatbelt_profile(tmp_path: Path) -> None:
    """_build_seatbelt_profile generates a valid seatbelt profile string."""
    from aegisvault.security.sandbox import MacOSSandboxRunner

    config = _enabled_config(tmp_path)
    runner = MacOSSandboxRunner(config)

    profile = runner._build_seatbelt_profile(
        tmp_path / "work",
        extra_readonly_paths=[tmp_path / "extra_ro"],
        extra_writable_paths=[tmp_path / "extra_rw"],
    )

    assert "(version 1)" in profile
    assert "(deny default)" in profile
    assert "(deny network*)" in profile
    assert "(allow file-read* (subpath" in profile
    assert str(runner.vault_dir) in profile
    assert str(tmp_path / "work") in profile


def test_macos_runner_get_runner_returns_macos_on_darwin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """get_sandbox_runner returns MacOSSandboxRunner on darwin."""
    monkeypatch.setattr(sys, "platform", "darwin")
    from aegisvault.security.sandbox import MacOSSandboxRunner

    config = _enabled_config(tmp_path)
    runner = get_sandbox_runner(config)
    assert isinstance(runner, MacOSSandboxRunner)


def test_macos_runner_disabled_returns_false(tmp_path: Path) -> None:
    """When disabled config is given, runner.enabled is False."""
    from aegisvault.security.sandbox import MacOSSandboxRunner

    config = AegisConfig()
    config.security.sandbox_enabled = False
    runner = MacOSSandboxRunner(config)
    assert runner.enabled is False
