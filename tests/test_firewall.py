"""Tests for Windows firewall command generation."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aegisvault.security import firewall


def test_block_command_contains_required_parts() -> None:
    """Generated block command includes name, direction, program, action."""
    cmd = firewall.build_block_rule_command(Path("/tmp/aegisvault"))
    assert firewall.RULE_NAME in cmd
    assert "Outbound" in cmd
    assert "/tmp/aegisvault" in cmd
    assert "Block" in cmd
    assert "-Enabled True" in cmd
    assert "-PolicyStore ActiveStore" in cmd


def test_block_command_escapes_single_quotes() -> None:
    """Single quotes in the process path are escaped to prevent command injection."""
    cmd = firewall.build_block_rule_command(Path(r"C:\Aegis'Vault\aegisvault.exe"))
    assert "Aegis''Vault" in cmd
    assert "';" not in cmd


def test_remove_command_contains_rule_name() -> None:
    """Generated remove command references the rule name."""
    cmd = firewall.build_remove_rule_command()
    assert firewall.RULE_NAME in cmd


def test_exists_command_contains_rule_name() -> None:
    """Generated existence check command references the rule name."""
    cmd = firewall.build_rule_exists_command()
    assert firewall.RULE_NAME in cmd
    assert "Get-NetFirewallRule" in cmd


def test_execution_raises_on_non_windows() -> None:
    """Applying rules on non-Windows raises RuntimeError."""
    with pytest.raises(RuntimeError):
        firewall.apply_block_rule(Path("/tmp/aegisvault"))


def test_remove_rule_raises_on_non_windows() -> None:
    """Removing rules on non-Windows raises RuntimeError."""
    with pytest.raises(RuntimeError):
        firewall.remove_block_rule()


def test_rule_exists_raises_on_non_windows() -> None:
    """Checking rule existence on non-Windows raises RuntimeError."""
    with pytest.raises(RuntimeError):
        firewall.rule_exists()


def test_powershell_prefers_pwsh(monkeypatch: pytest.MonkeyPatch) -> None:
    """_powershell returns pwsh when available."""
    monkeypatch.setattr(
        "aegisvault.security.firewall.shutil.which",
        lambda cmd: "/usr/bin/pwsh" if cmd == "pwsh" else None,
    )
    assert firewall._powershell() == "/usr/bin/pwsh"


def test_powershell_falls_back_to_powershell(monkeypatch: pytest.MonkeyPatch) -> None:
    """_powershell falls back to powershell when pwsh is unavailable."""

    def which(cmd: str) -> str | None:
        return "/usr/bin/powershell" if cmd == "powershell" else None

    monkeypatch.setattr("aegisvault.security.firewall.shutil.which", which)
    assert firewall._powershell() == "/usr/bin/powershell"


def test_powershell_raises_when_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """_powershell raises RuntimeError if neither PowerShell executable exists."""
    monkeypatch.setattr("aegisvault.security.firewall.shutil.which", lambda _cmd: None)
    with pytest.raises(RuntimeError, match="PowerShell not found"):
        firewall._powershell()


def test_apply_block_rule_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """apply_block_rule removes an existing rule then creates a new one on Windows."""
    monkeypatch.setattr("aegisvault.security.win_helpers.sys.platform", "win32")
    mock_run = MagicMock()
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = firewall.RULE_NAME
    monkeypatch.setattr("aegisvault.security.firewall.subprocess.run", mock_run)
    monkeypatch.setattr("aegisvault.security.firewall.shutil.which", lambda _cmd: "powershell")

    firewall.apply_block_rule(Path("/tmp/aegisvault"))

    # remove_block_rule + apply_block_rule = 2 subprocess calls.
    assert mock_run.call_count == 2
    args = mock_run.call_args_list[1][0][0]
    assert args[0] == "powershell"
    assert "New-NetFirewallRule" in args[2]


def test_remove_block_rule_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """remove_block_rule runs the removal command on Windows."""
    monkeypatch.setattr("aegisvault.security.win_helpers.sys.platform", "win32")
    mock_run = MagicMock()
    mock_run.return_value.returncode = 0
    monkeypatch.setattr("aegisvault.security.firewall.subprocess.run", mock_run)
    monkeypatch.setattr("aegisvault.security.firewall.shutil.which", lambda _cmd: "powershell")

    firewall.remove_block_rule()

    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert "Remove-NetFirewallRule" in args[2]


def test_rule_exists_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """rule_exists parses the PowerShell output on Windows."""
    monkeypatch.setattr("aegisvault.security.win_helpers.sys.platform", "win32")
    mock_run = MagicMock()
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = firewall.RULE_NAME
    monkeypatch.setattr("aegisvault.security.firewall.subprocess.run", mock_run)
    monkeypatch.setattr("aegisvault.security.firewall.shutil.which", lambda _cmd: "powershell")

    assert firewall.rule_exists() is True


def test_rule_exists_false_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """rule_exists returns False when the rule name is absent from output."""
    monkeypatch.setattr("aegisvault.security.win_helpers.sys.platform", "win32")
    mock_run = MagicMock()
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = "Other-Rule"
    monkeypatch.setattr("aegisvault.security.firewall.subprocess.run", mock_run)
    monkeypatch.setattr("aegisvault.security.firewall.shutil.which", lambda _cmd: "powershell")

    assert firewall.rule_exists() is False
