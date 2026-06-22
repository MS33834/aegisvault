"""Tests for Windows firewall command generation."""

from pathlib import Path

import pytest

from aegisvault.security import firewall


def test_block_command_contains_required_parts() -> None:
    """Generated block command includes name, direction, program, action."""
    cmd = firewall.build_block_rule_command(Path(r"C:\AegisVault\aegisvault.exe"))
    assert firewall.RULE_NAME in cmd
    assert "Outbound" in cmd
    assert "C:\\AegisVault\\aegisvault.exe" in cmd
    assert "Block" in cmd


def test_remove_command_contains_rule_name() -> None:
    """Generated remove command references the rule name."""
    cmd = firewall.build_remove_rule_command()
    assert firewall.RULE_NAME in cmd


def test_execution_raises_on_non_windows() -> None:
    """Applying rules on non-Windows raises RuntimeError."""
    with pytest.raises(RuntimeError):
        firewall.apply_block_rule(Path("/tmp/aegisvault"))
