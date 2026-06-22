"""Windows Defender Firewall helpers for AegisVault network isolation.

On Windows 11 these functions generate and execute PowerShell commands that
block outbound traffic for the AegisVault core process.

On non-Windows platforms the functions raise RuntimeError if execution is
attempted, but command generation can still be unit-tested.
"""

import shutil
import subprocess
import sys
from pathlib import Path

RULE_NAME = "AegisVault-Core-Outbound-Block"
RULE_DISPLAY_NAME = "AegisVault Core Process Outbound Block"
RULE_DESCRIPTION = "Block all outbound traffic from the AegisVault core process."


def _require_windows() -> None:
    """Raise if not on Windows."""
    if sys.platform != "win32":
        raise RuntimeError("Firewall rules can only be applied on Windows")


def _powershell() -> str:
    """Return the PowerShell executable path."""
    pwsh = shutil.which("pwsh")
    if pwsh:
        return pwsh
    ps = shutil.which("powershell")
    if ps:
        return ps
    raise RuntimeError("PowerShell not found")


def build_block_rule_command(process_path: Path) -> str:
    """Build the New-NetFirewallRule command as a string."""
    path = str(process_path.resolve())
    return (
        f"New-NetFirewallRule "
        f"-Name '{RULE_NAME}' "
        f"-DisplayName '{RULE_DISPLAY_NAME}' "
        f"-Description '{RULE_DESCRIPTION}' "
        f"-Direction Outbound "
        f"-Program '{path}' "
        f"-Action Block "
        f"-Profile Any"
    )


def build_remove_rule_command() -> str:
    """Build the Remove-NetFirewallRule command as a string."""
    return f"Remove-NetFirewallRule -Name '{RULE_NAME}' -ErrorAction SilentlyContinue"


def build_rule_exists_command() -> str:
    """Build the Get-NetFirewallRule existence check command."""
    return f"Get-NetFirewallRule -Name '{RULE_NAME}' -ErrorAction SilentlyContinue"


def apply_block_rule(process_path: Path) -> None:
    """Apply the outbound block rule on Windows."""
    _require_windows()
    remove_block_rule()
    command = build_block_rule_command(process_path)
    subprocess.run(
        [_powershell(), "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )


def remove_block_rule() -> None:
    """Remove the outbound block rule if it exists."""
    _require_windows()
    command = build_remove_rule_command()
    subprocess.run(
        [_powershell(), "-Command", command],
        check=False,
        capture_output=True,
        text=True,
    )


def rule_exists() -> bool:
    """Check whether the AegisVault block rule exists."""
    _require_windows()
    command = build_rule_exists_command()
    result = subprocess.run(
        [_powershell(), "-Command", command],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and RULE_NAME in result.stdout
