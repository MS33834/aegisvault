"""Tests for cross-platform desktop notifications."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aegisvault.platform.notifications import (
    DesktopNotifier,
    _LinuxNotifier,
    _MacOSNotifier,
    _WindowsNotifier,
)


def test_desktop_notifier_creates_correct_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DesktopNotifier selects the correct platform backend."""
    monkeypatch.setattr(sys, "platform", "linux")
    notifier = DesktopNotifier()
    assert isinstance(notifier._backend, _LinuxNotifier)

    monkeypatch.setattr(sys, "platform", "darwin")
    notifier = DesktopNotifier()
    assert isinstance(notifier._backend, _MacOSNotifier)

    monkeypatch.setattr(sys, "platform", "win32")
    notifier = DesktopNotifier()
    assert isinstance(notifier._backend, _WindowsNotifier)


def test_linux_notifier_no_notify_send(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux notifier returns False when notify-send is missing."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("shutil.which", lambda x: None)
    backend = _LinuxNotifier()
    assert backend.send("title", "message") is False


def test_linux_notifier_send_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux notifier calls notify-send correctly."""
    monkeypatch.setattr(sys, "platform", "linux")

    calls: list[list[str]] = []

    class FakeRunResult:
        returncode = 0

    def fake_run(cmd: list[str], **kwargs: object) -> "FakeRunResult":
        calls.append(cmd)
        return FakeRunResult()

    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/notify-send")
    monkeypatch.setattr("subprocess.run", fake_run)
    backend = _LinuxNotifier()
    assert backend.send("Test Title", "Test Message") is True
    assert len(calls) == 1
    assert calls[0][0] == "/usr/bin/notify-send"
    assert calls[0][1] == "Test Title"
    assert calls[0][2] == "Test Message"


def test_linux_notifier_send_with_urgency(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux notifier passes --urgency flag when non-normal."""
    monkeypatch.setattr(sys, "platform", "linux")

    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/notify-send")
    monkeypatch.setattr("subprocess.run", fake_run)
    backend = _LinuxNotifier()
    assert backend.send("Title", "Msg", urgency="critical") is True
    assert "--urgency" in calls[0]
    assert "critical" in calls[0]


def test_linux_notifier_send_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux notifier returns False on OSError."""
    monkeypatch.setattr(sys, "platform", "linux")

    def fake_run(cmd: list[str], **kwargs: object) -> None:
        raise OSError("cannot execute")

    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/notify-send")
    monkeypatch.setattr("subprocess.run", fake_run)
    backend = _LinuxNotifier()
    assert backend.send("Title", "Msg") is False


def test_macos_notifier_no_osascript(monkeypatch: pytest.MonkeyPatch) -> None:
    """macOS notifier returns False when osascript is missing."""
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr("shutil.which", lambda x: None)
    backend = _MacOSNotifier()
    assert backend.send("title", "message") is False


def test_macos_notifier_send_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """macOS notifier calls osascript with display notification command."""
    monkeypatch.setattr(sys, "platform", "darwin")

    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/osascript")
    monkeypatch.setattr("subprocess.run", fake_run)
    backend = _MacOSNotifier()
    assert backend.send("Test Title", "Test Message") is True
    assert len(calls) == 1
    assert calls[0][0] == "/usr/bin/osascript"
    assert "display notification" in calls[0][2]
    assert "Test Title" in calls[0][2]
    assert "Test Message" in calls[0][2]


def test_macos_notifier_escapes_quotes(monkeypatch: pytest.MonkeyPatch) -> None:
    """macOS notifier escapes single-quotes in title and message."""
    monkeypatch.setattr(sys, "platform", "darwin")

    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/osascript")
    monkeypatch.setattr("subprocess.run", fake_run)
    backend = _MacOSNotifier()
    assert backend.send("Ti'tle", "Mes'sage") is True
    # Should NOT contain raw single-quotes in the display notification string.
    script = calls[0][2]
    assert "Ti'tle" not in script
    assert "Mes'sage" not in script


def test_windows_notifier_no_powershell(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows notifier returns False when PowerShell is missing."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr("shutil.which", lambda x: None)
    backend = _WindowsNotifier()
    assert backend.send("title", "message") is False


def test_windows_notifier_send_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows notifier calls PowerShell with toast script."""
    monkeypatch.setattr(sys, "platform", "win32")

    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr("shutil.which", lambda x: "pwsh")
    monkeypatch.setattr("subprocess.run", fake_run)
    backend = _WindowsNotifier()
    assert backend.send("Test Title", "Test Message") is True
    assert len(calls) == 1
    assert calls[0][0] == "pwsh"
    assert "-Command" in calls[0]
    assert "ToastNotification" in calls[0][2]


def test_desktop_notifier_convenience_methods(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Convenience methods delegate to notify with correct parameters."""
    monkeypatch.setattr(sys, "platform", "linux")

    calls: list[tuple[str, str, str]] = []

    class FakeBackend:
        def send(self, title: str, message: str, urgency: str = "normal") -> bool:
            calls.append((title, message, urgency))
            return True

    notifier = DesktopNotifier()
    notifier._backend = FakeBackend()  # type: ignore[assignment]

    assert notifier.notify_sync_complete(5) is True
    assert calls[-1][0] == "AegisVault — Sync Complete"
    assert "5" in calls[-1][1]
    assert calls[-1][2] == "normal"

    assert notifier.notify_classification_done("report.pdf") is True
    assert calls[-1][0] == "AegisVault — File Classified"
    assert "report.pdf" in calls[-1][1]
    assert calls[-1][2] == "low"

    assert (
        notifier.notify_security_alert("unauthorized_access", "Someone tried to open vault") is True
    )
    assert "unauthorized_access" in calls[-1][0]
    assert "Someone tried to open vault" in calls[-1][1]
    assert calls[-1][2] == "critical"


def test_desktop_notifier_notify_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    """DesktopNotifier.notify delegates to the backend."""
    monkeypatch.setattr(sys, "platform", "linux")

    calls: list[tuple[str, str, str]] = []

    class FakeBackend:
        def send(self, title: str, message: str, urgency: str = "normal") -> bool:
            calls.append((title, message, urgency))
            return True

    notifier = DesktopNotifier()
    notifier._backend = FakeBackend()  # type: ignore[assignment]
    assert notifier.notify("Hi", "World", urgency="low") is True
    assert calls == [("Hi", "World", "low")]


def test_agent_receives_notifier(monkeypatch: pytest.MonkeyPatch) -> None:
    """AegisAgent accepts an optional notifier parameter."""
    from aegisvault.config import AegisConfig
    from aegisvault.orchestration.agent import AegisAgent

    config = AegisConfig()
    # Avoid actual classification network call.
    config.paths.index.mkdir(parents=True, exist_ok=True)

    mock_key = MagicMock()
    mock_key.get_key.return_value = b"\x00" * 32

    mock_notifier = MagicMock()
    agent = AegisAgent(config, notifier=mock_notifier, master_key_provider=mock_key)
    assert agent._notifier is mock_notifier


def test_agent_sends_classification_notification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Agent notifies on successful file classification."""
    import asyncio
    from uuid import uuid4

    from aegisvault.api.schemas import FileEvent, TaskStatus
    from aegisvault.config import AegisConfig
    from aegisvault.orchestration.agent import AegisAgent

    config = AegisConfig()
    config.paths.inbox = tmp_path / "Inbox"
    config.paths.vault = tmp_path / "Vault"
    config.paths.index = tmp_path / "Index"
    for p in [config.paths.inbox, config.paths.vault, config.paths.index]:
        p.mkdir(parents=True, exist_ok=True)

    notifier = MagicMock()

    mock_key = MagicMock()
    mock_key.get_key.return_value = b"\x00" * 32

    agent = AegisAgent(config, notifier=notifier, master_key_provider=mock_key)

    async def fake_process(event: FileEvent) -> TaskStatus:
        return TaskStatus(task_id=event.event_id, state="completed")

    monkeypatch.setattr(agent, "on_file_event", fake_process)

    event = FileEvent(
        event_id=uuid4(),
        source_path=Path("/tmp/test.pdf"),
    )

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(agent._handle_event(event))
    finally:
        loop.close()

    notifier.notify_classification_done.assert_called_once_with("test.pdf")


def test_agent_sends_failure_notification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Agent sends security alert notification on processing failure."""
    import asyncio
    from uuid import uuid4

    from aegisvault.api.schemas import FileEvent
    from aegisvault.config import AegisConfig
    from aegisvault.orchestration.agent import AegisAgent

    config = AegisConfig()
    config.paths.inbox = tmp_path / "Inbox"
    config.paths.vault = tmp_path / "Vault"
    config.paths.index = tmp_path / "Index"
    for p in [config.paths.inbox, config.paths.vault, config.paths.index]:
        p.mkdir(parents=True, exist_ok=True)

    notifier = MagicMock()

    mock_key = MagicMock()
    mock_key.get_key.return_value = b"\x00" * 32

    agent = AegisAgent(config, notifier=notifier, master_key_provider=mock_key)

    async def fake_process(event: FileEvent) -> None:
        raise ValueError("simulated failure")

    monkeypatch.setattr(agent, "on_file_event", fake_process)

    event = FileEvent(
        event_id=uuid4(),
        source_path=Path("/tmp/bad_file.txt"),
    )

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(agent._handle_event(event))
    finally:
        loop.close()

    notifier.notify_security_alert.assert_called_once()
    call_args = notifier.notify_security_alert.call_args
    assert call_args[0][0] == "processing_failure"
    assert "bad_file.txt" in call_args[0][1]
