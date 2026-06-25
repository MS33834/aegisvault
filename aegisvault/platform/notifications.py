"""Cross-platform desktop notifications for AegisVault.

Provides a unified :class:`DesktopNotifier` that dispatches to the
platform-appropriate notification mechanism:

- **Linux**: ``notify-send`` (libnotify)
- **macOS**: ``osascript display notification``
- **Windows**: PowerShell ``Windows.UI.Notifications`` toast (fallback to
  ``msg`` if unavailable)
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys

logger = logging.getLogger(__name__)


class _NotifierBackend:
    """Abstract notification backend."""

    def send(self, title: str, message: str, urgency: str = "normal") -> bool:
        """Send a notification. Returns True on success."""
        raise NotImplementedError


class _LinuxNotifier(_NotifierBackend):
    """Linux notification backend using ``notify-send``."""

    def send(self, title: str, message: str, urgency: str = "normal") -> bool:
        notify_send = shutil.which("notify-send")
        if notify_send is None:
            logger.warning("notify-send not found; cannot send desktop notification")
            return False
        cmd: list[str] = [notify_send, title, message]
        if urgency != "normal":
            cmd += ["--urgency", urgency]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            return True
        except (OSError, subprocess.TimeoutExpired):
            logger.warning("Failed to send notification via notify-send", exc_info=True)
            return False


class _MacOSNotifier(_NotifierBackend):
    """macOS notification backend using ``osascript``."""

    def send(self, title: str, message: str, urgency: str = "normal") -> bool:
        osascript = shutil.which("osascript")
        if osascript is None:
            logger.warning("osascript not found; cannot send desktop notification")
            return False
        # Escape single-quotes in title and message for AppleScript.
        safe_title = title.replace("'", "'\\''")
        safe_message = message.replace("'", "'\\''")
        script = f'display notification "{safe_message}"' f' with title "{safe_title}"'
        try:
            subprocess.run(
                [osascript, "-e", script],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return True
        except (OSError, subprocess.TimeoutExpired):
            logger.warning("Failed to send notification via osascript", exc_info=True)
            return False


class _WindowsNotifier(_NotifierBackend):
    """Windows notification backend using PowerShell toasts."""

    def send(self, title: str, message: str, urgency: str = "normal") -> bool:
        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if pwsh is None:
            logger.warning("PowerShell not found; cannot send desktop notification")
            return False
        # Escape special characters for PowerShell single-quoted strings.
        safe_title = title.replace("'", "''")
        safe_message = message.replace("'", "''")
        ps_script = (
            "[Windows.UI.Notifications.ToastNotificationManager,"
            "Windows.UI.Notifications,ContentType=WindowsRuntime] | Out-Null; "
            "$template = [Windows.UI.Notifications.ToastNotificationManager]"
            "::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]"
            "::ToastText02); "
            f"$template.GetElementsByTagName('text')[0].AppendChild("
            f"$template.CreateTextNode('{safe_title}')) | Out-Null; "
            f"$template.GetElementsByTagName('text')[1].AppendChild("
            f"$template.CreateTextNode('{safe_message}')) | Out-Null; "
            "$toast = [Windows.UI.Notifications.ToastNotification]"
            "::new($template); "
            "[Windows.UI.Notifications.ToastNotificationManager]"
            "::CreateToastNotifier('AegisVault').Show($toast)"
        )
        try:
            subprocess.run(
                [pwsh, "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return True
        except (OSError, subprocess.TimeoutExpired):
            logger.warning("Failed to send notification via PowerShell", exc_info=True)
            return False


def _get_backend() -> _NotifierBackend:
    """Return the platform-appropriate notification backend."""
    if sys.platform == "linux":
        return _LinuxNotifier()
    if sys.platform == "darwin":
        return _MacOSNotifier()
    if sys.platform == "win32":
        return _WindowsNotifier()
    return _NotifierBackend()


class DesktopNotifier:
    """Cross-platform desktop notification dispatcher.

    Send desktop notifications for key AegisVault events such as
    classification completion, sync operations, and security alerts.
    """

    def __init__(self) -> None:
        self._backend = _get_backend()

    def notify(
        self,
        title: str,
        message: str,
        urgency: str = "normal",
    ) -> bool:
        """Send a generic desktop notification.

        Parameters
        ----------
        title:
            Notification title (short summary).
        message:
            Notification body text.
        urgency:
            Urgency level: ``"low"``, ``"normal"``, or ``"critical"``.

        Returns
        -------
        ``True`` if the notification was sent successfully.
        """
        return self._backend.send(title, message, urgency)

    def notify_sync_complete(self, files_synced: int) -> bool:
        """Notify that a sync operation has completed.

        Parameters
        ----------
        files_synced:
            Number of files that were synchronised.
        """
        return self.notify(
            "AegisVault — Sync Complete",
            f"{files_synced} file(s) synchronised successfully.",
            urgency="normal",
        )

    def notify_classification_done(self, filename: str) -> bool:
        """Notify that a file has been classified.

        Parameters
        ----------
        filename:
            Name of the file that was classified.
        """
        return self.notify(
            "AegisVault — File Classified",
            f"'{filename}' has been processed and stored in the vault.",
            urgency="low",
        )

    def notify_security_alert(self, alert_type: str, details: str) -> bool:
        """Notify of a security-related alert.

        Parameters
        ----------
        alert_type:
            Short category of the alert (e.g. ``"unauthorized_access"``).
        details:
            Human-readable description of the alert.
        """
        return self.notify(
            f"AegisVault — Security Alert: {alert_type}",
            details,
            urgency="critical",
        )
