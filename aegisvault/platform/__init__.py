"""Platform connection management layer."""

from aegisvault.platform.manager import ConnectionManager
from aegisvault.platform.models import AuthMethod, Connection, PlatformType
from aegisvault.platform.notifications import DesktopNotifier

__all__ = [
    "AuthMethod",
    "Connection",
    "ConnectionManager",
    "DesktopNotifier",
    "PlatformType",
]
