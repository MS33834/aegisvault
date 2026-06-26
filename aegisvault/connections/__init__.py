"""Platform connection management layer."""

from aegisvault.connections.manager import ConnectionManager
from aegisvault.connections.models import AuthMethod, Connection, PlatformType
from aegisvault.connections.notifications import DesktopNotifier

__all__ = [
    "AuthMethod",
    "Connection",
    "ConnectionManager",
    "DesktopNotifier",
    "PlatformType",
]
