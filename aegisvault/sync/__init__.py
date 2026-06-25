"""AegisVault multi-device sync package.

Exports
-------
SyncMessage, SyncState, FileIndex, SecureSyncProtocol (from protocol)
DeviceDiscovery, UdpDiscovery (from discovery)
DeviceAuth (from auth)
SyncEngine, FileIndex (from engine)
Conflict, ConflictDetector, ConflictResolver, LastWriteWins, KeepBoth,
ManualResolve, CRDTMerge (from conflict)
"""

from aegisvault.sync.auth import DeviceAuth
from aegisvault.sync.conflict import (
    Conflict,
    ConflictDetector,
    ConflictResolver,
    CRDTMerge,
    KeepBoth,
    LastWriteWins,
    ManualResolve,
)
from aegisvault.sync.discovery import DeviceDiscovery, UdpDiscovery
from aegisvault.sync.engine import SyncEngine
from aegisvault.sync.protocol import FileIndex, SecureSyncProtocol, SyncMessage, SyncState

__all__ = [
    # protocol
    "SyncMessage",
    "SyncState",
    "FileIndex",
    "SecureSyncProtocol",
    # discovery
    "DeviceDiscovery",
    "UdpDiscovery",
    # auth
    "DeviceAuth",
    # engine
    "SyncEngine",
    # conflict
    "Conflict",
    "ConflictDetector",
    "ConflictResolver",
    "LastWriteWins",
    "KeepBoth",
    "ManualResolve",
    "CRDTMerge",
]
