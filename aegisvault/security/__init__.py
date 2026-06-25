"""Security service layer."""

from aegisvault.security.audit_log import ALLOWED_EVENT_TYPES, AuditLogger
from aegisvault.security.master_key import (
    DpapiMasterKeyProvider,
    FilePasswordProvider,
    MasterKeyProvider,
    TpmMasterKeyProvider,
    create_master_key_provider,
    emergency_rotate,
    rotate_master_key,
    should_rotate_key,
)
from aegisvault.security.password_store import (
    KeePassXCStore,
    PassStore,
    PasswordStore,
    PasswordStoreError,
    create_password_store,
)
from aegisvault.security.sandbox import (
    LinuxSandboxRunner,
    SandboxError,
    WindowsSandboxRunner,
    get_sandbox_runner,
)

__all__ = [
    "ALLOWED_EVENT_TYPES",
    "AuditLogger",
    "DpapiMasterKeyProvider",
    "FilePasswordProvider",
    "KeePassXCStore",
    "LinuxSandboxRunner",
    "MasterKeyProvider",
    "PassStore",
    "PasswordStore",
    "PasswordStoreError",
    "SandboxError",
    "TpmMasterKeyProvider",
    "WindowsSandboxRunner",
    "create_master_key_provider",
    "create_password_store",
    "emergency_rotate",
    "get_sandbox_runner",
    "rotate_master_key",
    "should_rotate_key",
]
