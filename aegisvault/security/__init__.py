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
    KeePassXCRetriever,
    KeePassXCStore,
    PassRetriever,
    PassStore,
    PasswordStore,
    PasswordStoreError,
    SecretEntry,
    SecretRetriever,
    auto_detect,
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
    "KeePassXCRetriever",
    "KeePassXCStore",
    "LinuxSandboxRunner",
    "MasterKeyProvider",
    "PassRetriever",
    "PassStore",
    "PasswordStore",
    "PasswordStoreError",
    "SandboxError",
    "SecretEntry",
    "SecretRetriever",
    "TpmMasterKeyProvider",
    "WindowsSandboxRunner",
    "auto_detect",
    "create_master_key_provider",
    "create_password_store",
    "emergency_rotate",
    "get_sandbox_runner",
    "rotate_master_key",
    "should_rotate_key",
]
