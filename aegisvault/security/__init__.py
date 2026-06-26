"""Security service layer."""

from aegisvault.security.audit_log import ALLOWED_EVENT_TYPES, AuditLogger
from aegisvault.security.crypto import decrypt_file_stream, encrypt_file_stream
from aegisvault.security.keytree import derive_file_key, derive_vault_key, generate_salt
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
from aegisvault.security.policy import (
    SecurityPolicyError,
    require_trusted_local_connection,
    sensitive_operation,
)
from aegisvault.security.sandbox import (
    LinuxSandboxRunner,
    SandboxError,
    WindowsSandboxRunner,
    get_sandbox_runner,
)
from aegisvault.security.windows_hello import (
    WindowsHelloError,
    get_key_derivation_salt,
    verify_user_identity,
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
    "SecurityPolicyError",
    "TpmMasterKeyProvider",
    "WindowsHelloError",
    "WindowsSandboxRunner",
    "auto_detect",
    "create_master_key_provider",
    "create_password_store",
    "decrypt_file_stream",
    "derive_file_key",
    "derive_vault_key",
    "emergency_rotate",
    "encrypt_file_stream",
    "generate_salt",
    "get_key_derivation_salt",
    "get_sandbox_runner",
    "require_trusted_local_connection",
    "rotate_master_key",
    "sensitive_operation",
    "should_rotate_key",
    "verify_user_identity",
]
