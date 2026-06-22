"""Security policy for sensitive operations.

Sensitive tasks (Vault encryption/decryption, password fill, key derivation)
must use a connection that is local and bound to 127.0.0.1/localhost.
"""

from collections.abc import Callable
from functools import wraps
from typing import TypeVar

from aegisvault.platform.models import Connection
from aegisvault.security.audit_log import AuditLogger


class SecurityPolicyError(Exception):
    """Raised when a sensitive operation violates the security policy."""


F = TypeVar("F", bound=Callable[..., object])


def require_trusted_local_connection(
    connection: Connection,
    audit_logger: AuditLogger | None = None,
    operation: str = "sensitive_operation",
) -> None:
    """Validate that a connection is trusted local for sensitive tasks."""
    if not connection.is_trusted_local():
        if audit_logger is not None:
            audit_logger.log(
                "policy_violation",
                {
                    "connection_id": str(connection.id),
                    "connection_name": connection.name,
                    "base_url": connection.base_url,
                    "operation": operation,
                },
            )
        raise SecurityPolicyError(
            f"Connection '{connection.name}' ({connection.base_url}) is not a "
            "trusted local connection. Sensitive tasks require 127.0.0.1 or localhost."
        )


def sensitive_operation(func: F) -> F:
    """Decorator marking a function as sensitive.

    Inspects positional and keyword arguments for a Connection instance and
    validates that it is trusted local before executing the wrapped function.
    """

    @wraps(func)
    def wrapper(*args: object, **kwargs: object) -> object:
        conns: list[Connection] = [arg for arg in args if isinstance(arg, Connection)] + [
            v for v in kwargs.values() if isinstance(v, Connection)
        ]
        if not conns:
            raise SecurityPolicyError("Sensitive operation requires a Connection argument")

        audit_logger: AuditLogger | None = None
        for arg in args:
            if isinstance(arg, AuditLogger):
                audit_logger = arg
                break
        if audit_logger is None:
            for value in kwargs.values():
                if isinstance(value, AuditLogger):
                    audit_logger = value
                    break

        for conn in conns:
            require_trusted_local_connection(
                conn,
                audit_logger=audit_logger,
                operation=func.__name__,
            )
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]
