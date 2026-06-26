"""Security policy for sensitive operations.

Sensitive tasks (Vault encryption/decryption, password fill, key derivation)
must use a connection that is local and bound to 127.0.0.1/localhost unless the
operator has explicitly enabled cloud fallback and marked the connection as
authorised.
"""

from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from typing import TypeVar

from aegisvault.config import AegisConfig
from aegisvault.connections.models import Connection
from aegisvault.security.audit_log import AuditLogger


class SecurityPolicyError(Exception):
    """Raised when a sensitive operation violates the security policy."""


F = TypeVar("F", bound=Callable[..., object])
T = TypeVar("T")


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


@dataclass
class SensitiveContext:
    """Runtime context for evaluating sensitive-operation policy."""

    connection: Connection
    config: AegisConfig
    audit_logger: AuditLogger | None = None
    operation: str = "sensitive_operation"


def enforce_sensitive_policy(ctx: SensitiveContext) -> None:
    """Validate *ctx* against the full sensitive-operation policy.

    Trusted local connections pass by default. When
    ``config.security.enforce_offline_policy`` is enabled, the current process
    must also have no active outbound client connections.

    Non-local connections are allowed only when cloud fallback is enabled
    globally and the connection itself is marked ``is_cloud_authorized``.
    """
    conn = ctx.connection
    cfg = ctx.config
    audit = ctx.audit_logger
    operation = ctx.operation

    if conn.is_trusted_local():
        if cfg.security.enforce_offline_policy:
            from aegisvault.security.offline import has_outbound_connection

            if has_outbound_connection():
                if audit is not None:
                    audit.log(
                        "offline_policy_violation",
                        {
                            "connection_id": str(conn.id),
                            "connection_name": conn.name,
                            "base_url": conn.base_url,
                            "operation": operation,
                        },
                    )
                raise SecurityPolicyError(
                    f"Operation '{operation}' requires an offline environment but "
                    "active outbound connections were detected."
                )
        return

    if cfg.security.cloud_fallback_enabled and conn.is_cloud_authorized:
        if audit is not None:
            audit.log(
                "cloud_fallback_used",
                {
                    "connection_id": str(conn.id),
                    "connection_name": conn.name,
                    "base_url": conn.base_url,
                    "operation": operation,
                },
            )
        return

    if audit is not None:
        audit.log(
            "policy_violation",
            {
                "connection_id": str(conn.id),
                "connection_name": conn.name,
                "base_url": conn.base_url,
                "operation": operation,
            },
        )
    raise SecurityPolicyError(
        f"Connection '{conn.name}' ({conn.base_url}) is not a trusted local "
        "connection and cloud fallback is not authorised for this operation."
    )


def _find_arg(
    args: tuple[object, ...],
    kwargs: dict[str, object],
    cls: type[T],
) -> T | None:
    """Return the first instance of *cls* found in positional/keyword args."""
    for arg in args:
        if isinstance(arg, cls):
            return arg
    for value in kwargs.values():
        if isinstance(value, cls):
            return value
    return None


def sensitive_operation(func: F) -> F:
    """Decorator marking a function as sensitive.

    Inspects positional and keyword arguments for a Connection instance and
    validates that it is trusted local before executing the wrapped function.

    If an :class:`AegisConfig` instance is also present, the richer policy
    implemented by :func:`enforce_sensitive_policy` is used instead, which can
    enforce offline-only execution and authorised cloud fallback.
    """

    @wraps(func)
    def wrapper(*args: object, **kwargs: object) -> object:
        conns: list[Connection] = [arg for arg in args if isinstance(arg, Connection)] + [
            v for v in kwargs.values() if isinstance(v, Connection)
        ]
        if not conns:
            raise SecurityPolicyError("Sensitive operation requires a Connection argument")

        audit_logger = _find_arg(args, kwargs, AuditLogger)
        config = _find_arg(args, kwargs, AegisConfig)

        if config is not None:
            for conn in conns:
                enforce_sensitive_policy(
                    SensitiveContext(
                        connection=conn,
                        config=config,
                        audit_logger=audit_logger,
                        operation=func.__name__,
                    )
                )
        else:
            for conn in conns:
                require_trusted_local_connection(
                    conn,
                    audit_logger=audit_logger,
                    operation=func.__name__,
                )
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]
