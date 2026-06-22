"""Security policy for sensitive operations.

Sensitive tasks (Vault encryption/decryption, password fill, key derivation)
must use a connection that is local and bound to 127.0.0.1/localhost.
"""

from collections.abc import Callable
from functools import wraps
from typing import TypeVar

from aegisvault.platform.models import Connection


class SecurityPolicyError(Exception):
    """Raised when a sensitive operation violates the security policy."""


F = TypeVar("F", bound=Callable[..., object])


def require_trusted_local_connection(connection: Connection) -> None:
    """Validate that a connection is trusted local for sensitive tasks."""
    if not connection.is_trusted_local():
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
        conn: Connection | None = None
        for arg in args:
            if isinstance(arg, Connection):
                conn = arg
                break
        if conn is None:
            maybe_conn = kwargs.get("connection")
            if isinstance(maybe_conn, Connection):
                conn = maybe_conn
        if not isinstance(conn, Connection):
            raise SecurityPolicyError(
                "Sensitive operation requires a Connection argument"
            )
        require_trusted_local_connection(conn)
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]
