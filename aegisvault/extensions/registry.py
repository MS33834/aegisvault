"""Plugin registry and entry-point loading utilities."""

from collections.abc import Callable
from importlib.metadata import entry_points
from typing import Any


def load_plugins(group: str, register: Callable[[str, Any], None]) -> None:
    """Load entry points for *group* and invoke each with *register*.

    Each entry point is expected to be a no-argument callable that calls the
    provided ``register(name, factory)`` to register itself.
    """
    eps = entry_points()
    for ep in eps.select(group=group):
        plugin: Callable[[Callable[[str, Any], None]], None] = ep.load()
        plugin(register)


def load_provider_plugins() -> None:
    """Load provider plugins registered under ``aegisvault.providers``."""
    from aegisvault.model.provider import register_provider

    load_plugins("aegisvault.providers", register_provider)
