"""Plugin registry and entry-point loading utilities."""

from collections.abc import Callable
from importlib.metadata import entry_points
from typing import Any


def load_plugins(group: str, register: Callable[[str, Any], None]) -> None:
    """Load entry points for *group* and invoke each with *register*.

    Each entry point is expected to be a no-argument callable that calls the
    provided ``register(name, factory)`` to register itself.
    """
    import logging

    logger = logging.getLogger(__name__)
    eps = entry_points()
    for ep in eps.select(group=group):
        try:
            plugin: Callable[[Callable[[str, Any], None]], None] = ep.load()
            plugin(register)
        except Exception:
            logger.warning("Failed to load plugin %s", ep.name, exc_info=True)


def load_provider_plugins() -> None:
    """Load provider plugins registered under ``aegisvault.providers``."""
    from aegisvault.model.provider import register_provider

    load_plugins("aegisvault.providers", register_provider)
