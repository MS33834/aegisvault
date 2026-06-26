"""Extension loading utilities for AegisVault."""

from aegisvault.extensions.registry import load_plugins, load_provider_plugins

__all__ = [
    "load_plugins",
    "load_provider_plugins",
]
