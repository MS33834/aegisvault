"""OpenAI-compatible model provider abstraction."""

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any, cast

import httpx

from aegisvault.platform.models import AuthMethod, Connection

logger = logging.getLogger(__name__)


def _build_headers(connection: Connection) -> dict[str, str]:
    """Build HTTP headers from connection auth config."""
    headers: dict[str, str] = {}
    headers.update(connection.custom_headers)

    if connection.auth_method == AuthMethod.BEARER and connection.api_key:
        headers["Authorization"] = f"Bearer {connection.api_key}"
    elif connection.auth_method == AuthMethod.API_KEY and connection.api_key:
        headers["Authorization"] = connection.api_key

    return headers


class ModelProvider(ABC):
    """Abstract model provider."""

    @abstractmethod
    async def chat_completion(self, messages: list[dict[str, Any]]) -> str:
        """Return assistant message content as string."""

    @abstractmethod
    async def health(self) -> bool:
        """Check if provider is reachable."""

    @abstractmethod
    async def close(self) -> None:
        """Close underlying resources."""


class OpenAICompatibleProvider(ModelProvider):
    """Provider for LM Studio / Ollama / OpenAI / custom endpoints."""

    def __init__(
        self,
        connection: Connection,
        temperature: float = 0.3,
    ) -> None:
        self.connection = connection
        self.temperature = temperature
        auth = (
            httpx.BasicAuth(connection.username, connection.password)
            if (
                connection.auth_method == AuthMethod.BASIC
                and connection.username
                and connection.password
            )
            else None
        )
        self.client = httpx.AsyncClient(
            base_url=connection.base_url,
            timeout=connection.timeout,
            headers=_build_headers(connection),
            auth=auth,
        )

    async def chat_completion(self, messages: list[dict[str, Any]]) -> str:
        """Call /v1/chat/completions."""
        payload = {
            "model": self.connection.model_name,
            "messages": messages,
            "temperature": self.temperature,
        }
        payload.update(self.connection.custom_payload)
        response = await self.client.post("/v1/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()
        return cast(str, data["choices"][0]["message"]["content"])

    async def health(self) -> bool:
        """Check provider health."""
        try:
            response = await self.client.get("/v1/models")
            response.raise_for_status()
            return True
        except Exception:  # noqa: BLE001
            return False

    async def close(self) -> None:
        """Close underlying HTTP client."""
        await self.client.aclose()


_PROVIDER_REGISTRY: dict[str, Callable[[Connection], ModelProvider]] = {}
_PLUGINS_LOADED: bool = False


BUILT_IN_PROVIDER_NAMES: tuple[str, ...] = (
    "openai_compatible",
    "ollama",
    "lm_studio",
    "llamacpp_server",
    "openai",
    "anthropic",
    "custom",
)


def register_provider(
    name: str,
    factory: Callable[[Connection], ModelProvider],
    *,
    allow_override: bool = False,
) -> None:
    """Register a model provider factory under *name*.

    By default overriding an existing registration raises ValueError to
    prevent accidental clobbering of built-in providers by third-party
    plugins. Set *allow_override* to True to replace an existing entry.
    """
    if name in _PROVIDER_REGISTRY and not allow_override:
        raise ValueError(
            f"Provider {name!r} is already registered. "
            "Use allow_override=True to replace it explicitly."
        )
    _PROVIDER_REGISTRY[name] = factory


def _load_built_in_providers() -> None:
    """Register built-in providers lazily."""
    if "openai_compatible" in _PROVIDER_REGISTRY:
        return
    for name in BUILT_IN_PROVIDER_NAMES:
        register_provider(name, OpenAICompatibleProvider)


def _load_provider_plugins() -> None:
    """Load third-party provider plugins once."""
    global _PLUGINS_LOADED
    if _PLUGINS_LOADED:
        return
    _PLUGINS_LOADED = True
    try:
        from aegisvault.extensions.registry import load_provider_plugins

        load_provider_plugins()
    except Exception:  # noqa: BLE001
        logger.warning("Failed to load provider plugins", exc_info=True)


def create_provider(connection: Connection) -> ModelProvider:
    """Factory to create a provider from a connection."""
    _load_built_in_providers()
    _load_provider_plugins()

    factory = _PROVIDER_REGISTRY.get(connection.platform_type.value)
    if factory is None:
        raise ValueError(
            f"Unsupported platform type: {connection.platform_type.value!r}. "
            f"Registered providers: {sorted(_PROVIDER_REGISTRY)}"
        )
    return factory(connection)
