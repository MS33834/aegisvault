"""Model capability layer."""

from aegisvault.model.provider import (
    ModelProvider,
    OpenAICompatibleProvider,
    create_provider,
    register_provider,
)

__all__ = [
    "ModelProvider",
    "OpenAICompatibleProvider",
    "create_provider",
    "register_provider",
]

_BUILT_IN_PROVIDERS = (
    "ollama",
    "lm_studio",
    "llamacpp_server",
    "openai_compatible",
    "openai",
)

for _provider_name in _BUILT_IN_PROVIDERS:
    register_provider(_provider_name, OpenAICompatibleProvider)

del _provider_name, _BUILT_IN_PROVIDERS
