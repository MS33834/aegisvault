"""Model capability layer."""

from aegisvault.model.classifier import Classifier
from aegisvault.model.embedding import LocalEmbeddingProvider
from aegisvault.model.provider import (
    BUILT_IN_PROVIDER_NAMES,
    ModelProvider,
    OpenAICompatibleProvider,
    create_provider,
    register_provider,
)

__all__ = [
    "BUILT_IN_PROVIDER_NAMES",
    "Classifier",
    "LocalEmbeddingProvider",
    "ModelProvider",
    "OpenAICompatibleProvider",
    "create_provider",
    "register_provider",
]

for _provider_name in BUILT_IN_PROVIDER_NAMES:
    register_provider(_provider_name, OpenAICompatibleProvider)

del _provider_name
