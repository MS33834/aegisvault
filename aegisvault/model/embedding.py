"""Local embedding model provider abstraction.

The core package does not depend on ``sentence-transformers``. Install the
``[semantic]`` extra to use the default local model implementation.
"""

from __future__ import annotations

import hashlib
import logging
import math
import random
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class LocalEmbeddingProvider(ABC):
    """Abstract local embedding provider."""

    @abstractmethod
    def embed(self, texts: list[str]) -> list[list[float]]:
        """Return one dense vector for each input text."""


class SentenceTransformersProvider(LocalEmbeddingProvider):
    """sentence-transformers backed embedding provider.

    The external dependency is imported lazily inside ``__init__`` so that the
    class can be imported without ``sentence-transformers`` installed.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self.model_name = model_name
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "sentence-transformers is not installed. "
                "Install it with: pip install aegisvault[semantic]"
            ) from exc
        try:
            self._model: Any = SentenceTransformer(model_name)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load embedding model {model_name!r}. "
                "Ensure the model is downloaded or network is available."
            ) from exc

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Encode texts using the loaded sentence-transformers model."""
        if not texts:
            return []
        embeddings: Any = self._model.encode(texts, show_progress_bar=False)
        if hasattr(embeddings, "tolist"):
            result: list[list[float]] = embeddings.tolist()
        else:
            result = embeddings
        return result


class DeterministicEmbeddingProvider(LocalEmbeddingProvider):
    """Deterministic embedding provider for tests and offline fallback demos.

    Vectors are produced from the SHA-256 hash of the input text and are
    normalized to unit length. They are *not* semantically meaningful.
    """

    def __init__(self, dimension: int = 384, seed: int = 0) -> None:
        self.dimension = dimension
        self.seed = seed

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Return deterministic pseudo-random unit vectors for the texts."""
        return [self._vector_for_text(text) for text in texts]

    def _vector_for_text(self, text: str) -> list[float]:
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        rng = random.Random(f"{self.seed}:{digest}")
        vector = [rng.random() for _ in range(self.dimension)]
        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0:
            return vector
        return [value / norm for value in vector]
