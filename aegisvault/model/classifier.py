"""File classification using a local or cloud model.

Sensitive classification defaults to trusted local connections.
Cloud connections are only used as fallback when explicitly authorized.
"""

import json
import re
from pathlib import Path
from typing import Any

from aegisvault.api.schemas import ClassificationResult
from aegisvault.model import ModelProvider, create_provider
from aegisvault.platform.manager import ConnectionManager
from aegisvault.platform.models import Connection

_FENCE_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]*)\s*\n?(.*?)\n?```", re.DOTALL)


_REQUIRED_FIELDS = frozenset(
    {"sensitivity", "category", "tags", "summary", "disguise_name", "disguise_extension"}
)


def _extract_json(raw: str) -> dict[str, Any]:
    """Extract JSON object from model output, tolerating markdown fences and surrounding prose.

    Prefers fenced code blocks that parse to a dict containing required
    classification fields. Falls back to the full output and finally to the
    first '{' ... '}' substring.
    """
    cleaned = raw.lstrip("\ufeff").strip()

    # 1. Try fenced code blocks anywhere in the output. Prefer the block with
    # the most required fields to avoid picking up incidental JSON snippets.
    best_block: dict[str, Any] | None = None
    best_score = -1
    for match in _FENCE_RE.finditer(cleaned):
        candidate = match.group(1).strip()
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            score = len(_REQUIRED_FIELDS & data.keys())
            if score > best_score:
                best_score = score
                best_block = data
    if best_block is not None:
        return best_block

    # 2. Try the cleaned output as-is.
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        # 3. Fall back to the first '{' and last '}'.
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end == -1 or end <= start:
            snippet = raw[:500]
            raise ValueError(
                f"No valid JSON object found in model output: {snippet!r}"
            ) from exc
        try:
            data = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError as inner:
            snippet = raw[:500]
            raise ValueError(
                f"Failed to parse JSON from model output: {snippet!r}"
            ) from inner

    if not isinstance(data, dict):
        snippet = raw[:500]
        raise ValueError(f"Model output did not contain a JSON object: {snippet!r}")
    return data


CLASSIFICATION_PROMPT = """You are a private content classifier for AegisVault.
Analyze the following file metadata and output ONLY a single valid JSON object.
Do not include markdown code fences, explanations, or any text outside the JSON.

Required JSON schema (all fields are required):
{{
  "sensitivity": "low|medium|high|critical",
  "category": "finance|identity|media|work|health|other",
  "tags": ["tag1", "tag2"],
  "summary": "One sentence summary, sanitized to remove names/accounts/dates",
  "disguise_name": "neutral_filename_without_extension",
  "disguise_extension": "log|txt|csv|dat"
}}

Guidelines:
- If classification is uncertain, choose the safest (most sensitive) option.
- Keep the summary generic and avoid reproducing sensitive identifiers.
- disguise_name and disguise_extension will be used to store the file securely.

File name: {filename}
File size: {size} bytes
"""


class Classifier:
    """Classify files using a managed model connection."""

    def __init__(self, provider: ModelProvider, connection: Connection) -> None:
        self.provider = provider
        self.connection = connection

    @classmethod
    def from_manager(
        cls,
        manager: ConnectionManager,
        *,
        allow_cloud_fallback: bool = False,
    ) -> "Classifier":
        """Create a classifier from the connection manager.

        Prefers trusted local connections. Only uses cloud connections when
        allow_cloud_fallback is True and the connection is explicitly authorized.
        """
        conn: Connection | None = None
        for candidate in manager.list_enabled():
            if "chat" not in candidate.capabilities:
                continue
            if candidate.is_trusted_local():
                conn = candidate
                break
            if allow_cloud_fallback and candidate.is_cloud_authorized:
                conn = candidate
                break

        if conn is None:
            raise RuntimeError(
                "No suitable chat connection found. "
                "Please configure a local model service or authorize a cloud connection."
            )
        return cls(create_provider(conn), conn)

    async def classify(self, path: Path) -> ClassificationResult:
        """Classify a file by path."""
        prompt = CLASSIFICATION_PROMPT.format(
            filename=path.name,
            size=path.stat().st_size,
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "You are a helpful, precise classifier."},
            {"role": "user", "content": prompt},
        ]
        raw = await self.provider.chat_completion(messages)
        data = _extract_json(raw)
        return ClassificationResult(**data)
