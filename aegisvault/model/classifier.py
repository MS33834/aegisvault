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


def _remove_comments(text: str) -> str:
    """Remove C/JS style comments without touching quotes."""
    result: list[str] = []
    i = 0
    length = len(text)
    in_string: str | None = None
    while i < length:
        char = text[i]
        if in_string is None:
            if char in {'"', "'"}:
                in_string = char
                result.append(char)
            elif char == "/" and i + 1 < length:
                if text[i + 1] == "/":
                    while i < length and text[i] != "\n":
                        i += 1
                    continue
                if text[i + 1] == "*":
                    i += 2
                    while i + 1 < length and not (text[i] == "*" and text[i + 1] == "/"):
                        i += 1
                    i += 2
                    continue
                result.append(char)
            else:
                result.append(char)
        else:
            if char == "\\" and i + 1 < length:
                result.append(char)
                result.append(text[i + 1])
                i += 2
                continue
            if char == in_string:
                in_string = None
            result.append(char)
        i += 1
    return "".join(result)


def _remove_trailing_commas(text: str) -> str:
    """Remove trailing commas before closing braces/brackets."""
    return re.sub(r",(\s*[}\]])", r"\1", text)


def _looks_single_quoted(text: str) -> bool:
    """Heuristic: text uses single quotes as JSON delimiters."""
    stripped = text.strip()
    return stripped.startswith("{") and "'" in stripped and '"' not in stripped


def _repair_json(text: str) -> str:
    """Apply safe repairs to common model JSON mistakes.

    Repairs include: comments, trailing commas, and single-quoted dicts.
    """
    cleaned = _remove_comments(text)
    cleaned = _remove_trailing_commas(cleaned)
    if _looks_single_quoted(cleaned):
        cleaned = cleaned.replace("'", '"')
    return cleaned


def _try_load_json(text: str) -> dict[str, Any] | None:
    """Try parsing JSON, including a repair pass for malformed output."""
    for candidate in (text, _repair_json(text)):
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return data
    return None


def _extract_json(raw: str) -> dict[str, Any]:
    """Extract JSON object from model output, tolerating markdown fences and surrounding prose.

    Prefers fenced code blocks that parse to a dict containing required
    classification fields. Falls back to the full output and finally to the
    first '{' ... '}' substring. A repair pass fixes common model mistakes
    such as comments, trailing commas, and single quotes.
    """
    cleaned = raw.lstrip("\ufeff").strip()

    # 1. Try fenced code blocks anywhere in the output. Prefer the block with
    # the most required fields to avoid picking up incidental JSON snippets.
    best_block: dict[str, Any] | None = None
    best_score = -1
    for match in _FENCE_RE.finditer(cleaned):
        candidate = match.group(1).strip()
        data = _try_load_json(candidate)
        if data is not None:
            score = len(_REQUIRED_FIELDS & data.keys())
            if score > best_score:
                best_score = score
                best_block = data
    if best_block is not None:
        return best_block

    # 2. Try the cleaned output as-is (with repair fallback).
    data = _try_load_json(cleaned)
    if data is not None:
        return data

    # 3. Fall back to the first '{' and last '}'.
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        snippet = raw[:500]
        raise ValueError(f"No valid JSON object found in model output: {snippet!r}")
    data = _try_load_json(cleaned[start : end + 1])
    if data is not None:
        return data

    snippet = raw[:500]
    raise ValueError(f"Failed to parse JSON from model output: {snippet!r}")


def _normalize_classification_data(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize extracted classification data before schema validation.

    Handles missing optional fields and common formatting inconsistencies.
    """
    normalized = dict(data)
    if isinstance(normalized.get("sensitivity"), str):
        normalized["sensitivity"] = normalized["sensitivity"].strip().lower()
    if normalized.get("category") and isinstance(normalized.get("category"), str):
        normalized["category"] = normalized["category"].strip().lower()
    if normalized.get("tags") is None:
        normalized["tags"] = []
    if normalized.get("summary") is None:
        normalized["summary"] = ""
    if isinstance(normalized.get("disguise_name"), str):
        normalized["disguise_name"] = normalized["disguise_name"].strip()
    if isinstance(normalized.get("disguise_extension"), str):
        normalized["disguise_extension"] = normalized["disguise_extension"].strip()
    return normalized


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

    def __init__(
        self,
        provider: ModelProvider,
        connection: Connection,
        prompt_template: str = CLASSIFICATION_PROMPT,
    ) -> None:
        self.provider = provider
        self.connection = connection
        self.prompt_template = prompt_template

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
        prompt = self.prompt_template.format(
            filename=path.name,
            size=path.stat().st_size,
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "You are a helpful, precise classifier."},
            {"role": "user", "content": prompt},
        ]
        raw = await self.provider.chat_completion(messages)
        data = _normalize_classification_data(_extract_json(raw))
        return ClassificationResult(**data)
