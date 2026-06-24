"""File classification using a local or cloud model.

Sensitive classification defaults to trusted local connections.
Cloud connections are only used as fallback when explicitly authorized.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from aegisvault.api.schemas import ClassificationResult, SensitivityLevel
from aegisvault.model import ModelProvider, create_provider
from aegisvault.platform.manager import ConnectionManager
from aegisvault.platform.models import Connection

_FENCE_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]*)\s*\n?(.*?)\n?```", re.DOTALL)


# ── Sensitive Keywords Table ────────────────────────────────────────────────

SENSITIVE_KEYWORDS: dict[str, list[str]] = {
    "identity": [
        "身份证",
        "护照",
        "passport",
        "ID card",
        "id_card",
        "idcard",
        "驾驶证",
        "户口本",
        "出生证明",
        "birth certificate",
        "social security",
        "ssn",
        "visa",
    ],
    "finance": [
        "银行",
        "bank",
        "invoice",
        "发票",
        "对账单",
        "statement",
        "税",
        "tax",
        "工资",
        "salary",
        "payroll",
        "receipt",
        "收据",
        "账单",
        "流水",
        "transaction",
    ],
    "legal": [
        "合同",
        "协议",
        "contract",
        "agreement",
        "判决",
        "起诉",
        "律师",
        "attorney",
        "court",
        "法院",
        "ndas",
        "license",
        "条款",
        "terms",
    ],
    "medical": [
        "病历",
        "处方",
        "诊断",
        "体检",
        "medical",
        "prescription",
        "diagnosis",
        "lab",
        "report",
        "检查报告",
        "化验",
    ],
    "credentials": [
        "密码",
        "password",
        "token",
        "密钥",
        "key",
        "secret",
        "credentials",
        "api_key",
        "apikey",
        "private key",
    ],
}

# Mapping from keyword category to ClassificationResult category.
_KEYWORD_CATEGORY_TO_CLASSIFICATION: dict[str, str] = {
    "identity": "identity",
    "finance": "finance",
    "legal": "legal",
    "medical": "health",
    "credentials": "credentials",
}

# Sensitivity level for high-confidence keyword matches.
_KEYWORD_SENSITIVITY: dict[str, SensitivityLevel] = {
    "identity": SensitivityLevel.CRITICAL,
    "finance": SensitivityLevel.HIGH,
    "legal": SensitivityLevel.HIGH,
    "medical": SensitivityLevel.HIGH,
    "credentials": SensitivityLevel.CRITICAL,
}

# Extensions that are unlikely to contain sensitive content (no LLM needed).
_BENIGN_EXTENSIONS: frozenset[str] = frozenset(
    {
        "log",
        "tmp",
        "cache",
        "json",
        "xml",
        "yaml",
        "yml",
        "lock",
        "pyc",
        "pyo",
        "class",
        "jar",
        "exe",
        "dll",
        "so",
        "dylib",
        "woff",
        "woff2",
        "ttf",
        "eot",
        "otf",
    }
)

# Extensions that are strong signals for text-based classified content.
_TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        "txt",
        "md",
        "csv",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "rtf",
        "odt",
        "ods",
        "odp",
    }
)

# Extensions for image/media files.
_IMAGE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "jpg",
        "jpeg",
        "png",
        "gif",
        "bmp",
        "webp",
        "svg",
        "tiff",
        "tif",
        "ico",
        "heic",
        "heif",
    }
)

_MEDIA_EXTENSIONS: frozenset[str] = frozenset(
    {
        "mp4",
        "mkv",
        "avi",
        "mov",
        "wmv",
        "flv",
        "webm",
        "mp3",
        "wav",
        "flac",
        "aac",
        "ogg",
        "wma",
    }
)


def _file_size_human(st_size: int) -> str:
    """Return a human-readable file size label."""
    if st_size < 1024:
        return "tiny"
    if st_size < 1024 * 1024:
        return "small"
    if st_size < 10 * 1024 * 1024:
        return "medium"
    return "large"


def _match_keywords(filename_lower: str) -> tuple[str | None, int]:
    """Search filename for sensitive keywords.

    Returns ``(category, score)`` where *score* is the number of matched
    keywords (higher = more confidence). Returns ``(None, 0)`` if no match.
    """
    best_category: str | None = None
    best_score = 0
    for category, keywords in SENSITIVE_KEYWORDS.items():
        score = 0
        for kw in keywords:
            if kw.lower() in filename_lower:
                score += 1
        if score > best_score:
            best_score = score
            best_category = category
    return best_category, best_score


def pre_classify(file_path: Path) -> dict[str, Any] | None:
    """Pre-classify a file using fast, local heuristics.

    This is a pre-processing step before LLM classification. It uses
    filename keywords, extension, and file-size metadata to produce a
    preliminary classification. When the heuristics are confident enough
    the caller can skip the LLM call entirely.

    Parameters
    ----------
    file_path:
        Path to the file on disk.

    Returns
    -------
    A dict suitable for constructing a ``ClassificationResult`` when the
    heuristics are confident, or ``None`` when LLM classification is needed.

    The returned dict always contains: ``sensitivity``, ``category``, ``tags``,
    ``summary``, ``disguise_name``, ``disguise_extension``.
    """
    filename = file_path.name
    filename_lower = filename.lower()
    extension = file_path.suffix.lower().lstrip(".") if file_path.suffix else ""

    try:
        file_size = file_path.stat().st_size
    except OSError:
        return None

    # ── Skip obviously benign files ──
    if extension in _BENIGN_EXTENSIONS and _match_keywords(filename_lower)[1] == 0:
        return {
            "sensitivity": SensitivityLevel.LOW.value,
            "category": "documents",
            "tags": ["auto-classified", "benign"],
            "summary": f"A {extension} file",
            "disguise_name": _generate_disguise_name(filename),
            "disguise_extension": "log",
        }

    size_label = _file_size_human(file_size)

    # ── Keyword matching ──
    kw_category, kw_score = _match_keywords(filename_lower)

    # Some categories have generic keywords — require higher confidence.
    min_conf: dict[str, int] = {"credentials": 2}

    if kw_category is not None and kw_score >= min_conf.get(kw_category, 1):
        category = _KEYWORD_CATEGORY_TO_CLASSIFICATION.get(kw_category, kw_category)
        sensitivity = _KEYWORD_SENSITIVITY.get(kw_category, SensitivityLevel.MEDIUM).value
        tags = [category, kw_category]
        summary = f"A {category} document"
        disguise_ext = _pick_disguise_extension(extension)

        return {
            "sensitivity": sensitivity,
            "category": category,
            "tags": tags,
            "summary": summary,
            "disguise_name": _generate_disguise_name(filename),
            "disguise_extension": disguise_ext,
        }

    # ── Media files: can often be classified without LLM ──
    if extension in _IMAGE_EXTENSIONS:
        return {
            "sensitivity": SensitivityLevel.LOW.value,
            "category": "media",
            "tags": ["photo", extension, size_label],
            "summary": f"A digital photograph ({size_label})",
            "disguise_name": _generate_disguise_name(filename),
            "disguise_extension": "dat",
        }

    if extension in _MEDIA_EXTENSIONS:
        return {
            "sensitivity": SensitivityLevel.LOW.value,
            "category": "media",
            "tags": ["media", extension, size_label],
            "summary": f"A media file ({size_label})",
            "disguise_name": _generate_disguise_name(filename),
            "disguise_extension": "bin",
        }

    # ── Not confident enough — LLM classification needed ──
    return None


def _generate_disguise_name(filename: str) -> str:
    """Generate a deterministic disguise name from the filename hash."""
    digest = hashlib.sha256(filename.lower().encode()).hexdigest()[:8]
    # Ensure it contains at least one digit.
    return f"file{digest}"


def _pick_disguise_extension(original_ext: str) -> str:
    """Pick a neutral disguise extension based on the original extension."""
    if original_ext.lower() in _TEXT_EXTENSIONS:
        return "csv"
    if original_ext.lower() in _IMAGE_EXTENSIONS or original_ext.lower() in _MEDIA_EXTENSIONS:
        return "dat"
    return "log"


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
Your task is to analyze file metadata and produce a structured classification.
Output ONLY a single valid JSON object — no markdown fences, no explanations, no text outside JSON.

All fields are required. The JSON schema:
{{
  "sensitivity": "low|medium|high|critical",
  "category": "identity|finance|legal|media|documents|work|health|other",
  "tags": ["tag1", "tag2", ...],
  "summary": "one generic sentence, no identifiers",
  "disguise_name": "neutral_lowercase_alphanumeric_no_extension",
  "disguise_extension": "log|txt|csv|dat|bin"
}}

---

## SENSITIVITY RULES

Critical — identity documents (ID cards, passports, driver's licenses, social security,
          birth certificates), bank account numbers, credit card data, cryptographic keys.
High     — legal contracts/agreements/NDAs, bank/financial statements,
          payment confirmations, medical diagnoses, insurance policies, tax filings.
Medium   — invoices, receipts, expense reports, lab results, HR correspondence, salary slips.
Low      — generic photos/images, personal notes, screenshots, drafts,
          reference documents, media files.

## CATEGORY RULES

identity  — National ID, passport, driver's license, visa, birth certificate,
            social security card. Look for identity document keywords in
            filename (e.g. "id_card", "passport", "身份证", "护照").
finance   — Bank statements, payment records, invoices, receipts, tax returns,
            expense sheets, credit reports. Look for financial keywords
            (e.g. "statement", "账单", "发票").
legal     — Contracts, agreements, NDAs, court documents, terms of service,
            employment contracts. Look for legal keywords
            (e.g. "contract", "合同", "agreement", "协议").
media     — Photos, screenshots, audio, video, GIFs, wallpapers.
            Typical image/video extensions.
documents — Generic documents: notes, reports, memos, study materials, drafts,
            spreadsheets with non-financial content.
            Default category when no strong signal exists.
work      — Resumes/CVs, cover letters, performance reviews, meeting minutes,
            business correspondence.
health    — Medical records, prescriptions, lab results, doctor's notes,
            vaccination records.
other     — Anything that does not fit the above categories.

When uncertain between two categories, choose the specific one over "other" or "documents".

## SUMMARY RULES

- Write exactly ONE sentence in plain language — never more.
- STRICTLY FORBIDDEN in summary: proper names, personal names, account numbers, ID numbers, dates,
  physical addresses, email addresses, phone numbers, company names, bank names.
- Replace sensitive specifics with generic descriptions:
  BAD  — "Bank of China statement for Zhang Wei, March 2025"
  GOOD — "A personal bank statement"
  BAD  — "John Smith's passport scan from London office"
  GOOD — "A passport identity document"
- If the file extension alone sufficiently describes content, use that:
  GOOD — "A digital photograph" (for .jpg/.png)
  GOOD — "A spreadsheet file" (for .xlsx with non-financial content)

## disguise_name RULES

Purpose: conceal the original file identity when stored in the Vault.
- Format: lowercase English letters (a-z) and digits (0-9) only.
- Length: strictly 8–16 characters.
- MUST contain at least one digit.
- MUST NOT contain any reference to original content, filename, category, or sensitivity.
- Generate unique-like patterns, for example: "file4a7f", "doc91x3m2", "rec5p9k", "item8b2n".
- Never reuse the original filename, even partially.

## disguise_extension RULES

- Choose ONE from: "log", "txt", "csv", "dat", "bin".
- Pick the most neutral option based on file type context:
  - Text/spreadsheet originals → "csv" or "txt"
  - Binary/image/PDF originals → "dat" or "bin"
  - Unknown type → "log"
- Must NOT match the original extension.

## TAGS RULES

- Provide 2–5 lowercase tags.
- Use general categories and formats, never specific identifiers.
- Examples:
  identity  → ["identity", "id-card"] or ["identity", "passport"]
  finance   → ["finance", "bank-statement"] or ["finance", "invoice"]
  legal     → ["legal", "contract"] or ["legal", "nda"]
  media     → ["photo", "screenshot"] or ["video", "recording"]
  documents → ["document", "note"] or ["document", "report"]

## FINAL CONSTRAINTS

- Output EXACTLY one JSON object, nothing else — no wrappers, no preambles.
- If the file purpose is truly uncertain: set sensitivity to "high" (err on the safe side),
  category to "other", and tags to ["unclassified"].
- Never invent details you cannot determine from the filename and size alone.

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
        # First pass: look for a trusted local connection.
        for candidate in manager.list_enabled():
            if "chat" not in candidate.capabilities:
                continue
            if candidate.is_trusted_local():
                return cls(create_provider(candidate), candidate)

        # Second pass: fall back to a cloud connection if allowed.
        if allow_cloud_fallback:
            for candidate in manager.list_enabled():
                if "chat" not in candidate.capabilities:
                    continue
                if candidate.is_cloud_authorized:
                    return cls(create_provider(candidate), candidate)

        raise RuntimeError(
            "No suitable chat connection found. "
            "Please configure a local model service or authorize a cloud connection."
        )

    async def classify(self, path: Path) -> ClassificationResult:
        """Classify a file by path.

        First attempts fast heuristic pre-classification. If the heuristics
        are confident enough the LLM call is skipped, reducing cost and latency.
        """
        # 1. Try heuristic pre-classification first.
        pre_result = pre_classify(path)
        if pre_result is not None:
            return ClassificationResult(**pre_result)

        # 2. Fall through to LLM classification.
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
