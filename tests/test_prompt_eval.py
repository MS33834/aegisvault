"""Parameterized prompt-level evaluation for the classifier JSON extractor."""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aegisvault.api.schemas import ClassificationResult
from aegisvault.model import ModelProvider
from aegisvault.model.classifier import (
    CLASSIFICATION_PROMPT,
    Classifier,
    _extract_json,
    _normalize_classification_data,
)
from aegisvault.platform.manager import ConnectionManager
from aegisvault.platform.models import Connection, PlatformType


class FakeProvider(ModelProvider):
    """Fake model provider that always returns a fixed raw response."""

    def __init__(self, response: str) -> None:
        self.response = response

    async def chat_completion(self, messages: list[dict[str, Any]]) -> str:
        return self.response

    async def health(self) -> bool:
        return True

    async def close(self) -> None:
        pass


@pytest.fixture
def local_connection() -> Connection:
    """Trusted local connection for classifier construction."""
    return Connection(
        name="Local Test",
        platform_type=PlatformType.OLLAMA,
        base_url="http://127.0.0.1:11434/v1",
        is_local=True,
    )


def _load_samples() -> list[dict[str, Any]]:
    """Load prompt evaluation samples from the JSONL fixture."""
    fixture = Path(__file__).parent / "fixtures" / "prompt_eval_samples.jsonl"
    samples: list[dict[str, Any]] = []
    with fixture.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            samples.append(json.loads(line))
    return samples


@pytest.fixture(scope="session")
def eval_results() -> list[dict[str, Any]]:
    """Session-scoped collector for per-sample evaluation results."""
    return []


def summarize_prompt_eval_results(
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Print and return a summary of prompt evaluation results."""
    total = len(results)
    passed = sum(1 for result in results if result["passed"])
    pass_rate = passed / total if total else 0.0
    failures = [result for result in results if not result["passed"]]

    print(f"\nPrompt eval summary: {passed}/{total} passed ({pass_rate:.1%})")
    for failure in failures:
        print(f"  FAIL [{failure['id']}] " f"expected={failure['expected']} {failure['error']}")

    return {
        "total": total,
        "passed": passed,
        "pass_rate": pass_rate,
        "failures": failures,
    }


@pytest.mark.parametrize("sample", _load_samples(), ids=lambda s: s["id"])
async def test_prompt_eval_sample(
    sample: dict[str, Any],
    tmp_path: Path,
    local_connection: Connection,
    eval_results: list[dict[str, Any]],
) -> None:
    """Evaluate a single prompt sample against the extractor and classifier."""
    raw_output = sample["raw_output"]
    expected_outcome = sample["expected_outcome"]
    record: dict[str, Any] = {
        "id": sample["id"],
        "expected": expected_outcome,
        "passed": False,
        "error": None,
    }

    try:
        if expected_outcome == "success":
            data = _extract_json(raw_output)
            assert isinstance(data, dict)
            expected_fields = sample.get("expected_fields", {})
            for key in expected_fields:
                assert key in data

            source_path = tmp_path / "sample.txt"
            source_path.write_text("sample content")
            classifier = Classifier(FakeProvider(raw_output), local_connection)
            result = await classifier.classify(source_path)
            assert isinstance(result, ClassificationResult)
            for key, value in expected_fields.items():
                assert getattr(result, key) == value

        elif expected_outcome == "extract_success_schema_fail":
            data = _extract_json(raw_output)
            assert isinstance(data, dict)

            source_path = tmp_path / "sample.txt"
            source_path.write_text("sample content")
            classifier = Classifier(FakeProvider(raw_output), local_connection)
            with pytest.raises(ValidationError):
                await classifier.classify(source_path)

        elif expected_outcome == "extract_fail":
            with pytest.raises((ValueError, json.JSONDecodeError)):
                _extract_json(raw_output)

        else:
            pytest.fail(f"Unknown expected_outcome: {expected_outcome}")

        record["passed"] = True
    except Exception as exc:  # noqa: BLE001
        record["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        eval_results.append(record)


def test_prompt_eval_summary(
    eval_results: list[dict[str, Any]],
) -> None:
    """Report aggregated pass rate and failure details for prompt evaluation."""
    summary = summarize_prompt_eval_results(eval_results)
    assert summary["pass_rate"] == 1.0, summary["failures"]


@pytest.mark.parametrize(
    "raw_output,expected_field",
    [
        (
            '{"sensitivity": "medium", "category": "work", "tags": ["report"], '
            '"summary": "一份工作报告", "disguise_name": "zhongwen_wendang", '
            '"disguise_extension": "log"}',
            {"summary": "一份工作报告", "disguise_name": "zhongwen_wendang"},
        ),
        (
            "Some explanation first:\n\n"
            "```text\nnot the json you are looking for\n```\n\n"
            "```json\n"
            '{"sensitivity": "medium", "category": "work", "tags": ["report"], '
            '"summary": "A work report", "disguise_name": "team_building_2023", '
            '"disguise_extension": "log"}\n'
            "```",
            {"sensitivity": "medium", "disguise_extension": "log"},
        ),
        (
            "\ufeff\n"
            "```json\n"
            '{"sensitivity": "low", "category": "other", "tags": [], '
            '"summary": "BOM prefix test", "disguise_name": "bom_test", '
            '"disguise_extension": "txt"}\n'
            "```",
            {"summary": "BOM prefix test", "disguise_name": "bom_test"},
        ),
    ],
    ids=["chinese-filename", "multiple-code-blocks", "bom-prefix"],
)
def test_extract_json_new_samples(
    raw_output: str,
    expected_field: dict[str, Any],
) -> None:
    """Verify _extract_json handles Chinese content, multiple fences and BOM."""
    data = _extract_json(raw_output)
    assert isinstance(data, dict)
    for key, value in expected_field.items():
        assert data.get(key) == value


@pytest.mark.parametrize(
    "raw_output,expected_fields",
    [
        (
            '{"sensitivity": "high", "category": "finance", '
            '"tags": ["bank"], "summary": "A bank statement", '
            '"disguise_name": "statement", "disguise_extension": "csv",}',
            {"sensitivity": "high", "disguise_extension": "csv"},
        ),
        (
            '{"sensitivity": "low", /* category */ "category": "other", '
            '"tags": [], "summary": "comment test", '
            '"disguise_name": "comment_test", "disguise_extension": "txt"}',
            {"summary": "comment test", "disguise_name": "comment_test"},
        ),
        (
            "{'sensitivity': 'critical', 'category': 'health', 'tags': ['scan'], "
            "'summary': 'single quote test', 'disguise_name': 'health_scan', "
            "'disguise_extension': 'dat'}",
            {"sensitivity": "critical", "disguise_name": "health_scan"},
        ),
    ],
    ids=["trailing-comma", "block-comment", "single-quotes"],
)
def test_extract_json_repairs_common_model_mistakes(
    raw_output: str,
    expected_fields: dict[str, Any],
) -> None:
    """Verify _extract_json repairs trailing commas, comments and single quotes."""
    data = _extract_json(raw_output)
    assert isinstance(data, dict)
    for key, value in expected_fields.items():
        assert data.get(key) == value


def test_normalize_classification_data_defaults_and_case() -> None:
    """Normalization lowercases enums and backfills missing optional fields."""
    normalized = _normalize_classification_data(
        {
            "sensitivity": "  MEDIUM  ",
            "category": "WORK",
            "tags": None,
            "summary": None,
            "disguise_name": "  spaced_name  ",
            "disguise_extension": "  LOG  ",
        }
    )
    assert normalized["sensitivity"] == "medium"
    assert normalized["category"] == "work"
    assert normalized["tags"] == []
    assert normalized["summary"] == ""
    assert normalized["disguise_name"] == "spaced_name"
    assert normalized["disguise_extension"] == "LOG"


# ---------------------------------------------------------------------------
# Prompt stability evaluation framework
# ---------------------------------------------------------------------------

# Register new prompt variants here to measure their stability against the
# shared fixture suite. Each variant must accept {filename} and {size}.
PROMPT_VARIANTS: list[dict[str, Any]] = [
    {
        "id": "default",
        "template": CLASSIFICATION_PROMPT,
    },
    {
        "id": "concise",
        "template": (
            "Classify the file. Reply with ONLY valid JSON.\n\n"
            "Schema: sensitivity, category, tags, summary, disguise_name, "
            "disguise_extension.\n\n"
            "File: {filename}\nSize: {size}\n"
        ),
    },
    {
        "id": "structured",
        "template": (
            "You are AegisVault classifier. Return JSON only.\n"
            "Use this exact shape:\n"
            '{{"sensitivity": "...", "category": "...", "tags": [...], '
            '"summary": "...", "disguise_name": "...", "disguise_extension": "..."}}\n'
            "\nFile name: {filename}\nFile size: {size} bytes\n"
        ),
    },
]


async def _run_prompt_variant(
    variant: dict[str, Any],
    samples: list[dict[str, Any]],
    tmp_path: Path,
    local_connection: Connection,
) -> dict[str, Any]:
    """Run all samples through a single prompt variant and return metrics."""
    results: list[dict[str, Any]] = []
    for sample in samples:
        record: dict[str, Any] = {
            "sample_id": sample["id"],
            "passed": False,
            "error": None,
        }
        try:
            source_path = tmp_path / f"{sample['id']}.txt"
            source_path.write_text("sample content")
            classifier = Classifier(
                FakeProvider(sample["raw_output"]),
                local_connection,
                prompt_template=variant["template"],
            )
            if sample["expected_outcome"] == "success":
                result = await classifier.classify(source_path)
                assert isinstance(result, ClassificationResult)
                for key, value in sample.get("expected_fields", {}).items():
                    assert getattr(result, key) == value
            elif sample["expected_outcome"] == "extract_success_schema_fail":
                with pytest.raises(ValidationError):
                    await classifier.classify(source_path)
            elif sample["expected_outcome"] == "extract_fail":
                with pytest.raises((ValueError, json.JSONDecodeError)):
                    await classifier.classify(source_path)
            record["passed"] = True
        except Exception as exc:  # noqa: BLE001
            record["error"] = f"{type(exc).__name__}: {exc}"
        results.append(record)

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    return {
        "variant_id": variant["id"],
        "total": total,
        "passed": passed,
        "pass_rate": passed / total if total else 0.0,
        "failures": [r for r in results if not r["passed"]],
    }


@pytest.mark.parametrize("variant", PROMPT_VARIANTS, ids=lambda v: v["id"])
async def test_prompt_variant_stability(
    variant: dict[str, Any],
    tmp_path: Path,
    local_connection: Connection,
) -> None:
    """Each registered prompt variant must reach 100% stability on the suite."""
    samples = _load_samples()
    metrics = await _run_prompt_variant(variant, samples, tmp_path, local_connection)
    assert (
        metrics["pass_rate"] == 1.0
    ), f"Prompt variant {variant['id']!r} failed on: {metrics['failures']}"


# ---------------------------------------------------------------------------
# Classifier construction from ConnectionManager
# ---------------------------------------------------------------------------


def test_classifier_from_manager_prefers_trusted_local(
    tmp_path: Path,
) -> None:
    """from_manager selects the trusted local chat connection."""
    manager = ConnectionManager(tmp_path / "conn.json")
    # Wipe the default seeded connection to control the fixture.
    for conn in manager.list_all():
        manager.delete(conn.id)

    local = Connection(
        name="local",
        platform_type=PlatformType.OLLAMA,
        base_url="http://127.0.0.1:11434/v1",
        is_local=True,
        capabilities=["chat"],
    )
    cloud = Connection(
        name="cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
        is_cloud_authorized=True,
        capabilities=["chat"],
    )
    manager.add(local)
    manager.add(cloud)

    classifier = Classifier.from_manager(manager, allow_cloud_fallback=True)
    assert classifier.connection.id == local.id


def test_classifier_from_manager_cloud_fallback(
    tmp_path: Path,
) -> None:
    """from_manager falls back to authorized cloud when no local connection exists."""
    manager = ConnectionManager(tmp_path / "conn.json")
    for conn in manager.list_all():
        manager.delete(conn.id)

    cloud = Connection(
        name="cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
        is_cloud_authorized=True,
        capabilities=["chat"],
    )
    manager.add(cloud)

    classifier = Classifier.from_manager(manager, allow_cloud_fallback=True)
    assert classifier.connection.id == cloud.id


def test_classifier_from_manager_no_chat_connection_raises(
    tmp_path: Path,
) -> None:
    """from_manager raises RuntimeError when no suitable connection exists."""
    manager = ConnectionManager(tmp_path / "conn.json")
    for conn in manager.list_all():
        manager.delete(conn.id)

    no_chat = Connection(
        name="no-chat",
        platform_type=PlatformType.OLLAMA,
        base_url="http://127.0.0.1:11434/v1",
        capabilities=["embed"],
    )
    manager.add(no_chat)

    with pytest.raises(RuntimeError, match="No suitable chat connection"):
        Classifier.from_manager(manager)


def test_classifier_from_manager_cloud_not_authorized(
    tmp_path: Path,
) -> None:
    """Unauthorized cloud connections are ignored unless explicitly authorized."""
    manager = ConnectionManager(tmp_path / "conn.json")
    for conn in manager.list_all():
        manager.delete(conn.id)

    cloud = Connection(
        name="cloud",
        platform_type=PlatformType.OPENAI,
        base_url="https://api.openai.com/v1",
        is_local=False,
        is_cloud_authorized=False,
        capabilities=["chat"],
    )
    manager.add(cloud)

    with pytest.raises(RuntimeError, match="No suitable chat connection"):
        Classifier.from_manager(manager, allow_cloud_fallback=True)


async def test_classifier_uses_custom_prompt_template(
    tmp_path: Path,
    local_connection: Connection,
) -> None:
    """Classifier can be parameterized with a custom prompt template."""
    custom_prompt = "CUSTOM {filename} {size}"
    raw_output = (
        '{"sensitivity": "low", "category": "other", "tags": [], '
        '"summary": "custom prompt test", "disguise_name": "custom", '
        '"disguise_extension": "txt"}'
    )
    provider = FakeProvider(raw_output)
    classifier = Classifier(provider, local_connection, prompt_template=custom_prompt)

    source_path = tmp_path / "doc.txt"
    source_path.write_text("x")
    result = await classifier.classify(source_path)

    assert isinstance(result, ClassificationResult)
    assert result.summary == "custom prompt test"
