"""Parameterized prompt-level evaluation for the classifier JSON extractor."""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aegisvault.api.schemas import ClassificationResult
from aegisvault.model import ModelProvider
from aegisvault.model.classifier import Classifier, _extract_json
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
        print(
            f"  FAIL [{failure['id']}] "
            f"expected={failure['expected']} {failure['error']}"
        )

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
            for key, value in expected_fields.items():
                assert data.get(key) == value

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
