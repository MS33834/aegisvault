"""Tests for classification result schema."""

from aegisvault.api.schemas import ClassificationResult, SensitivityLevel


def test_classification_result_defaults() -> None:
    """ClassificationResult requires mandatory fields."""
    result = ClassificationResult(
        sensitivity=SensitivityLevel.HIGH,
        category="finance",
        disguise_name="2023_report",
        disguise_extension="log",
    )
    assert result.sensitivity == SensitivityLevel.HIGH
    assert result.tags == []
    assert result.summary == ""
