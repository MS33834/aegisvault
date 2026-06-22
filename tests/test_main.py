"""Tests for the CLI entry point."""

from unittest.mock import patch

from aegisvault.__main__ import main


def test_main_prints_and_returns_zero() -> None:
    """main() prints a startup message and returns success."""
    with patch("aegisvault.__main__.print") as mock_print:
        result = main()
    assert result == 0
    mock_print.assert_called_once_with("AegisVault is starting...")
