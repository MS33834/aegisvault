"""Tests for the CLI entry point."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from aegisvault.__main__ import (
    _create_tray_app,
    build_config,
    main,
    parse_args,
    run_headless,
    run_with_tray,
)
from tests.presentation_stubs import (
    FakeApplication,
    install_presentation_stubs,
    restore_modules,
)


def test_parse_args_defaults() -> None:
    """Default arguments leave the tray enabled and paths unset."""
    args = parse_args([])
    assert args.no_tray is False
    assert args.inbox is None
    assert args.vault is None
    assert args.index is None
    assert args.connections is None
    assert args.debug is False


def test_parse_args_no_tray() -> None:
    """--no-tray disables the system tray UI."""
    args = parse_args(["--no-tray"])
    assert args.no_tray is True


def test_parse_args_paths() -> None:
    """Path overrides are parsed as Paths."""
    args = parse_args(
        [
            "--inbox",
            "/tmp/inbox",
            "--vault",
            "/tmp/vault",
            "--index",
            "/tmp/index",
            "--connections",
            "/tmp/conn.json",
            "--debug",
        ]
    )
    assert args.inbox == Path("/tmp/inbox")
    assert args.vault == Path("/tmp/vault")
    assert args.index == Path("/tmp/index")
    assert args.connections == Path("/tmp/conn.json")
    assert args.debug is True


def test_build_config_applies_overrides(tmp_path: Path) -> None:
    """build_config applies CLI path overrides to AegisConfig."""
    args = parse_args(
        [
            "--inbox",
            str(tmp_path / "Inbox"),
            "--vault",
            str(tmp_path / "Vault"),
            "--index",
            str(tmp_path / "Index"),
            "--connections",
            str(tmp_path / "conn.json"),
        ]
    )
    config = build_config(args)
    assert config.paths.inbox == tmp_path / "Inbox"
    assert config.paths.vault == tmp_path / "Vault"
    assert config.paths.index == tmp_path / "Index"
    assert config.paths.connections == tmp_path / "conn.json"


def test_main_prints_and_returns_zero() -> None:
    """main() prints a startup message and returns success in headless mode."""
    with (
        patch("aegisvault.__main__.run_headless") as mock_run,
        patch("aegisvault.__main__.AegisAgent") as mock_agent_cls,
    ):
        mock_agent = MagicMock()
        mock_agent_cls.return_value = mock_agent
        result = main(["--no-tray"])

    assert result == 0
    mock_run.assert_called_once_with(mock_agent)


def test_main_falls_back_to_headless_without_qt() -> None:
    """main() falls back to headless mode when Qt is unavailable."""
    with patch("aegisvault.__main__._create_tray_app", side_effect=ImportError("no Qt")):
        with (
            patch("aegisvault.__main__.run_headless") as mock_run,
            patch("aegisvault.__main__.AegisAgent") as mock_agent_cls,
        ):
            mock_agent = MagicMock()
            mock_agent_cls.return_value = mock_agent
            result = main([])

    assert result == 0
    mock_run.assert_called_once_with(mock_agent)


def test_run_headless_starts_monitoring() -> None:
    """run_headless starts the Inbox watcher on an asyncio loop."""
    agent = MagicMock()
    with patch("aegisvault.__main__.asyncio") as mock_asyncio:
        mock_loop = MagicMock()
        mock_loop.is_running.return_value = True
        mock_asyncio.new_event_loop.return_value = mock_loop
        mock_asyncio.sleep = MagicMock(return_value=None)

        def stop_loop(*_args: object, **_kwargs: object) -> None:
            agent.stop_monitoring.side_effect = None
            # Simulate one iteration then KeyboardInterrupt on second call.
            if mock_loop.run_until_complete.call_count >= 2:
                raise KeyboardInterrupt

        mock_loop.run_until_complete.side_effect = stop_loop
        run_headless(agent)

    agent.start_monitoring.assert_called_once()
    agent.stop_monitoring.assert_called_once()
    mock_loop.call_soon.assert_called_once_with(mock_loop.stop)


def test_create_tray_app_returns_tray_instance(tmp_path: Path) -> None:
    """_create_tray_app returns a TrayApplication configured for the given config."""
    from aegisvault.config import AegisConfig

    saved = install_presentation_stubs()
    FakeApplication._instance = None
    try:
        from aegisvault.presentation.tray import TrayApplication

        config = AegisConfig()
        config.paths.connections = tmp_path / "connections.json"
        tray = _create_tray_app(config)
        assert isinstance(tray, TrayApplication)
    finally:
        FakeApplication._instance = None
        restore_modules(saved)


def test_run_with_tray_starts_monitoring_in_background() -> None:
    """run_with_tray starts the tray UI and Inbox monitoring concurrently."""
    import time

    from tests.presentation_stubs import FakeApplication

    saved = install_presentation_stubs()
    FakeApplication._instance = None
    try:
        from aegisvault.config import AegisConfig

        config = AegisConfig()
        config.paths.connections = Path("/tmp/conn.json")
        agent = MagicMock()
        with patch("aegisvault.__main__._create_tray_app") as mock_create_tray:
            mock_tray = MagicMock()

            def stop_after_short_delay() -> None:
                time.sleep(0.1)

            mock_tray.run.side_effect = stop_after_short_delay
            mock_create_tray.return_value = mock_tray
            run_with_tray(agent, config)

        agent.start_monitoring.assert_called_once()
        agent.stop_monitoring.assert_called_once()
        mock_tray.run.assert_called_once()
    finally:
        FakeApplication._instance = None
        restore_modules(saved)


def test_main_no_tray_does_not_import_qt() -> None:
    """main with --no-tray should not require Qt."""
    # Simulate Qt being unavailable for the headless path.
    module_path = "aegisvault.presentation.tray"
    real_module = sys.modules.get(module_path)
    sys.modules[module_path] = None  # type: ignore[assignment]
    try:
        with (
            patch("aegisvault.__main__.run_headless") as mock_run,
            patch("aegisvault.__main__.AegisAgent") as mock_agent_cls,
        ):
            mock_agent = MagicMock()
            mock_agent_cls.return_value = mock_agent
            result = main(["--no-tray"])
        assert result == 0
        mock_run.assert_called_once_with(mock_agent)
    finally:
        if real_module is not None:
            sys.modules[module_path] = real_module
        else:
            sys.modules.pop(module_path, None)
