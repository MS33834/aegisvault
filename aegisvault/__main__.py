"""CLI entry point for AegisVault."""

import argparse
import asyncio
import logging
import sys
import threading
from pathlib import Path
from typing import Any

from aegisvault.config import AegisConfig
from aegisvault.orchestration.agent import AegisAgent
from aegisvault.security import windows_hello
from aegisvault.security.audit_log import AuditLogger
from aegisvault.security.master_key import MasterKeyProvider, create_master_key_provider

logger = logging.getLogger(__name__)


def _master_key_storage_path(config: AegisConfig) -> Path:
    """Return the filesystem location used to persist the protected master key."""
    return config.paths.connections.parent / "master_key.bin"


def _configure_logging(debug: bool) -> None:
    """Set up console logging."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="aegisvault",
        description="AegisVault - local private content management agent",
    )
    parser.add_argument(
        "--no-tray",
        action="store_true",
        help="Run in headless mode without the system tray UI.",
    )
    parser.add_argument(
        "--inbox",
        type=Path,
        help="Override the Inbox directory path.",
    )
    parser.add_argument(
        "--vault",
        type=Path,
        help="Override the Vault directory path.",
    )
    parser.add_argument(
        "--index",
        type=Path,
        help="Override the Index directory path.",
    )
    parser.add_argument(
        "--connections",
        type=Path,
        help="Override the connections file path.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> AegisConfig:
    """Build an AegisConfig from CLI arguments."""
    config = AegisConfig.load_from_file()
    config.debug = args.debug
    if args.inbox:
        config.paths.inbox = args.inbox
    if args.vault:
        config.paths.vault = args.vault
    if args.index:
        config.paths.index = args.index
    if args.connections:
        config.paths.connections = args.connections
    return config


def _run_asyncio_loop(loop: asyncio.AbstractEventLoop, shutdown: threading.Event) -> None:
    """Run an asyncio event loop until the shutdown event is set."""
    asyncio.set_event_loop(loop)
    while not shutdown.is_set():
        loop.run_until_complete(asyncio.sleep(0.2))


def _create_tray_app(config: AegisConfig) -> Any:
    """Import and create the tray application (delayed to avoid Qt import in tests)."""
    from aegisvault.presentation.tray import TrayApplication

    return TrayApplication(config=config)


def run_headless(agent: AegisAgent) -> None:
    """Run the agent in headless mode with the asyncio loop in the main thread."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    shutdown = threading.Event()
    agent.start_monitoring(loop)

    try:
        while not shutdown.is_set():
            try:
                loop.run_until_complete(asyncio.sleep(0.5))
            except KeyboardInterrupt:
                shutdown.set()
    finally:
        agent.stop_monitoring()
        if loop.is_running():
            loop.call_soon(loop.stop)
        loop.close()


def run_with_tray(agent: AegisAgent, config: AegisConfig) -> None:
    """Run the tray UI in the main thread and asyncio monitoring in a background thread."""
    loop = asyncio.new_event_loop()
    shutdown = threading.Event()
    asyncio_thread = threading.Thread(
        target=_run_asyncio_loop,
        args=(loop, shutdown),
        daemon=True,
    )
    asyncio_thread.start()
    agent.start_monitoring(loop)

    tray = _create_tray_app(config)
    try:
        tray.run()
    finally:
        shutdown.set()
        agent.stop_monitoring()
        asyncio_thread.join(timeout=2)
        loop.call_soon_threadsafe(loop.stop)
        asyncio_thread.join(timeout=2)


def main(argv: list[str] | None = None) -> int:
    """Run the AegisVault CLI entry point."""
    args = parse_args(argv)
    _configure_logging(args.debug)
    config = build_config(args)
    audit_logger = AuditLogger(config)

    master_key_provider: MasterKeyProvider | None = None
    if config.security.windows_hello_enabled:
        storage_path = _master_key_storage_path(config)
        hello_salt = windows_hello.get_key_derivation_salt(storage_path)
        master_key_provider = create_master_key_provider(
            config.security.master_key_provider,
            storage_path,
            password=config.security.master_key_password,
            hello_salt=hello_salt,
        )

    agent = AegisAgent(config, audit_logger=audit_logger, master_key_provider=master_key_provider)

    logger.info("AegisVault is starting...")

    if args.no_tray:
        run_headless(agent)
    else:
        try:
            run_with_tray(agent, config)
        except ImportError as exc:
            logger.warning("Tray UI unavailable (%s); falling back to headless mode.", exc)
            run_headless(agent)

    return 0


if __name__ == "__main__":
    sys.exit(main())
