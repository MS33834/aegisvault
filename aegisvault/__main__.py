"""CLI entry point for AegisVault."""

import argparse
import asyncio
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any

from aegisvault.config import AegisConfig
from aegisvault.execution.vault import VaultManager
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

    sub = parser.add_subparsers(dest="command", help="Available subcommands")

    search_parser = sub.add_parser("search", help="Search vault content by keywords")
    search_parser.add_argument("query", help="Search query string")

    sub.add_parser("status", help="Show agent status (inbox/vault counts, recent tasks)")

    list_parser = sub.add_parser("list", help="List vault files, optionally by category")
    list_parser.add_argument("category", nargs="?", default=None, help="Filter by category name")

    export_parser = sub.add_parser("export", help="Export (decrypt) vault files to a directory")
    export_parser.add_argument(
        "output_dir", type=Path, help="Directory to export decrypted files to"
    )
    export_parser.add_argument("--category", default=None, help="Filter by category name")
    export_parser.add_argument("--query", default=None, help="Search query to filter files")

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


def _create_agent(config: AegisConfig) -> AegisAgent:
    """Create an AegisAgent with minimal setup (no monitoring loop)."""
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

    return AegisAgent(
        config,
        audit_logger=audit_logger,
        master_key_provider=master_key_provider,
    )


def _count_files(path: Path) -> int:
    """Count regular files in a directory (non-recursive)."""
    if not path.exists() or not path.is_dir():
        return 0
    return sum(1 for entry in path.iterdir() if entry.is_file())


def _count_vault_files(path: Path) -> int:
    """Count all regular files in the Vault directory tree."""
    if not path.exists() or not path.is_dir():
        return 0
    return sum(1 for entry in path.rglob("*") if entry.is_file())


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def cmd_search(agent: AegisAgent, query: str) -> int:
    """Search vault content by keywords."""
    from aegisvault.api.schemas import SearchQuery

    async def _search() -> Any:
        return await agent.search(SearchQuery(query=query))

    results = asyncio.run(_search())
    if not results:
        print(f"No results found for: {query}")
        return 0

    for i, result in enumerate(results, 1):
        print(f"{i}. {result.vault_path}")
        print(f"   Category: {result.category}")
        print(f"   Summary: {result.summary}")
        print(f"   Score:   {result.score:.4f}")
        print()
    return 0


def cmd_status(agent: AegisAgent, config: AegisConfig) -> int:
    """Show agent status."""
    inbox_count = _count_files(config.paths.inbox)
    vault_count = _count_vault_files(config.paths.vault)
    recent = agent.task_store.list_recent(limit=5)

    print("=== AegisVault Status ===")
    print(f"  Inbox files : {inbox_count}")
    print(f"  Vault files : {vault_count}")
    print()

    if recent:
        print("Recent tasks:")
        for summary in recent:
            src = str(summary.source_path) if summary.source_path else "N/A"
            print(f"  {summary.task_id}  [{summary.state}]  {src}")
            if summary.message:
                print(f"    {summary.message}")
    else:
        print("No recent tasks.")
    return 0


def cmd_list(agent: AegisAgent, category: str | None = None) -> int:
    """List vault files, optionally filtered by category."""
    items = agent.task_store.list_vault_files(category)

    if not items:
        cat_msg = f" in category '{category}'" if category else ""
        print(f"No vault files found{cat_msg}.")
        return 0

    cat_msg = f" in category '{category}'" if category else ""
    print(f"Vault files{cat_msg} ({len(items)} total):")
    print()
    for i, item in enumerate(items, 1):
        print(f"{i}. {item['vault_path']}")
        print(f"   Category: {item['category']}")
        if item["summary"]:
            print(f"   Summary: {item['summary']}")
        if item["tags"]:
            print(f"   Tags:    {', '.join(item['tags'])}")
        print()
    return 0


def cmd_export(
    agent: AegisAgent,
    config: AegisConfig,
    output_dir: Path,
    category: str | None = None,
    query: str | None = None,
) -> int:
    """Export (decrypt) vault files to a directory."""
    items = agent.task_store.list_vault_files(category)
    if not items:
        cat_msg = f" in category '{category}'" if category else ""
        print(f"No vault files found{cat_msg}.")
        return 0

    if query:
        from aegisvault.api.schemas import SearchQuery

        async def _search() -> Any:
            return await agent.search(SearchQuery(query=query))

        results = asyncio.run(_search())
        result_paths = {str(r.vault_path) for r in results}
        items = [item for item in items if str(item["vault_path"]) in result_paths]

        if not items:
            print(f"No vault files match query: {query}")
            return 0

    if not agent.master_key_provider:
        print("Cannot export: master key provider is not configured.", file=sys.stderr)
        return 1

    from aegisvault.security.keytree import derive_vault_key

    vault_key = derive_vault_key(agent.master_key_provider.get_key())
    output_dir.mkdir(parents=True, exist_ok=True)
    vault_manager = VaultManager(config.paths.vault, vault_key, agent.audit_logger)

    exported = 0
    for item in items:
        vault_path = Path(item["vault_path"])
        if not vault_path.exists():
            continue
        dest = output_dir / vault_path.name
        if dest.exists():
            suffix = os.urandom(4).hex()
            dest = output_dir / f"{dest.stem}_{suffix}{dest.suffix}"
        try:
            vault_manager.decrypt(vault_path, item["salt"], dest)
            exported += 1
            print(f"  Exported: {dest}")
        except Exception as exc:
            print(f"  Failed:   {vault_path} ({exc})", file=sys.stderr)

    print(f"\nExported {exported}/{len(items)} file(s) to {output_dir}")
    return 0


# ---------------------------------------------------------------------------
# Existing monitoring / tray logic (unchanged)
# ---------------------------------------------------------------------------


def _check_first_run() -> None:
    """Launch the first-run wizard when settings.json does not exist yet."""
    from aegisvault.config import PathConfig

    settings_path = PathConfig().settings
    if settings_path.exists():
        return

    logger.info("Settings file not found — launching first-run wizard.")
    from PyQt6.QtWidgets import QApplication

    from aegisvault.presentation.first_run_wizard import FirstRunWizard

    QApplication.instance() or QApplication(sys.argv[:1])
    wizard = FirstRunWizard(AegisConfig())
    wizard.exec()
    logger.info("First-run wizard completed.")


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

    # --- Subcommand path (no monitoring loop) ---
    if args.command is not None:
        config = build_config(args)
        agent = _create_agent(config)
        logger.info("AegisVault CLI - %s", args.command)

        if args.command == "search":
            return cmd_search(agent, args.query)
        elif args.command == "status":
            return cmd_status(agent, config)
        elif args.command == "list":
            return cmd_list(agent, args.category)
        elif args.command == "export":
            return cmd_export(agent, config, args.output_dir, args.category, args.query)
        else:
            print(f"Unknown command: {args.command}", file=sys.stderr)
            return 1

    # --- First-run wizard (before default monitoring path) ---
    _check_first_run()

    # --- Default path (monitoring loop, original behaviour) ---
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
