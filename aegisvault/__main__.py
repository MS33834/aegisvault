"""CLI entry point for AegisVault."""

import argparse
import asyncio
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any

from aegisvault.api.schemas import SearchResult
from aegisvault.config import AegisConfig
from aegisvault.execution.vault import VaultManager
from aegisvault.orchestration.agent import AegisAgent
from aegisvault.orchestration.task_store import TaskStore
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
    root = logging.getLogger()
    if root.handlers:
        root.setLevel(min(root.level, level))
        logger.info("Logging already configured; adjusting level to %s", level)
    else:
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

    # Helper: attach global-like arguments to a subparser so they also work
    # after the subcommand (e.g. `aegisvault search "test" --inbox /tmp/a`).
    def _add_context_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--inbox", type=Path, help="Override the Inbox directory path.")
        p.add_argument("--vault", type=Path, help="Override the Vault directory path.")
        p.add_argument("--index", type=Path, help="Override the Index directory path.")
        p.add_argument("--connections", type=Path, help="Override the connections file path.")
        p.add_argument("--debug", action="store_true", help="Enable debug logging.")

    search_parser = sub.add_parser("search", help="Search vault content by keywords")
    search_parser.add_argument("query", help="Search query string")
    search_parser.add_argument(
        "--semantic", action="store_true", help="Enable semantic search via embeddings"
    )
    search_parser.add_argument("--top-k", type=int, default=5, help="Number of results to return")
    _add_context_args(search_parser)

    status_parser = sub.add_parser(
        "status", help="Show agent status (inbox/vault counts, recent tasks)"
    )
    _add_context_args(status_parser)

    list_parser = sub.add_parser("list", help="List vault files, optionally by category")
    list_parser.add_argument("category", nargs="?", default=None, help="Filter by category name")
    _add_context_args(list_parser)

    export_parser = sub.add_parser("export", help="Export (decrypt) vault files to a directory")
    export_parser.add_argument(
        "output_dir", type=Path, help="Directory to export decrypted files to"
    )
    export_parser.add_argument("--category", default=None, help="Filter by category name")
    export_parser.add_argument("--query", default=None, help="Search query to filter files")
    _add_context_args(export_parser)

    serve_parser = sub.add_parser("serve", help="Start the AegisVault API server")
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1 for local-only access)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="TCP port to listen on (default: 8000)",
    )
    serve_parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )
    _add_context_args(serve_parser)

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


def _create_agent(config: AegisConfig) -> AegisAgent | None:
    """Create an AegisAgent with minimal setup (no monitoring loop).

    Returns None gracefully when the master key provider is unavailable
    (e.g. FilePasswordProvider without a configured password).  Callers
    should degrade gracefully when None is returned.
    """
    try:
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
            audit_logger=AuditLogger(config),
            master_key_provider=master_key_provider,
        )
    except (RuntimeError, FileNotFoundError) as exc:
        logger.warning("Cannot initialize master key: %s", exc)
        return None


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


def cmd_search(agent: AegisAgent, query: str, semantic: bool = False, top_k: int = 5) -> int:
    """Search vault content by keywords."""
    from aegisvault.api.schemas import SearchQuery

    async def _search() -> Any:
        return await agent.search(SearchQuery(query=query, top_k=top_k, semantic=semantic))

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
            suffix = os.urandom(8).hex()
            dest = output_dir / f"{dest.stem}_{suffix}{dest.suffix}"
        try:
            vault_manager.decrypt(vault_path, item["salt"], dest)
            exported += 1
            print(f"  Exported: {dest}")
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"  Failed:   {vault_path} ({exc})", file=sys.stderr)

    print(f"\nExported {exported}/{len(items)} file(s) to {output_dir}")
    return 0


def cmd_serve(
    agent: AegisAgent,
    config: AegisConfig,
    host: str = "127.0.0.1",
    port: int = 8000,
    reload: bool = False,
) -> int:
    """Start the AegisVault API server."""
    from aegisvault.api.server import is_available, run_server

    if not is_available():
        print(
            "FastAPI is required for the API server. "
            "Install it with: pip install aegisvault[server]",
            file=sys.stderr,
        )
        return 1

    run_server(config, agent, host=host, port=port, reload=reload)
    return 0


# ---------------------------------------------------------------------------
# Fallback subcommand handlers (no master key needed — TaskStore only)
# ---------------------------------------------------------------------------


def _task_store(config: AegisConfig) -> TaskStore:
    """Create a minimal TaskStore for read-only subcommands."""
    from aegisvault.orchestration.task_store import TaskStore as _TaskStore

    return _TaskStore(config.paths.index / "tasks.db")


def _print_search_results(results: list[SearchResult], query: str) -> None:
    """Print search results in a consistent format."""
    if not results:
        print(f"No results found for: {query}")
        return
    for i, result in enumerate(results, 1):
        print(f"{i}. {result.vault_path}")
        print(f"   Category: {result.category}")
        print(f"   Summary: {result.summary}")
        print(f"   Score:   {result.score:.4f}")
        print()


def cmd_search_fallback(
    config: AegisConfig,
    query: str,
    semantic: bool = False,
    top_k: int = 5,
) -> int:
    """Search vault metadata via TaskStore directly (no master key needed)."""
    store = _task_store(config)
    if semantic:
        print(
            "Note: Semantic search requires an embedding provider (and master key). "
            "Falling back to text search.",
            file=sys.stderr,
        )
    try:
        results = store.search(query, top_k=top_k)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Search failed: {exc}", file=sys.stderr)
        return 1
    _print_search_results(results, query)
    return 0


def cmd_status_fallback(config: AegisConfig) -> int:
    """Show agent status via TaskStore (no master key needed)."""
    inbox_count = _count_files(config.paths.inbox)
    vault_count = _count_vault_files(config.paths.vault)
    store = _task_store(config)
    recent = store.list_recent(limit=5)

    print("=== AegisVault Status (read-only) ===")
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


def cmd_list_fallback(config: AegisConfig, category: str | None = None) -> int:
    """List vault files via TaskStore directly (no master key needed)."""
    store = _task_store(config)
    items = store.list_vault_files(category)

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


def cmd_serve_fallback(
    config: AegisConfig,
    host: str = "127.0.0.1",
    port: int = 8000,
    reload: bool = False,
) -> int:
    """Start the API server without a master key — gives a friendly error."""
    from aegisvault.api.server import is_available

    if not is_available():
        print(
            "FastAPI is required for the API server. "
            "Install it with: pip install aegisvault[server]",
            file=sys.stderr,
        )
        return 1

    print(
        "Cannot start API server: master key is not configured.\n"
        "Set the AEGISVAULT_SECURITY__MASTER_KEY_PASSWORD environment variable\n"
        "or configure a master key provider via settings.json.",
        file=sys.stderr,
    )
    return 1


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
            if agent is not None:
                return cmd_search(
                    agent,
                    args.query,
                    semantic=getattr(args, "semantic", False),
                    top_k=getattr(args, "top_k", 5),
                )
            # Fallback: search via TaskStore directly (no master key needed).
            return cmd_search_fallback(
                config,
                args.query,
                semantic=getattr(args, "semantic", False),
                top_k=getattr(args, "top_k", 5),
            )
        elif args.command == "status":
            if agent is not None:
                return cmd_status(agent, config)
            return cmd_status_fallback(config)
        elif args.command == "list":
            if agent is not None:
                return cmd_list(agent, args.category)
            return cmd_list_fallback(config, args.category)
        elif args.command == "export":
            if agent is None or agent.master_key_provider is None:
                print(
                    "Cannot export: master key is not configured. "
                    "Set AEGISVAULT_SECURITY__MASTER_KEY_PASSWORD "
                    "or configure a master key provider first.",
                    file=sys.stderr,
                )
                return 1
            return cmd_export(agent, config, args.output_dir, args.category, args.query)
        elif args.command == "serve":
            if agent is not None:
                return cmd_serve(
                    agent,
                    config,
                    host=args.host,
                    port=args.port,
                    reload=args.reload,
                )
            # Try to start server without agent (limited functionality).
            return cmd_serve_fallback(
                config,
                host=args.host,
                port=args.port,
                reload=args.reload,
            )
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
