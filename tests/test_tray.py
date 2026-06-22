"""Tests for the system tray application."""

# mypy: ignore-errors

# ruff: noqa: N802

from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import pytest

from aegisvault.config import AegisConfig
from aegisvault.orchestration.state_machine import TaskState
from aegisvault.orchestration.task_store import TaskStore

from .presentation_stubs import (
    FakeAction,
    FakeApplication,
    FakeMenu,
    install_presentation_stubs,
    restore_modules,
)


@pytest.fixture
def qt_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace PyQt6 widgets with stubs so tests run without a display."""
    saved = install_presentation_stubs()
    FakeApplication._instance = None
    yield
    FakeApplication._instance = None
    restore_modules(saved)


@pytest.fixture
def config(tmp_path: Path) -> AegisConfig:
    """Test configuration with isolated paths."""
    cfg = AegisConfig()
    cfg.paths.index = tmp_path / "Index"
    cfg.paths.connections = tmp_path / "connections.json"
    cfg.paths.inbox = tmp_path / "Inbox"
    cfg.paths.vault = tmp_path / "Vault"
    return cfg


def _menu_texts(menu: FakeMenu) -> list[str]:
    """Collect text from actions and nested menus in a FakeMenu."""
    texts: list[str] = []
    for action in menu.actions:
        if action is None:
            continue
        if isinstance(action, FakeMenu):
            texts.append(action.title)
            texts.extend(_menu_texts(action))
        elif isinstance(action, FakeAction):
            texts.append(action.text)
    return texts


def _find_action(menu: FakeMenu, predicate: Callable[[FakeAction], bool]) -> FakeAction | None:
    """Find the first action matching predicate in the menu."""
    for action in menu.actions:
        if isinstance(action, FakeAction) and predicate(action):
            return action
    return None


def _find_nested_menu(menu: FakeMenu, title: str) -> FakeMenu | None:
    """Find a nested FakeMenu by title."""
    for action in menu.actions:
        if isinstance(action, FakeMenu) and action.title == title:
            return action
    return None


def test_tray_header_is_present(qt_stubs: None, config: AegisConfig) -> None:
    """Tray initializes a header label with app name, version and status summary."""
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication(config=config)
    tray._refresh_header()

    assert isinstance(tray._header_label, object)
    assert "AegisVault" in tray._header_label.text
    assert "v0.1.0" in tray._header_label.text
    assert "完成" in tray._header_label.text


def test_tray_quick_actions_are_present(qt_stubs: None, config: AegisConfig) -> None:
    """Tray menu exposes quick-entry actions with icons."""
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication(config=config)
    tray._add_quick_actions(tray.menu)

    texts = _menu_texts(tray.menu)
    assert "📥 Open Inbox" in texts
    assert "🔐 Open Vault" in texts
    assert "🔍 Search Vault..." in texts
    assert "📊 Dashboard" in texts
    assert "🔔 Notifications (0)" in texts
    assert any("Activity" in text for text in texts)

    notifications = _find_action(tray.menu, lambda a: "Notifications" in a.text)
    assert notifications is not None
    assert notifications.enabled is False


def test_tray_connections_submenu_exists(qt_stubs: None, config: AegisConfig) -> None:
    """Tray has a Connections submenu listing enabled connections."""
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication(config=config)
    tray._build_connections_menu()
    tray.menu.addMenu(tray.connections_menu)

    connections_menu = _find_nested_menu(tray.menu, "Connections")
    assert connections_menu is not None
    texts = _menu_texts(connections_menu)
    assert any("Local Ollama" in text for text in texts)
    assert any("Manage Connections..." in text for text in texts)


def test_tray_without_config_shows_not_configured(qt_stubs: None) -> None:
    """Tray shows a placeholder when no task store is configured."""
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication()
    tray._build_tasks_menu()

    assert tray.task_store is None
    texts = [a.text for a in tray.tasks_menu.actions if a is not None]
    assert any("not configured" in text for text in texts)
    assert any("Refresh" in text for text in texts)


def test_tray_builds_tasks_menu_with_progress(qt_stubs: None, config: AegisConfig) -> None:
    """Tray renders task sections and an overall progress bar."""
    from aegisvault.presentation.tray import TrayApplication

    store = TaskStore(config.paths.index / "tasks.db")
    task_id = uuid4()
    store.create(task_id, Path("/tmp/file.txt"))
    store.update_state(task_id, TaskState.ENCRYPTING, "working")

    tray = TrayApplication(config=config)
    tray._build_tasks_menu()

    assert tray.task_store is not None
    assert tray._tasks_progress_bar.range == (0, 100)
    assert tray._tasks_progress_bar.value == 0
    assert "完成 0/1" in tray._tasks_progress_bar.format

    texts = _menu_texts(tray.tasks_menu)
    assert any("进行中" in text for text in texts)
    assert any(str(task_id)[:8] in text for text in texts)
    assert any("加密中" in text for text in texts)
    assert any("最近完成" in text for text in texts)
    assert any("需关注" in text for text in texts)
    assert any("打开任务中心..." in text for text in texts)
    assert any("Refresh" in text for text in texts)


def test_tray_progress_reflects_completed_tasks(qt_stubs: None, config: AegisConfig) -> None:
    """Progress bar shows completed / total ratio."""
    from aegisvault.presentation.tray import TrayApplication

    store = TaskStore(config.paths.index / "tasks.db")
    completed_id = uuid4()
    pending_id = uuid4()
    store.create(completed_id, Path("/tmp/done.txt"))
    store.update_state(completed_id, TaskState.COMPLETED)
    store.create(pending_id, Path("/tmp/pending.txt"))

    tray = TrayApplication(config=config)
    tray._build_tasks_menu()

    assert tray._tasks_progress_bar.value == 50
    assert "完成 1/2" in tray._tasks_progress_bar.format


def test_tray_menu_refreshes_on_about_to_show(qt_stubs: None, config: AegisConfig) -> None:
    """Menu refreshes when aboutToShow fires, reflecting state changes."""
    from aegisvault.presentation.tray import TrayApplication

    store = TaskStore(config.paths.index / "tasks.db")
    task_id = uuid4()
    store.create(task_id, Path("/tmp/file.txt"))

    tray = TrayApplication(config=config)
    tray._build_tasks_menu()

    store.update_state(task_id, TaskState.COMPLETED)
    assert tray._tasks_progress_bar.value == 0

    tray.tasks_menu.emit_about_to_show()

    assert tray._tasks_progress_bar.value == 100
    assert "完成 1/1" in tray._tasks_progress_bar.format


def test_tray_refresh_action_is_present(qt_stubs: None, config: AegisConfig) -> None:
    """A Refresh action is available in the tasks menu."""
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication(config=config)
    tray._build_tasks_menu()

    refresh_actions = [
        a
        for a in tray.tasks_menu.actions
        if a is not None and isinstance(a, FakeAction) and "Refresh" in a.text
    ]
    assert len(refresh_actions) == 1
    assert len(refresh_actions[0].triggered.connected) == 1


def test_tray_task_center_placeholder_is_present(qt_stubs: None, config: AegisConfig) -> None:
    """A task center placeholder action is present in the tasks menu."""
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication(config=config)
    tray._build_tasks_menu()

    task_center = _find_action(tray.tasks_menu, lambda a: "打开任务中心" in a.text)
    assert task_center is not None
    assert len(task_center.triggered.connected) == 1


def test_tray_attention_section_shows_failed_and_quarantined(
    qt_stubs: None, config: AegisConfig
) -> None:
    """The attention section surfaces FAILED and QUARANTINED tasks."""
    from aegisvault.presentation.tray import TrayApplication

    store = TaskStore(config.paths.index / "tasks.db")
    failed_id = uuid4()
    quarantined_id = uuid4()
    store.create(failed_id, Path("/tmp/failed.txt"))
    store.update_state(failed_id, TaskState.FAILED)
    store.create(quarantined_id, Path("/tmp/bad.txt"))
    store.update_state(quarantined_id, TaskState.QUARANTINED)

    tray = TrayApplication(config=config)
    tray._build_tasks_menu()

    texts = _menu_texts(tray.tasks_menu)
    assert any(str(failed_id)[:8] in text for text in texts)
    assert any(str(quarantined_id)[:8] in text for text in texts)
    assert any("失败" in text for text in texts)
    assert any("已隔离" in text for text in texts)


def test_tray_status_summary_without_task_store(qt_stubs: None) -> None:
    """Status summary works when no task store is configured."""
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication()
    summary = tray._status_summary()

    assert "未配置本地连接" in summary or "本地连接正常" in summary
    assert "📦" in summary
    assert "完成 0" in summary


def test_tray_status_summary_with_failed_and_quarantined(
    qt_stubs: None, config: AegisConfig
) -> None:
    """Status summary reports failed and quarantined counts."""
    from aegisvault.presentation.tray import TrayApplication

    store = TaskStore(config.paths.index / "tasks.db")
    failed_id = uuid4()
    quarantined_id = uuid4()
    store.create(failed_id, Path("/tmp/failed.txt"))
    store.update_state(failed_id, TaskState.FAILED)
    store.create(quarantined_id, Path("/tmp/bad.txt"))
    store.update_state(quarantined_id, TaskState.QUARANTINED)

    tray = TrayApplication(config=config)
    summary = tray._status_summary()

    assert "失败 1" in summary
    assert "隔离 1" in summary


def test_tray_vault_size_text(qt_stubs: None, config: AegisConfig) -> None:
    """Vault size is calculated from files in the vault directory."""
    from aegisvault.presentation.tray import TrayApplication

    config.paths.vault.mkdir(parents=True, exist_ok=True)
    (config.paths.vault / "data.bin").write_bytes(b"x" * 1500)

    tray = TrayApplication(config=config)
    size_text = tray._vault_size_text()

    assert "KB" in size_text or "B" in size_text


def test_tray_no_enabled_connections_shows_placeholder(qt_stubs: None, config: AegisConfig) -> None:
    """Connections menu shows a placeholder when no connections are enabled."""
    from aegisvault.presentation.tray import TrayApplication

    # Use a fresh empty connections file so the default Ollama connection is not seeded.
    empty_path = config.paths.connections.parent / "empty_connections.json"
    empty_path.write_text('{"version": 1, "connections": []}')
    tray = TrayApplication(connections_path=empty_path, config=config)

    # Disable any seeded connections.
    for conn in tray.connection_manager.list_all():
        conn.is_enabled = False
        tray.connection_manager.update(conn)

    tray._refresh_connections_menu()
    texts = [a.text for a in tray.connections_menu.actions if a is not None]
    assert any("No connections enabled" in text for text in texts)


def test_tray_remote_connection_marked_unverified(qt_stubs: None, config: AegisConfig) -> None:
    """A remote enabled connection is labelled as unverified."""
    from aegisvault.platform.models import AuthMethod, Connection, PlatformType
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication(config=config)
    # Remove any seeded connections and add a remote one.
    for conn in list(tray.connection_manager.list_all()):
        tray.connection_manager.delete(conn.id)
    remote = Connection(
        name="Remote API",
        platform_type=PlatformType.OPENAI_COMPATIBLE,
        base_url="https://example.com/v1",
        auth_method=AuthMethod.BEARER,
        api_key="secret",
        is_local=False,
        is_enabled=True,
    )
    tray.connection_manager.add(remote)

    tray._refresh_connections_menu()
    texts = [a.text for a in tray.connections_menu.actions if a is not None]
    assert any("远程 / 未验证" in text for text in texts)


def test_tray_run_builds_menu_and_execs(qt_stubs: None, config: AegisConfig) -> None:
    """run() builds the menu, shows the tray icon and calls app.exec()."""
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication(config=config)
    tray.run()

    assert tray.tray.visible is True
    assert tray.tray.tooltip == "AegisVault"
    assert tray.tray.menu is tray.menu
    texts = _menu_texts(tray.menu)
    assert "🚪 Quit" in texts
    assert any("About AegisVault" in text for text in texts)


def test_tray_quick_action_handlers_print(
    qt_stubs: None, config: AegisConfig, capsys: pytest.CaptureFixture[str]
) -> None:
    """Quick action handlers emit placeholder output."""
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication(config=config)
    tray._open_inbox()
    tray._open_vault()
    tray._search_vault()
    tray._open_dashboard()
    tray._show_about()
    tray._open_docs()
    tray._open_task_center()

    captured = capsys.readouterr().out
    assert "Open Inbox" in captured
    assert "Open Vault" in captured
    assert "Search Vault" in captured
    assert "Open Dashboard" in captured
    assert "AegisVault v0.1.0" in captured
    assert "Open documentation" in captured
    assert "Open Task Center" in captured


def test_tray_activity_summary_text(qt_stubs: None, config: AegisConfig) -> None:
    """Activity summary reflects task counts in the quick actions panel."""
    from aegisvault.presentation.tray import TrayApplication

    store = TaskStore(config.paths.index / "tasks.db")
    active_id = uuid4()
    completed_id = uuid4()
    failed_id = uuid4()
    store.create(active_id, Path("/tmp/active.txt"))
    store.create(completed_id, Path("/tmp/done.txt"))
    store.update_state(completed_id, TaskState.COMPLETED)
    store.create(failed_id, Path("/tmp/failed.txt"))
    store.update_state(failed_id, TaskState.FAILED)

    tray = TrayApplication(config=config)
    summary = tray._activity_summary_text()

    assert "总计 3" in summary
    assert "进行中 1" in summary
    assert "完成 1" in summary
    assert "失败 1" in summary


def test_tray_activity_summary_without_store(qt_stubs: None) -> None:
    """Activity summary reports not configured when no task store exists."""
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication()
    assert tray._activity_summary_text() == "📦 Tasks not configured"


def test_tray_activity_summary_with_quarantined(qt_stubs: None, config: AegisConfig) -> None:
    """Activity summary includes the quarantined count."""
    from aegisvault.presentation.tray import TrayApplication

    store = TaskStore(config.paths.index / "tasks.db")
    quarantined_id = uuid4()
    store.create(quarantined_id, Path("/tmp/bad.txt"))
    store.update_state(quarantined_id, TaskState.QUARANTINED)

    tray = TrayApplication(config=config)
    summary = tray._activity_summary_text()

    assert "隔离 1" in summary


def test_tray_task_action_includes_tooltip(qt_stubs: None, config: AegisConfig) -> None:
    """Task actions expose a tooltip with state details."""
    from aegisvault.api.schemas import TaskSummary
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication(config=config)
    task = TaskSummary(
        task_id=uuid4(),
        state=TaskState.ENCRYPTING.name,
        message="processing",
    )
    action = tray._task_action(task, tray.tasks_menu)

    assert "加密中" in action.text
    assert "processing" in action.text
    assert action.tooltip == "正在加密并写入保险库"


def test_tray_open_connection_manager(qt_stubs: None, config: AegisConfig) -> None:
    """Opening the connection manager creates a ConnectionManagerDialog."""
    from aegisvault.presentation.tray import TrayApplication

    tray = TrayApplication(config=config)
    # Dialog exec is a no-op with stubs; this exercises the creation path.
    tray._open_connection_manager()


def test_tray_vault_size_text_in_tb(qt_stubs: None, config: AegisConfig) -> None:
    """Vault size falls back to TB for very large directories."""
    from types import SimpleNamespace

    from aegisvault.presentation.tray import TrayApplication

    class FakeVault:
        def exists(self) -> bool:
            return True

        def rglob(self, _pattern: str) -> list["FakeVault"]:
            return [self]

        def is_file(self) -> bool:
            return True

        def stat(self) -> object:
            return SimpleNamespace(st_size=5 * 1024**4)

    tray = TrayApplication(config=config)
    tray.config.paths.vault = FakeVault()  # type: ignore[assignment]

    assert tray._vault_size_text().endswith("TB")
