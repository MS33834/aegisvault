"""Tests for the system tray application."""

# ruff: noqa: N802

import sys
import types
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import pytest

from aegisvault.config import AegisConfig
from aegisvault.orchestration.state_machine import TaskState
from aegisvault.orchestration.task_store import TaskStore


class FakeProgressBar:
    """Stub progress bar for headless tests."""

    def __init__(self) -> None:
        self.value = 0
        self.format = ""
        self.range = (0, 0)
        self.text_visible = False

    def setRange(self, min_value: int, max_value: int) -> None:
        self.range = (min_value, max_value)

    def setValue(self, value: int) -> None:
        self.value = value

    def setFormat(self, fmt: str) -> None:
        self.format = fmt

    def setTextVisible(self, visible: bool) -> None:
        self.text_visible = visible


class FakeSignal:
    """Stub Qt signal for headless tests."""

    def __init__(self) -> None:
        self.connected: list[object] = []

    def connect(self, callback: object) -> None:
        self.connected.append(callback)


class FakeLabel:
    """Stub QLabel for headless tests."""

    def __init__(self) -> None:
        self.text = ""

    def setText(self, text: str) -> None:
        self.text = text


class FakeAction:
    """Stub QAction for headless tests."""

    def __init__(self, text: str = "", parent: object | None = None) -> None:
        self.text = text
        self.parent = parent
        self.enabled = True
        self.triggered = FakeSignal()

    def setEnabled(self, enabled: bool) -> None:
        self.enabled = enabled

    def setDefaultWidget(self, widget: object) -> None:
        self.widget = widget

    def setToolTip(self, tooltip: str) -> None:
        self.tooltip = tooltip


class FakeWidgetAction(FakeAction):
    """Stub QWidgetAction for headless tests."""

    def __init__(self, parent: object | None = None) -> None:
        super().__init__("", parent)


class FakeMenu:
    """Stub QMenu for headless tests."""

    def __init__(self, title: str = "") -> None:
        self.title = title
        self.actions: list[FakeAction | None | object] = []
        self.aboutToShow = FakeSignal()

    def addSection(self, text: str) -> FakeAction:
        action = FakeAction(text, self)
        self.actions.append(action)
        return action

    def addAction(self, action: FakeAction | None) -> None:
        self.actions.append(action)

    def addSeparator(self) -> None:
        self.actions.append(None)

    def addMenu(self, menu: object) -> None:
        self.actions.append(menu)

    def clear(self) -> None:
        self.actions.clear()

    def emit_about_to_show(self) -> None:
        for callback in self.aboutToShow.connected:
            callback()  # type: ignore[operator]


class FakeSystemTrayIcon:
    """Stub QSystemTrayIcon for headless tests."""

    def __init__(self) -> None:
        self.menu: object | None = None
        self.visible = False
        self.tooltip = ""

    def setContextMenu(self, menu: object) -> None:
        self.menu = menu

    def setVisible(self, visible: bool) -> None:
        self.visible = visible

    def setToolTip(self, tooltip: str) -> None:
        self.tooltip = tooltip


class FakeApplication:
    """Stub QApplication for headless tests."""

    _instance: "FakeApplication | None" = None

    def __init__(self, _args: object) -> None:
        if FakeApplication._instance is None:
            FakeApplication._instance = self
        self.quit_called = False

    def quit(self) -> None:
        self.quit_called = True

    def exec(self) -> int:
        return 0

    @classmethod
    def instance(cls) -> "FakeApplication | None":
        return cls._instance


@pytest.fixture
def qt_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace PyQt6 widgets with stubs so tests run without a display."""
    # Provide minimal fake PyQt6 submodules before tray.py is imported.
    fake_qt = types.ModuleType("PyQt6")
    fake_qt_gui = types.ModuleType("PyQt6.QtGui")
    fake_qt_gui.QAction = FakeAction
    fake_qt_widgets = types.ModuleType("PyQt6.QtWidgets")
    fake_qt_widgets.QApplication = FakeApplication
    fake_qt_widgets.QLabel = FakeLabel
    fake_qt_widgets.QMenu = FakeMenu
    fake_qt_widgets.QProgressBar = FakeProgressBar
    fake_qt_widgets.QSystemTrayIcon = FakeSystemTrayIcon
    fake_qt_widgets.QWidgetAction = FakeWidgetAction

    saved_modules = {
        "PyQt6": sys.modules.get("PyQt6"),
        "PyQt6.QtGui": sys.modules.get("PyQt6.QtGui"),
        "PyQt6.QtWidgets": sys.modules.get("PyQt6.QtWidgets"),
        "aegisvault.presentation.connection_dialog": sys.modules.get(
            "aegisvault.presentation.connection_dialog"
        ),
        "aegisvault.presentation.tray": sys.modules.get("aegisvault.presentation.tray"),
    }
    sys.modules["PyQt6"] = fake_qt
    sys.modules["PyQt6.QtGui"] = fake_qt_gui
    sys.modules["PyQt6.QtWidgets"] = fake_qt_widgets

    # Stub out the connection dialog import so its own PyQt6 usage is not loaded.
    fake_dialog_module = types.ModuleType("aegisvault.presentation.connection_dialog")
    fake_dialog_module.ConnectionManagerDialog = object  # type: ignore[attr-defined]
    sys.modules["aegisvault.presentation.connection_dialog"] = fake_dialog_module

    # Ensure the tray module is reloaded using the stubs.
    sys.modules.pop("aegisvault.presentation.tray", None)

    FakeApplication._instance = None
    yield
    FakeApplication._instance = None
    sys.modules.update(saved_modules)
    sys.modules.pop("aegisvault.presentation.tray", None)


@pytest.fixture
def config(tmp_path: Path) -> AegisConfig:
    """Test configuration with isolated paths."""
    cfg = AegisConfig()
    cfg.paths.index = tmp_path / "Index"
    cfg.paths.connections = tmp_path / "connections.json"
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


def _find_action(
    menu: FakeMenu, predicate: Callable[[FakeAction], bool]
) -> FakeAction | None:
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

    assert isinstance(tray._header_label, FakeLabel)
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
