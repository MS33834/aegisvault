"""System tray application with connection management entry."""

from pathlib import Path

from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QMenu,
    QProgressBar,
    QSystemTrayIcon,
    QWidgetAction,
)

from aegisvault import __version__
from aegisvault.api.schemas import TaskSummary
from aegisvault.config import AegisConfig
from aegisvault.orchestration.state_machine import TaskState
from aegisvault.orchestration.task_store import TaskStore
from aegisvault.platform.manager import ConnectionManager
from aegisvault.presentation.connection_dialog import ConnectionManagerDialog

_STATE_ICONS: dict[str, str] = {
    TaskState.IDLE.name: "⏳",
    TaskState.CLASSIFYING.name: "🔍",
    TaskState.ENCRYPTING.name: "🔒",
    TaskState.INDEXING.name: "📊",
    TaskState.COMPLETED.name: "✅",
    TaskState.FAILED.name: "❌",
    TaskState.QUARANTINED.name: "⚠️",
}

_STATE_SHORT_LABELS: dict[str, str] = {
    TaskState.IDLE.name: "等待中",
    TaskState.CLASSIFYING.name: "识别中",
    TaskState.ENCRYPTING.name: "加密中",
    TaskState.INDEXING.name: "索引中",
    TaskState.COMPLETED.name: "已完成",
    TaskState.FAILED.name: "失败",
    TaskState.QUARANTINED.name: "已隔离",
}

_STATUS_ICONS = {
    "secure": "🔐",
    "warning": "⚠️",
    "offline": "🔌",
    "online": "🌐",
}


class TrayApplication:
    """System tray application."""

    def __init__(
        self,
        connections_path: Path | None = None,
        config: AegisConfig | None = None,
    ) -> None:
        existing = QApplication.instance()
        self.app = (
            existing
            if isinstance(existing, QApplication)
            else QApplication([])
        )
        self.tray = QSystemTrayIcon()
        self.menu = QMenu()
        self.config = config
        self.connections_path = connections_path or (
            config.paths.connections
            if config is not None
            else Path.home() / "AegisVault" / "Config" / "connections.json"
        )
        self.task_store: TaskStore | None = None
        if config is not None:
            self.task_store = TaskStore(config.paths.index / "tasks.db")

        self.connection_manager = ConnectionManager(self.connections_path)

        self._header_action = QWidgetAction(self.menu)
        self._header_label = QLabel()
        self._header_action.setDefaultWidget(self._header_label)

        self.tasks_menu = QMenu("Tasks")
        self._tasks_progress_action = QWidgetAction(self.tasks_menu)
        self._tasks_progress_bar = QProgressBar()
        self._tasks_progress_bar.setRange(0, 100)
        self._tasks_progress_bar.setTextVisible(True)
        self._tasks_progress_action.setDefaultWidget(self._tasks_progress_bar)

        self.connections_menu = QMenu("Connections")

    def run(self) -> None:
        """Start the tray application."""
        self.menu.aboutToShow.connect(self._refresh_header)
        self.menu.addAction(self._header_action)
        self.menu.addSeparator()

        self._add_quick_actions(self.menu)
        self.menu.addSeparator()

        self._build_connections_menu()
        self.menu.addMenu(self.connections_menu)

        self._build_tasks_menu()
        self.menu.addMenu(self.tasks_menu)

        self.menu.addSeparator()
        self.menu.addSection("Help")
        about_action = QAction(f"ℹ️ About AegisVault v{__version__}", self.menu)
        about_action.triggered.connect(self._show_about)
        self.menu.addAction(about_action)

        docs_action = QAction("📖 Open Documentation", self.menu)
        docs_action.triggered.connect(self._open_docs)
        self.menu.addAction(docs_action)

        self.menu.addSeparator()
        quit_action = QAction("🚪 Quit", self.menu)
        quit_action.triggered.connect(self.app.quit)
        self.menu.addAction(quit_action)

        self._refresh_header()
        self.tray.setContextMenu(self.menu)
        self.tray.setVisible(True)
        self.tray.setToolTip("AegisVault")
        self.app.exec()

    def _add_quick_actions(self, menu: QMenu) -> None:
        """Add static quick-entry actions with icons and grouping."""
        menu.addSection("Quick Actions")

        open_inbox = QAction("📥 Open Inbox", menu)
        open_inbox.triggered.connect(self._open_inbox)
        menu.addAction(open_inbox)

        open_vault = QAction("🔐 Open Vault", menu)
        open_vault.triggered.connect(self._open_vault)
        menu.addAction(open_vault)

        search_vault = QAction("🔍 Search Vault...", menu)
        search_vault.triggered.connect(self._search_vault)
        menu.addAction(search_vault)

        dashboard = QAction("📊 Dashboard", menu)
        dashboard.triggered.connect(self._open_dashboard)
        menu.addAction(dashboard)

        menu.addSeparator()
        notifications = QAction("🔔 Notifications (0)", menu)
        notifications.setEnabled(False)
        menu.addAction(notifications)

    def _open_inbox(self) -> None:
        """Open the configured inbox directory."""
        inbox = self.config.paths.inbox if self.config else Path.home() / "AegisVault" / "Inbox"
        print(f"Open Inbox: {inbox}")  # noqa: T201

    def _open_vault(self) -> None:
        """Open the configured vault directory."""
        vault = self.config.paths.vault if self.config else Path.home() / "AegisVault" / "Vault"
        print(f"Open Vault: {vault}")  # noqa: T201

    def _search_vault(self) -> None:
        """Placeholder for vault search UI."""
        print("Search Vault...")  # noqa: T201

    def _open_dashboard(self) -> None:
        """Placeholder for dashboard UI."""
        print("Open Dashboard...")  # noqa: T201

    def _show_about(self) -> None:
        """Placeholder for about dialog."""
        print(
            f"AegisVault v{__version__} - Local private content management agent"
        )  # noqa: T201

    def _open_docs(self) -> None:
        """Placeholder for documentation link."""
        print("Open documentation...")  # noqa: T201

    def _refresh_header(self) -> None:
        """Update the header label with app name, version and status summary."""
        status = self._status_summary()
        self._header_label.setText(
            f"<b>🔐 AegisVault</b> <span style='color:#888'>v{__version__}</span>"
            f"<br/><small>{status}</small>"
        )

    def _status_summary(self) -> str:
        """Build a one-line status summary for the header."""
        local_ok = any(
            conn.is_enabled and conn.is_trusted_local()
            for conn in self.connection_manager.list_all()
        )
        connection_text = (
            f"{_STATUS_ICONS['online']} 本地连接正常"
            if local_ok
            else f"{_STATUS_ICONS['offline']} 未配置本地连接"
        )

        completed = failed = quarantined = 0
        if self.task_store is not None:
            counts = self.task_store.counts_by_state()
            completed = counts.get(TaskState.COMPLETED.name, 0)
            failed = counts.get(TaskState.FAILED.name, 0)
            quarantined = counts.get(TaskState.QUARANTINED.name, 0)

        vault_size = self._vault_size_text()
        secure_text = (
            f"{_STATUS_ICONS['secure']} 已加密"
            if completed
            else f"{_STATUS_ICONS['warning']} 等待文件"
        )
        parts = [secure_text, connection_text, f"完成 {completed}"]
        if failed:
            parts.append(f"{_STATE_ICONS[TaskState.FAILED.name]} 失败 {failed}")
        if quarantined:
            parts.append(f"{_STATE_ICONS[TaskState.QUARANTINED.name]} 隔离 {quarantined}")
        parts.append(f"📦 {vault_size}")
        return " · ".join(parts)

    def _vault_size_text(self) -> str:
        """Return a human-readable vault size."""
        vault = self.config.paths.vault if self.config else Path.home() / "AegisVault" / "Vault"
        if not vault.exists():
            return "0 B"
        total_bytes = sum(
            f.stat().st_size for f in vault.rglob("*") if f.is_file()
        )
        size = float(total_bytes)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _build_connections_menu(self) -> None:
        """Create the connections submenu and wire lazy refresh."""
        self.connections_menu.aboutToShow.connect(self._refresh_connections_menu)
        self._refresh_connections_menu()

    def _refresh_connections_menu(self) -> None:
        """Refresh the connections submenu with status icons and grouping."""
        self.connections_menu.clear()
        self.connections_menu.addSection("Enabled Connections")
        enabled = self.connection_manager.list_enabled()

        if not enabled:
            none_action = QAction("No connections enabled", self.connections_menu)
            none_action.setEnabled(False)
            self.connections_menu.addAction(none_action)
        else:
            for conn in enabled:
                if conn.is_trusted_local():
                    icon = _STATUS_ICONS["secure"]
                    mark = "本地 · 可信"
                else:
                    icon = _STATUS_ICONS["online"]
                    mark = "远程 / 未验证"
                label = f"{icon} {conn.name} ({conn.platform_type.value}) · {mark}"
                action = QAction(label, self.connections_menu)
                action.setEnabled(False)
                action.setToolTip(conn.base_url)
                self.connections_menu.addAction(action)

        self.connections_menu.addSeparator()
        manage_action = QAction("⚙️ Manage Connections...", self.connections_menu)
        manage_action.triggered.connect(self._open_connection_manager)
        self.connections_menu.addAction(manage_action)

    def _build_tasks_menu(self) -> None:
        """Create the initial tasks submenu and wire refresh."""
        self.tasks_menu.aboutToShow.connect(self._refresh_tasks_menu)
        self._refresh_tasks_menu()

    def _refresh_tasks_menu(self) -> None:
        """Refresh the tasks submenu from the task store."""
        self.tasks_menu.clear()
        self.tasks_menu.addSection("Task Activity")

        if self.task_store is None:
            not_configured = QAction("Tasks not configured", self.tasks_menu)
            not_configured.setEnabled(False)
            self.tasks_menu.addAction(not_configured)
            self.tasks_menu.addSeparator()
            self.tasks_menu.addAction(self._refresh_action())
            return

        counts = self.task_store.counts_by_state()
        total = sum(counts.values())
        completed = counts.get(TaskState.COMPLETED.name, 0)
        failed = counts.get(TaskState.FAILED.name, 0)
        quarantined = counts.get(TaskState.QUARANTINED.name, 0)
        progress = int(100 * completed / total) if total else 0

        self._tasks_progress_bar.setValue(progress)
        status_icon = (
            _STATUS_ICONS["secure"]
            if failed == 0 and quarantined == 0
            else _STATUS_ICONS["warning"]
        )
        self._tasks_progress_bar.setFormat(
            f"{status_icon} 完成 {completed}/{total} · 失败 {failed} · 隔离 {quarantined}"
        )
        self.tasks_menu.addAction(self._tasks_progress_action)
        self.tasks_menu.addSeparator()

        active = self.task_store.list_active(limit=3)
        recent_completed = [
            task
            for task in self.task_store.list_recent(limit=10)
            if task.state == TaskState.COMPLETED.name
        ][:5]
        attention = self.task_store.list_attention(limit=3)

        self._add_task_section(self.tasks_menu, "🔥 进行中", active, empty_text="暂无进行中的任务")
        self._add_task_section(
            self.tasks_menu,
            "✅ 最近完成",
            recent_completed,
            empty_text="暂无已完成任务",
        )
        self._add_task_section(
            self.tasks_menu,
            "⚠️ 需关注",
            attention,
            empty_text="暂无失败或隔离任务",
        )

        self.tasks_menu.addSeparator()
        task_center = QAction("🗂️ 打开任务中心...", self.tasks_menu)
        task_center.triggered.connect(self._open_task_center)
        self.tasks_menu.addAction(task_center)
        self.tasks_menu.addAction(self._refresh_action())

    def _add_task_section(
        self,
        menu: QMenu,
        title: str,
        tasks: list[TaskSummary],
        empty_text: str,
    ) -> None:
        """Add a labelled section of task actions."""
        menu.addSection(title)
        if not tasks:
            empty_action = QAction(empty_text, menu)
            empty_action.setEnabled(False)
            menu.addAction(empty_action)
        else:
            for task in tasks:
                action = self._task_action(task, menu)
                menu.addAction(action)
        menu.addSeparator()

    def _task_action(self, task: TaskSummary, parent: QMenu) -> QAction:
        """Build a disabled action representing a task row."""
        state = task.state
        short_id = str(task.task_id)[:8]
        icon = _STATE_ICONS.get(state, "•")
        short_state = _STATE_SHORT_LABELS.get(state, state)
        message = task.message or ""
        label = f"{icon} {short_id} · {short_state}"
        if message:
            snippet = message.replace("\n", " ")[:40]
            label = f"{label} · {snippet}"
        action = QAction(label, parent)
        action.setEnabled(False)
        return action

    def _refresh_action(self) -> QAction:
        """Return a Refresh action wired to the tasks menu refresh handler."""
        refresh_action = QAction("Refresh", self.tasks_menu)
        refresh_action.triggered.connect(self._refresh_tasks_menu)
        return refresh_action

    def _open_task_center(self) -> None:
        """Placeholder for the task center UI."""
        print("Open Task Center...")  # noqa: T201

    def _open_connection_manager(self) -> None:
        """Open the platform connection manager dialog."""
        manager = ConnectionManager(self.connections_path)
        dialog = ConnectionManagerDialog(manager)
        dialog.exec()
