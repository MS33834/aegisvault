"""System tray application with connection management entry."""

import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

try:
    from PyQt6.QtGui import QAction
    from PyQt6.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QComboBox,
        QDialog,
        QFormLayout,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMenu,
        QProgressBar,
        QPushButton,
        QSystemTrayIcon,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidgetAction,
    )
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "PyQt6 is required for the AegisVault GUI. "
        "Install the GUI extra: pip install 'aegisvault[gui]'"
    ) from exc

from aegisvault import __version__
from aegisvault.api.schemas import ClassificationResult, SensitivityLevel, TaskSummary
from aegisvault.config import AegisConfig
from aegisvault.execution.vault import VaultManager
from aegisvault.orchestration.state_machine import TaskState
from aegisvault.orchestration.task_store import TaskStore
from aegisvault.platform.manager import ConnectionManager
from aegisvault.presentation.connection_dialog import ConnectionManagerDialog
from aegisvault.presentation.settings_dialog import SettingsDialog
from aegisvault.presentation.vault_browser import VaultBrowser

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

_STATE_DETAILS: dict[str, str] = {
    TaskState.IDLE.name: "任务等待处理",
    TaskState.CLASSIFYING.name: "正在识别内容类别",
    TaskState.ENCRYPTING.name: "正在加密并写入保险库",
    TaskState.INDEXING.name: "正在建立索引",
    TaskState.COMPLETED.name: "已完成加密归档",
    TaskState.FAILED.name: "处理失败，需要关注",
    TaskState.QUARANTINED.name: "已隔离，等待人工复核",
}

_STATUS_ICONS = {
    "secure": "🔐",
    "warning": "⚠️",
    "offline": "🔌",
    "online": "🌐",
    "busy": "⚙️",
    "idle": "💤",
}


class TrayApplication:
    """System tray application."""

    def __init__(
        self,
        connections_path: Path | None = None,
        config: AegisConfig | None = None,
        vault_key: bytes | None = None,
    ) -> None:
        existing = QApplication.instance()
        self.app = existing if isinstance(existing, QApplication) else QApplication([])
        self.tray = QSystemTrayIcon()
        self.menu = QMenu()
        self.config = config
        self.vault_key = vault_key
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
        self._build_menu()
        self._refresh_header()
        self.tray.setContextMenu(self.menu)
        self.tray.setVisible(True)
        self.tray.setToolTip("AegisVault")
        self.app.exec()

    def _build_menu(self) -> None:
        """Construct the context menu structure."""
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

        settings_action = QAction("⚙️ Settings...", self.menu)
        settings_action.triggered.connect(self._open_settings)
        self.menu.addAction(settings_action)

        vault_browser_action = QAction("🗄️ Vault Browser...", self.menu)
        vault_browser_action.triggered.connect(self._open_vault_browser)
        self.menu.addAction(vault_browser_action)

        self.menu.addSeparator()
        self.menu.addSection("ℹ️ Help")

        about_action = QAction(f"About AegisVault v{__version__}", self.menu)
        about_action.triggered.connect(self._show_about)
        self.menu.addAction(about_action)

        docs_action = QAction("📖 Open Documentation", self.menu)
        docs_action.triggered.connect(self._open_docs)
        self.menu.addAction(docs_action)

        self.menu.addSeparator()
        quit_action = QAction("🚪 Quit", self.menu)
        quit_action.triggered.connect(self.app.quit)
        self.menu.addAction(quit_action)

    def _add_quick_actions(self, menu: QMenu) -> None:
        """Add static quick-entry actions with icons and grouping."""
        menu.addSection("⚡ Quick Actions")

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
        menu.addSection("🔔 Activity")
        notifications = QAction("🔔 Notifications (0)", menu)
        notifications.setEnabled(False)
        menu.addAction(notifications)

        status_summary = QAction(self._activity_summary_text(), menu)
        status_summary.setEnabled(False)
        menu.addAction(status_summary)

    def _activity_summary_text(self) -> str:
        """Return a short activity summary string for the quick actions panel."""
        if self.task_store is None:
            return "📦 Tasks not configured"
        counts = self.task_store.counts_by_state()
        total = sum(counts.values())
        completed = counts.get(TaskState.COMPLETED.name, 0)
        failed = counts.get(TaskState.FAILED.name, 0)
        quarantined = counts.get(TaskState.QUARANTINED.name, 0)
        active = total - completed - failed - quarantined
        parts = [f"📋 总计 {total}"]
        if active:
            parts.append(f"⚙️ 进行中 {active}")
        parts.append(f"✅ 完成 {completed}")
        if failed:
            parts.append(f"❌ 失败 {failed}")
        if quarantined:
            parts.append(f"⚠️ 隔离 {quarantined}")
        return " · ".join(parts)

    def _open_inbox(self) -> None:
        """Open the configured inbox directory in the file manager."""
        inbox = self.config.paths.inbox if self.config else Path.home() / "AegisVault" / "Inbox"
        inbox.mkdir(parents=True, exist_ok=True)
        self._open_path_in_file_manager(inbox)

    def _open_vault(self) -> None:
        """Open the configured vault directory in the file manager."""
        vault = self.config.paths.vault if self.config else Path.home() / "AegisVault" / "Vault"
        vault.mkdir(parents=True, exist_ok=True)
        self._open_path_in_file_manager(vault)

    def _search_vault(self) -> None:
        """Open the vault search dialog."""
        if self.config is not None:
            vault_path = self.config.paths.vault
        else:
            vault_path = Path.home() / "AegisVault" / "Vault"
        dialog = SearchVaultDialog(self.task_store, vault_path, self.vault_key)
        dialog.exec()

    def _open_dashboard(self) -> None:
        """Show a dashboard summary dialog with task statistics."""
        from PyQt6.QtWidgets import QMessageBox

        if self.task_store is None:
            QMessageBox.information(self.menu, "Dashboard", "Task store not configured.")
            return

        counts = self.task_store.counts_by_state()
        total = sum(counts.values())
        completed = counts.get(TaskState.COMPLETED.name, 0)
        failed = counts.get(TaskState.FAILED.name, 0)
        quarantined = counts.get(TaskState.QUARANTINED.name, 0)
        active = total - completed - failed - quarantined

        vault_size = self._vault_size_text()
        local_ok = any(
            conn.is_enabled and conn.is_trusted_local()
            for conn in self.connection_manager.list_all()
        )
        conn_status = "✅ 本地连接正常" if local_ok else "⚠️ 未配置本地连接"

        text = (
            f"🔐 AegisVault Dashboard\n\n"
            f"━━━ 任务统计 ━━━\n"
            f"📋 总计: {total}\n"
            f"⚙️ 进行中: {active}\n"
            f"✅ 已完成: {completed}\n"
            f"❌ 失败: {failed}\n"
            f"⚠️ 隔离: {quarantined}\n\n"
            f"━━━ 存储状态 ━━━\n"
            f"📦 Vault 大小: {vault_size}\n"
            f"🔌 连接状态: {conn_status}"
        )
        QMessageBox.information(self.menu, "📊 Dashboard", text)

    def _show_about(self) -> None:
        """Show the About dialog with version and description."""
        from PyQt6.QtWidgets import QMessageBox

        text = (
            f"<h3>🔐 AegisVault</h3>"
            f"<p>Version {__version__}</p>"
            f"<p>Local private content management agent.</p>"
            f"<p>Inbox → Classify → Encrypt → Vault</p>"
            f"<hr/>"
            f"<p><small>AES-256-GCM encryption · Argon2id key derivation · "
            f"Sandboxed execution · Offline verification</small></p>"
        )
        QMessageBox.about(self.menu, "About AegisVault", text)

    def _open_docs(self) -> None:
        """Open the documentation in the default browser."""
        from PyQt6.QtCore import QUrl
        from PyQt6.QtGui import QDesktopServices

        url = QUrl("https://github.com/MS33834/AegisVault")
        QDesktopServices.openUrl(url)

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
        total_bytes = sum(f.stat().st_size for f in vault.rglob("*") if f.is_file())
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
        self.connections_menu.addSection("🔌 Enabled Connections")
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
        self.tasks_menu.addSection("📈 Task Activity")

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
        detail = _STATE_DETAILS.get(state, "")
        message = task.message or ""
        label = f"{icon} {short_id} · {short_state}"
        if message:
            snippet = message.replace("\n", " ")[:40]
            label = f"{label} · {snippet}"
        action = QAction(label, parent)
        action.setEnabled(False)
        action.setToolTip(detail)
        return action

    def _refresh_action(self) -> QAction:
        """Return a Refresh action wired to the tasks menu refresh handler."""
        refresh_action = QAction("🔄 Refresh", self.tasks_menu)
        refresh_action.triggered.connect(self._refresh_tasks_menu)
        return refresh_action

    def _open_task_center(self) -> None:
        """Open the Vault Browser as the task center."""
        self._open_vault_browser()

    def _open_connection_manager(self) -> None:
        """Open the platform connection manager dialog."""
        manager = ConnectionManager(self.connections_path)
        dialog = ConnectionManagerDialog(manager)
        dialog.exec()

    def _open_settings(self) -> None:
        """Open the settings dialog."""
        config = self.config or AegisConfig()
        dialog = SettingsDialog(config)
        dialog.exec()

    def _open_vault_browser(self) -> None:
        """Open the Vault browser dialog."""
        vault_path = (
            self.config.paths.vault
            if self.config is not None
            else Path.home() / "AegisVault" / "Vault"
        )
        dialog = VaultBrowser(self.task_store, vault_path, self.vault_key)
        dialog.exec()

    @staticmethod
    def _open_path_in_file_manager(path: Path) -> None:
        """Open *path* in the platform's default file manager."""
        import sys

        if sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            import subprocess

            subprocess.run(["open", str(path)], check=False)
        else:
            import subprocess

            subprocess.run(["xdg-open", str(path)], check=False)


class SearchVaultDialog(QDialog):
    """Search and open encrypted Vault files."""

    def __init__(
        self,
        task_store: TaskStore | None,
        vault_path: Path,
        vault_key: bytes | None,
    ) -> None:
        super().__init__()
        self.task_store = task_store
        self.vault_path = vault_path
        self.vault_key = vault_key
        self.vault_manager = VaultManager(vault_path, vault_key) if vault_key is not None else None
        self._results: list[dict[str, Any]] = []

        self.setWindowTitle("🔍 Search Vault")
        self.setMinimumSize(800, 500)

        layout = QVBoxLayout(self)

        filter_layout = QFormLayout()
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText("Search name, category, summary, tags...")
        self.category_combo = QComboBox()
        self.category_combo.setEditable(True)
        self.category_combo.setCurrentText("(any)")
        self.sensitivity_combo = QComboBox()
        self.sensitivity_combo.addItem("(any)")
        for level in SensitivityLevel:
            self.sensitivity_combo.addItem(level.value)
        self.tags_input = QLineEdit()
        self.tags_input.setPlaceholderText("tag1, tag2, ...")

        filter_layout.addRow("Keyword:", self.keyword_input)
        filter_layout.addRow("Category:", self.category_combo)
        filter_layout.addRow("Sensitivity:", self.sensitivity_combo)
        filter_layout.addRow("Tags:", self.tags_input)
        layout.addLayout(filter_layout)

        button_layout = QHBoxLayout()
        self.search_button = QPushButton("🔍 Search")
        self.search_button.clicked.connect(self._run_search)
        button_layout.addWidget(self.search_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(
            ["Disguise Name", "Category", "Sensitivity", "Summary"]
        )
        header = self.results_table.horizontalHeader()
        assert header is not None
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.results_table.cellDoubleClicked.connect(self._open_result)
        layout.addWidget(self.results_table)

        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

        self._load_categories()
        self._run_search()

    def _load_categories(self) -> None:
        """Populate the category filter with existing Vault categories."""
        if self.task_store is None:
            return
        categories: set[str] = set()
        with self.task_store._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                "SELECT classification FROM tasks WHERE state = ? AND vault_path IS NOT NULL",
                (TaskState.COMPLETED.name,),
            ).fetchall()
        for row in rows:
            classification_json = row["classification"]
            if not classification_json:
                continue
            try:
                classification = ClassificationResult.model_validate_json(classification_json)
            except Exception:
                continue
            if classification.category:
                categories.add(classification.category)
        for category in sorted(categories):
            self.category_combo.addItem(category)

    def _fetch_results(self) -> list[dict[str, Any]]:
        """Return Vault items matching the current filters."""
        if self.task_store is None:
            return []

        keyword = self.keyword_input.text().strip().lower()
        category = self.category_combo.currentText().strip()
        sensitivity = self.sensitivity_combo.currentText().strip()
        requested_tags = [
            tag.strip() for tag in self.tags_input.text().strip().lower().split(",") if tag.strip()
        ]

        results: list[dict[str, Any]] = []
        with self.task_store._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                """
                SELECT task_id, vault_path, salt, classification
                FROM tasks
                WHERE state = ? AND vault_path IS NOT NULL
                """,
                (TaskState.COMPLETED.name,),
            ).fetchall()

        for row in rows:
            classification_json = row["classification"]
            if not classification_json:
                continue
            try:
                classification = ClassificationResult.model_validate_json(classification_json)
            except Exception:
                continue

            if category and category != "(any)" and classification.category != category:
                continue
            if (
                sensitivity
                and sensitivity != "(any)"
                and classification.sensitivity.value != sensitivity
            ):
                continue
            if requested_tags and not any(
                requested in [tag.lower() for tag in classification.tags]
                for requested in requested_tags
            ):
                continue
            if keyword:
                haystack = " ".join(
                    [
                        classification.disguise_name,
                        classification.category,
                        classification.summary,
                        " ".join(classification.tags),
                    ]
                ).lower()
                if keyword not in haystack:
                    continue

            results.append(
                {
                    "task_id": row["task_id"],
                    "vault_path": Path(row["vault_path"]),
                    "salt": row["salt"],
                    "classification": classification,
                }
            )

        return results

    def _refresh_table(self) -> None:
        """Render the current results into the results table."""
        self.results_table.setRowCount(len(self._results))
        for row, result in enumerate(self._results):
            classification = result["classification"]
            self.results_table.setItem(row, 0, QTableWidgetItem(classification.disguise_name))
            self.results_table.setItem(row, 1, QTableWidgetItem(classification.category))
            self.results_table.setItem(row, 2, QTableWidgetItem(classification.sensitivity.value))
            self.results_table.setItem(row, 3, QTableWidgetItem(classification.summary))

    def _run_search(self) -> None:
        """Execute the search and refresh the results table."""
        self._results = self._fetch_results()
        self._refresh_table()
        self.status_label.setText(f"Found {len(self._results)} result(s)")

    def _open_result(self, row: int, _column: int) -> None:
        """Decrypt the selected Vault file to a temporary location."""
        if row < 0 or row >= len(self._results):
            return

        if self.vault_manager is None:
            self.status_label.setText("Decrypt failed: no vault key configured")
            return

        result = self._results[row]
        try:
            fd, dest_path = tempfile.mkstemp(prefix="aegisvault_", suffix="_decrypted")
            os.close(fd)
            self.vault_manager.decrypt(result["vault_path"], result["salt"], Path(dest_path))
            self.status_label.setText(f"Decrypted to: {dest_path}")
        except Exception as exc:
            self.status_label.setText(f"Decrypt failed: {exc}")
