"""Vault browser UI for AegisVault."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import (
        QAbstractItemView,
        QDialog,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QMenu,
        QMessageBox,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QTreeWidget,
        QTreeWidgetItem,
        QVBoxLayout,
        QWidget,
    )
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "PyQt6 is required for the AegisVault GUI. "
        "Install the GUI extra: pip install 'aegisvault[gui]'"
    ) from exc

from aegisvault.api.schemas import ClassificationResult
from aegisvault.execution.vault import VaultManager
from aegisvault.orchestration.state_machine import TaskState
from aegisvault.orchestration.task_store import TaskStore


class VaultBrowser(QDialog):
    """Browse, preview and manage completed Vault tasks."""

    def __init__(
        self,
        task_store: TaskStore | None,
        vault_path: Path,
        vault_key: bytes | None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.task_store = task_store
        self.vault_path = vault_path
        self.vault_key = vault_key
        self.vault_manager = VaultManager(vault_path, vault_key) if vault_key else None
        self._items: list[dict[str, Any]] = []

        self.setWindowTitle("Vault Browser")
        self.setMinimumSize(900, 600)

        main_layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.category_tree = QTreeWidget()
        self.category_tree.setHeaderLabel("Categories")
        self._all_item = QTreeWidgetItem(self.category_tree, ["All"])
        self.category_tree.addTopLevelItem(self._all_item)
        self.category_tree.currentItemChanged.connect(self._filter_changed)
        splitter.addWidget(self.category_tree)

        self.file_table = QTableWidget()
        self.file_table.setColumnCount(4)
        self.file_table.setHorizontalHeaderLabels(
            ["Disguise Name", "Category", "Sensitivity", "Timestamp"]
        )
        header = self.file_table.horizontalHeader()
        assert header is not None
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.file_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.file_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.file_table.itemSelectionChanged.connect(self._selection_changed)
        self.file_table.cellDoubleClicked.connect(self._decrypt_selected)
        self.file_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self._show_context_menu)
        splitter.addWidget(self.file_table)

        preview = QWidget()
        preview_layout = QVBoxLayout(preview)
        preview_layout.addWidget(QLabel("Preview / Metadata"))
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        preview_layout.addWidget(self.preview_text)
        splitter.addWidget(preview)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        splitter.setStretchFactor(2, 2)
        main_layout.addWidget(splitter)

        self._load_items()
        self._refresh_categories()
        self._refresh_table()

    def _load_items(self) -> None:
        """Load COMPLETED tasks with classification metadata."""
        self._items = []
        if self.task_store is None:
            return

        with self.task_store._connect(row_factory=sqlite3.Row) as conn:
            rows = conn.execute(
                """
                SELECT task_id, vault_path, salt, classification, created_at, updated_at
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
            self._items.append(
                {
                    "task_id": row["task_id"],
                    "vault_path": Path(row["vault_path"]),
                    "salt": row["salt"],
                    "classification": classification,
                    "timestamp": row["updated_at"] or row["created_at"] or "",
                }
            )

    def _refresh_categories(self) -> None:
        """Populate the category tree from loaded items."""
        self.category_tree.clear()
        self._all_item = QTreeWidgetItem(self.category_tree, ["All"])
        self.category_tree.addTopLevelItem(self._all_item)
        for category in sorted({item["classification"].category for item in self._items}):
            self.category_tree.addTopLevelItem(QTreeWidgetItem(self.category_tree, [category]))
        self.category_tree.setCurrentItem(self._all_item)

    def _selected_category(self) -> str | None:
        """Return the selected category filter, or None for "All"."""
        item = self.category_tree.currentItem()
        if item is None or item == self._all_item:
            return None
        return item.text(0)

    def _visible_items(self) -> list[dict[str, Any]]:
        """Return items matching the current category filter."""
        category = self._selected_category()
        if category is None:
            return list(self._items)
        return [item for item in self._items if item["classification"].category == category]

    def _filter_changed(
        self,
        _current: QTreeWidgetItem | None,
        _previous: QTreeWidgetItem | None,
    ) -> None:
        """Refresh the file list when the category selection changes."""
        self._refresh_table()

    def _refresh_table(self) -> None:
        """Render visible items into the file table."""
        visible = self._visible_items()
        self.file_table.setRowCount(len(visible))
        for row, item in enumerate(visible):
            classification = item["classification"]
            self.file_table.setItem(row, 0, QTableWidgetItem(classification.disguise_name))
            self.file_table.setItem(row, 1, QTableWidgetItem(classification.category))
            self.file_table.setItem(row, 2, QTableWidgetItem(classification.sensitivity.value))
            self.file_table.setItem(row, 3, QTableWidgetItem(item["timestamp"]))
        self._selection_changed()

    def _current_item(self) -> dict[str, Any] | None:
        """Return the item for the first selected table row."""
        selected = self.file_table.selectedItems()
        if not selected:
            return None
        row = selected[0].row()
        visible = self._visible_items()
        if row < 0 or row >= len(visible):
            return None
        return visible[row]

    def _selection_changed(self) -> None:
        """Update the preview panel for the selected item."""
        item = self._current_item()
        if item is None:
            self.preview_text.setPlainText("Select a Vault item to view metadata.")
            return
        classification = item["classification"]
        lines = [
            f"Task ID: {item['task_id']}",
            f"Vault Path: {item['vault_path']}",
            f"Disguise Name: {classification.disguise_name}",
            f"Category: {classification.category}",
            f"Sensitivity: {classification.sensitivity.value}",
            f"Tags: {', '.join(classification.tags)}",
            f"Summary: {classification.summary}",
            f"Timestamp: {item['timestamp']}",
        ]
        self.preview_text.setPlainText("\n".join(lines))

    def _show_context_menu(self, position: Any) -> None:
        """Show the Decrypt / Open / Delete context menu."""
        item = self._current_item()
        if item is None:
            return
        menu = QMenu(self)
        decrypt_action = menu.addAction("Decrypt")
        open_action = menu.addAction("Open")
        delete_action = menu.addAction("Delete")
        if decrypt_action is None or open_action is None or delete_action is None:
            return
        viewport = self.file_table.viewport()
        if viewport is None:
            return
        decrypt_action.triggered.connect(lambda _checked=False, i=item: self._decrypt_item(i))
        open_action.triggered.connect(lambda _checked=False, i=item: self._open_item(i))
        delete_action.triggered.connect(lambda _checked=False, i=item: self._delete_item(i))
        menu.exec(viewport.mapToGlobal(position))

    def _decrypt_selected(self, _row: int, _column: int) -> None:
        """Decrypt the currently selected item on double-click."""
        self._decrypt_item(self._current_item())

    def _decrypt_item(self, item: dict[str, Any] | None) -> None:
        """Decrypt *item* to a temporary path and show the result."""
        if item is None:
            return
        if self.vault_manager is None:
            QMessageBox.warning(self, "Decrypt", "No vault key configured.")
            return
        try:
            fd, dest = tempfile.mkstemp(prefix="aegisvault_", suffix="_decrypted")
            os.close(fd)
            self.vault_manager.decrypt(item["vault_path"], item["salt"], Path(dest))
            self.preview_text.setPlainText(f"Decrypted to:\n{dest}")
        except Exception as exc:
            QMessageBox.warning(self, "Decrypt", f"Decrypt failed: {exc}")

    def _open_item(self, item: dict[str, Any] | None) -> None:
        """Decrypt *item* and open it with the platform default application."""
        if item is None:
            return
        if self.vault_manager is None:
            QMessageBox.warning(self, "Open", "No vault key configured.")
            return
        try:
            fd, dest = tempfile.mkstemp(prefix="aegisvault_", suffix="_decrypted")
            os.close(fd)
            self.vault_manager.decrypt(item["vault_path"], item["salt"], Path(dest))
            self._open_path(Path(dest))
        except Exception as exc:
            QMessageBox.warning(self, "Open", f"Open failed: {exc}")

    @staticmethod
    def _open_path(path: Path) -> None:
        """Open *path* with the platform's default application."""
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        else:
            subprocess.run(["xdg-open", str(path)], check=False)

    def _delete_item(self, item: dict[str, Any] | None) -> None:
        """Delete *item* from the task store and the Vault filesystem."""
        if item is None:
            return
        classification = item["classification"]
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Delete '{classification.disguise_name}'?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            if self.task_store is not None:
                from uuid import UUID

                self.task_store.delete(UUID(item["task_id"]))
            item["vault_path"].unlink(missing_ok=True)
            self._load_items()
            self._refresh_categories()
            self._refresh_table()
        except Exception as exc:
            QMessageBox.warning(self, "Delete", f"Delete failed: {exc}")
