"""Headless PyQt6 stubs for presentation layer tests."""

# mypy: ignore-errors

# ruff: noqa: N802

from __future__ import annotations

import types
from typing import Any


class FakeSignal:
    """Stub Qt signal for headless tests."""

    def __init__(self) -> None:
        self.connected: list[object] = []

    def connect(self, callback: object) -> None:
        self.connected.append(callback)


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


class FakeLabel:
    """Stub QLabel for headless tests."""

    def __init__(self, text: str = "") -> None:
        self.text = text

    def setText(self, text: str) -> None:
        self.text = text

    def setAlignment(self, _alignment: object) -> None:
        pass

    def setWordWrap(self, _enabled: bool) -> None:
        pass


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

    _instance: FakeApplication | None = None

    def __init__(self, _args: object) -> None:
        if FakeApplication._instance is None:
            FakeApplication._instance = self
        self.quit_called = False

    def quit(self) -> None:
        self.quit_called = True

    def exec(self) -> int:
        return 0

    @classmethod
    def instance(cls) -> FakeApplication | None:
        return cls._instance


# --- Dialog stubs ---


class FakeDialog:
    """Stub QDialog for headless tests."""

    class DialogCode:
        Accepted = 1
        Rejected = 0

    def __init__(self) -> None:
        self._title = ""
        self._minimum_width = 0
        self._minimum_size: tuple[int, int] = (0, 0)
        self._exec_result = self.DialogCode.Accepted

    def setWindowTitle(self, title: str) -> None:
        self._title = title

    def setMinimumWidth(self, width: int) -> None:
        self._minimum_width = width

    def setMinimumSize(self, width: int, height: int) -> None:
        self._minimum_size = (width, height)

    def exec(self) -> int:
        if self._exec_result == self.DialogCode.Accepted:
            self.accept()
        return self._exec_result

    def accept(self) -> None:
        pass

    def reject(self) -> None:
        pass


class FakeDialogButtonBox:
    """Stub QDialogButtonBox for headless tests."""

    class StandardButton:
        Save = 1
        Cancel = 2

    def __init__(self, _buttons: object = None) -> None:
        self.accepted = FakeSignal()
        self.rejected = FakeSignal()


class FakeMessageBox:
    """Stub QMessageBox for headless tests."""

    class StandardButton:
        Yes = 1
        No = 2

    _last_warning: tuple[object, str, str] | None = None
    _last_information: tuple[object, str, str] | None = None
    _last_question: tuple[object, str, str] | None = None

    @classmethod
    def warning(cls, parent: object, title: str, text: str) -> None:
        cls._last_warning = (parent, title, text)

    @classmethod
    def information(cls, parent: object, title: str, text: str) -> None:
        cls._last_information = (parent, title, text)

    @classmethod
    def question(cls, parent: object, title: str, text: str) -> int:
        cls._last_question = (parent, title, text)
        return cls.StandardButton.Yes


class FakeLineEdit:
    """Stub QLineEdit for headless tests."""

    class EchoMode:
        Password = 2
        Normal = 0

    def __init__(self) -> None:
        self._text = ""
        self._placeholder = ""
        self._echo_mode = self.EchoMode.Normal
        self._style_sheet = ""

    def text(self) -> str:
        return self._text

    def setText(self, text: str) -> None:
        self._text = text

    def setPlaceholderText(self, text: str) -> None:
        self._placeholder = text

    def setEchoMode(self, mode: int) -> None:
        self._echo_mode = mode

    def setStyleSheet(self, sheet: str) -> None:
        self._style_sheet = sheet


class FakeComboBox:
    """Stub QComboBox for headless tests."""

    def __init__(self) -> None:
        self._items: list[str] = []
        self._current = ""

    def addItems(self, items: list[str]) -> None:
        self._items = list(items)
        if self._items and not self._current:
            self._current = self._items[0]

    def currentText(self) -> str:
        return self._current

    def setCurrentText(self, text: str) -> None:
        self._current = text


class FakeCheckBox:
    """Stub QCheckBox for headless tests."""

    def __init__(self, text: str = "") -> None:
        self._text = text
        self._checked = False
        self._tooltip = ""

    def setText(self, text: str) -> None:
        self._text = text

    def setToolTip(self, tooltip: str) -> None:
        self._tooltip = tooltip

    def setChecked(self, checked: bool) -> None:
        self._checked = checked

    def isChecked(self) -> bool:
        return self._checked


class FakePushButton:
    """Stub QPushButton for headless tests."""

    def __init__(self, text: str = "") -> None:
        self.text = text
        self.clicked = FakeSignal()


class FakeTableWidgetItem:
    """Stub QTableWidgetItem for headless tests."""

    def __init__(self, text: str = "") -> None:
        self._text = text
        self._row = -1
        self._column = -1

    def text(self) -> str:
        return self._text

    def row(self) -> int:
        return self._row

    def column(self) -> int:
        return self._column


class FakeTableWidget:
    """Stub QTableWidget for headless tests."""

    def __init__(self) -> None:
        self._column_count = 0
        self._horizontal_labels: list[str] = []
        self._row_count = 0
        self._items: dict[tuple[int, int], FakeTableWidgetItem] = {}
        self._selection_behavior = 0
        self._edit_triggers = 0
        self._selected: list[FakeTableWidgetItem] = []
        self._header = FakeHeaderView()

    def setColumnCount(self, count: int) -> None:
        self._column_count = count

    def setHorizontalHeaderLabels(self, labels: list[str]) -> None:
        self._horizontal_labels = labels

    def horizontalHeader(self) -> FakeHeaderView:
        return self._header

    def setSelectionBehavior(self, behavior: int) -> None:
        self._selection_behavior = behavior

    def setEditTriggers(self, triggers: int) -> None:
        self._edit_triggers = triggers

    def setRowCount(self, count: int) -> None:
        self._row_count = count

    def setItem(self, row: int, column: int, item: FakeTableWidgetItem) -> None:
        item._row = row
        item._column = column
        self._items[(row, column)] = item

    def item(self, row: int, column: int) -> FakeTableWidgetItem | None:
        return self._items.get((row, column))

    def selectedItems(self) -> list[FakeTableWidgetItem]:
        return list(self._selected)

    def select_row(self, row: int) -> None:
        """Test helper to select a whole row."""
        self._selected = [item for (r, c), item in self._items.items() if r == row]


class FakeHeaderView:
    """Stub QHeaderView for headless tests."""

    class ResizeMode:
        Stretch = 1

    def setSectionResizeMode(self, _mode: int) -> None:
        pass


class FakeAbstractItemView:
    """Stub QAbstractItemView for headless tests."""

    class SelectionBehavior:
        SelectRows = 1

    class EditTrigger:
        NoEditTriggers = 0


class FakeFormLayout:
    """Stub QFormLayout for headless tests."""

    def __init__(self, _parent: object | None = None) -> None:
        self._rows: list[tuple[str | None, object]] = []

    def addRow(self, label: object, widget: object | None = None) -> None:
        if widget is None:
            self._rows.append((None, label))
        else:
            self._rows.append((str(label), widget))


class FakeVBoxLayout:
    """Stub QVBoxLayout for headless tests."""

    def __init__(self, _parent: object | None = None) -> None:
        self._widgets: list[object] = []
        self._layouts: list[object] = []

    def addWidget(self, widget: object) -> None:
        self._widgets.append(widget)

    def addLayout(self, layout: object) -> None:
        self._layouts.append(layout)


class FakeHBoxLayout(FakeVBoxLayout):
    """Stub QHBoxLayout for headless tests."""

    def addStretch(self) -> None:
        pass


class FakeQt:
    """Stub Qt namespace for headless tests."""

    class AlignmentFlag:
        AlignLeft = 1


def install_presentation_stubs() -> dict[str, Any]:
    """Install fake PyQt6 modules and return the saved originals."""
    import sys

    saved_modules: dict[str, Any] = {
        "PyQt6": sys.modules.get("PyQt6"),
        "PyQt6.QtCore": sys.modules.get("PyQt6.QtCore"),
        "PyQt6.QtGui": sys.modules.get("PyQt6.QtGui"),
        "PyQt6.QtWidgets": sys.modules.get("PyQt6.QtWidgets"),
    }

    fake_qt = types.ModuleType("PyQt6")
    fake_qt_gui = types.ModuleType("PyQt6.QtGui")
    fake_qt_widgets = types.ModuleType("PyQt6.QtWidgets")
    fake_qt_core = types.ModuleType("PyQt6.QtCore")

    fake_qt_gui.QAction = FakeAction

    fake_qt_core.Qt = FakeQt

    fake_qt_widgets.QAbstractItemView = FakeAbstractItemView
    fake_qt_widgets.QApplication = FakeApplication
    fake_qt_widgets.QCheckBox = FakeCheckBox
    fake_qt_widgets.QComboBox = FakeComboBox
    fake_qt_widgets.QDialog = FakeDialog
    fake_qt_widgets.QDialogButtonBox = FakeDialogButtonBox
    fake_qt_widgets.QFormLayout = FakeFormLayout
    fake_qt_widgets.QHBoxLayout = FakeHBoxLayout
    fake_qt_widgets.QHeaderView = FakeHeaderView
    fake_qt_widgets.QLabel = FakeLabel
    fake_qt_widgets.QLineEdit = FakeLineEdit
    fake_qt_widgets.QMenu = FakeMenu
    fake_qt_widgets.QMessageBox = FakeMessageBox
    fake_qt_widgets.QProgressBar = FakeProgressBar
    fake_qt_widgets.QPushButton = FakePushButton
    fake_qt_widgets.QSystemTrayIcon = FakeSystemTrayIcon
    fake_qt_widgets.QTableWidget = FakeTableWidget
    fake_qt_widgets.QTableWidgetItem = FakeTableWidgetItem
    fake_qt_widgets.QVBoxLayout = FakeVBoxLayout
    fake_qt_widgets.QWidget = object
    fake_qt_widgets.QWidgetAction = FakeWidgetAction

    sys.modules["PyQt6"] = fake_qt
    sys.modules["PyQt6.QtCore"] = fake_qt_core
    sys.modules["PyQt6.QtGui"] = fake_qt_gui
    sys.modules["PyQt6.QtWidgets"] = fake_qt_widgets

    return saved_modules


def restore_modules(saved_modules: dict[str, Any]) -> None:
    """Restore the original PyQt6 modules and clear submodule caches."""
    import sys

    sys.modules.update(saved_modules)
    sys.modules.pop("aegisvault.presentation.tray", None)
    sys.modules.pop("aegisvault.presentation.connection_dialog", None)
    # Force re-import of presentation submodules on the next test by clearing
    # the package-level cache as well.
    presentation = sys.modules.get("aegisvault.presentation")
    if presentation is not None:
        presentation.__dict__.pop("tray", None)
        presentation.__dict__.pop("connection_dialog", None)
