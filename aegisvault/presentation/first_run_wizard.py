"""First-run setup wizard for AegisVault."""

from __future__ import annotations

import re
from pathlib import Path

try:
    from PyQt6.QtWidgets import (
        QFileDialog,
        QFormLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPushButton,
        QVBoxLayout,
        QWizard,
        QWizardPage,
    )
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "PyQt6 is required for the AegisVault GUI. "
        "Install the GUI extra: pip install 'aegisvault[gui]'"
    ) from exc

from aegisvault.config import AegisConfig

_DIGIT = re.compile(r"\d")
_UPPER = re.compile(r"[A-Z]")
_LOWER = re.compile(r"[a-z]")
_SPECIAL = re.compile(r"[^a-zA-Z0-9]")


def password_strength(password: str) -> tuple[str, str]:
    """Return (label, colour) for *password* strength."""
    if not password:
        return ("", "")
    types = sum(bool(p.search(password)) for p in (_DIGIT, _UPPER, _LOWER, _SPECIAL))
    length = len(password)
    if length < 8:
        return ("Weak", "red")
    if length < 12 or types < 3:
        return ("Medium", "orange")
    if length < 16 or types < 4:
        return ("Strong", "green")
    return ("Very Strong", "darkgreen")


class WelcomePage(QWizardPage):
    """Welcome / introduction page."""

    def __init__(self) -> None:
        super().__init__()
        self.setTitle("欢迎使用 AegisVault")
        self.setSubTitle("您的本地私密内容管理助手")

        layout = QVBoxLayout(self)

        intro = QLabel(
            "AegisVault 帮助您组织、分类并保护本地文件。\n\n"
            "核心功能:\n"
            "  • 自动文件分类与标签\n"
            "  • 本地 AI 驱动的内容分析\n"
            "  • 加密保险库存储\n"
            "  • Inbox 新文件自动处理\n\n"
            "本向导将帮助您完成 AegisVault 的首次配置。"
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        layout.addStretch()


class PathsPage(QWizardPage):
    """Inbox / Vault directory selection."""

    def __init__(self, config: AegisConfig) -> None:
        super().__init__()
        self.setTitle("路径设置")
        self.setSubTitle("选择 AegisVault 的文件存储位置")

        form = QFormLayout(self)

        self._inbox_edit = QLineEdit(str(config.paths.inbox))
        self._vault_edit = QLineEdit(str(config.paths.vault))

        form.addRow("Inbox 目录:", self._browse_row(self._inbox_edit, "选择 Inbox 目录"))
        form.addRow("Vault 目录:", self._browse_row(self._vault_edit, "选择 Vault 目录"))

        tip = QLabel(
            "<small>Inbox: 放入此目录的文件将被自动处理。\n"
            "Vault: 处理完成后的文件将存储在此处。</small>"
        )
        tip.setWordWrap(True)
        form.addRow(tip)

        self.registerField("inbox_path*", self._inbox_edit)
        self.registerField("vault_path*", self._vault_edit)

    @staticmethod
    def _browse_row(edit: QLineEdit, caption: str) -> QHBoxLayout:
        """Return a horizontal layout pairing *edit* with a browse button."""
        row = QHBoxLayout()
        row.addWidget(edit)
        btn = QPushButton("浏览...")
        btn.clicked.connect(lambda checked: PathsPage._browse_dir(edit, caption))
        row.addWidget(btn)
        return row

    @staticmethod
    def _browse_dir(edit: QLineEdit, caption: str) -> None:
        """Open a directory chooser and update *edit*."""
        current = Path(edit.text())
        if not current.exists():
            current = Path.home()
        chosen = QFileDialog.getExistingDirectory(None, caption, str(current))
        if chosen:
            edit.setText(chosen)


class ModelPage(QWizardPage):
    """Local model connection configuration."""

    def __init__(self, config: AegisConfig) -> None:
        super().__init__()
        self.setTitle("模型连接")
        self.setSubTitle("配置本地 AI 模型端点")

        form = QFormLayout(self)

        self._url_edit = QLineEdit(config.model.base_url)
        self._url_edit.setPlaceholderText("http://127.0.0.1:11434/v1")

        self._name_edit = QLineEdit(config.model.model_name)
        self._name_edit.setPlaceholderText("qwen2.5:7b")

        form.addRow("模型 URL:", self._url_edit)
        form.addRow("模型名称:", self._name_edit)

        self._test_btn = QPushButton("测试连接")
        self._test_label = QLabel("")
        test_row = QHBoxLayout()
        test_row.addWidget(self._test_btn)
        test_row.addWidget(self._test_label)
        test_row.addStretch()
        form.addRow(test_row)

        self._test_btn.clicked.connect(self._on_test)

        tip = QLabel(
            "<small>对于 Ollama，默认 URL 为 http://127.0.0.1:11434/v1。\n"
            "您可稍后在设置中修改此配置。</small>"
        )
        tip.setWordWrap(True)
        form.addRow(tip)

        self.registerField("model_url*", self._url_edit)
        self.registerField("model_name*", self._name_edit)

    def _on_test(self) -> None:
        """Attempt a connection test (placeholder for future implementation)."""
        import httpx

        url = self._url_edit.text().strip()
        self._test_label.setText("正在测试...")
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(f"{url.rstrip('/')}/models")
                if resp.is_success:
                    self._test_label.setText("连接成功")
                else:
                    self._test_label.setText(f"失败 ({resp.status_code})")
        except Exception:
            self._test_label.setText("无法连接")


class SecurityPage(QWizardPage):
    """Master password / security configuration."""

    def __init__(self) -> None:
        super().__init__()
        self.setTitle("安全设置")
        self.setSubTitle("创建主密钥密码以保护您的保险库")

        form = QFormLayout(self)

        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_edit.setPlaceholderText("输入主密钥密码")

        self._confirm_edit = QLineEdit()
        self._confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_edit.setPlaceholderText("确认主密钥密码")

        self._strength_label = QLabel("")

        form.addRow("主密钥密码:", self._password_edit)
        form.addRow("确认密码:", self._confirm_edit)
        form.addRow("密码强度:", self._strength_label)

        self._password_edit.textChanged.connect(self._update_strength)

        warning = QLabel("<b>重要提示:</b> 主密钥密码无法恢复。\n请务必妥善备份！")
        warning.setWordWrap(True)
        form.addRow(warning)

        self.registerField("master_password*", self._password_edit)
        self.registerField("confirm_password*", self._confirm_edit)

    def _update_strength(self, text: str) -> None:
        """Update the password strength indicator."""
        label, colour = password_strength(text)
        if label:
            self._strength_label.setText(
                f'<span style="color:{colour};font-weight:bold">{label}</span>'
            )
        else:
            self._strength_label.setText("")

    def validatePage(self) -> bool:  # noqa: N802
        """Validate that passwords match and meet minimum strength."""
        pwd = str(self.field("master_password"))
        confirm = str(self.field("confirm_password"))
        if pwd != confirm:
            QMessageBox.warning(self, "密码不匹配", "两次输入的密码不一致。")
            return False
        if pwd and len(pwd) < 8:
            QMessageBox.warning(self, "密码太弱", "密码至少需要 8 个字符。")
            return False
        return True


class FinishPage(QWizardPage):
    """Configuration summary and finish."""

    def __init__(self) -> None:
        super().__init__()
        self.setTitle("设置完成")
        self.setSubTitle("确认您的配置")

        layout = QVBoxLayout(self)
        self._summary = QLabel()
        self._summary.setWordWrap(True)
        layout.addWidget(self._summary)
        layout.addStretch()

    def initializePage(self) -> None:  # noqa: N802
        """Build the summary from collected wizard fields."""
        w = self.wizard()
        if w is None:
            return
        inbox = w.field("inbox_path")
        vault = w.field("vault_path")
        url = w.field("model_url")
        model = w.field("model_name")
        has_pwd = bool(w.field("master_password"))

        lines = [
            "<b>配置摘要:</b>",
            "",
            f"  Inbox 目录: {inbox}",
            f"  Vault 目录: {vault}",
            f"  模型 URL: {url}",
            f"  模型名称: {model}",
            f"  主密钥密码: {'已设置' if has_pwd else '未设置'}",
            "",
            "点击“完成”保存配置并启动 AegisVault。",
        ]
        self._summary.setText("<br>".join(lines))


class FirstRunWizard(QWizard):
    """First-run setup wizard that collects and saves AegisVault configuration."""

    def __init__(self, config: AegisConfig, parent: QWizard | None = None) -> None:
        super().__init__(parent)
        self._config = config

        self.setWindowTitle("AegisVault 设置向导")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)

        self.addPage(WelcomePage())
        self.addPage(PathsPage(config))
        self.addPage(ModelPage(config))
        self.addPage(SecurityPage())
        self.addPage(FinishPage())

    def accept(self) -> None:
        """Apply wizard fields to the configuration and persist to disk."""
        inbox = Path(str(self.field("inbox_path")))
        vault = Path(str(self.field("vault_path")))
        model_url = str(self.field("model_url"))
        model_name = str(self.field("model_name"))
        password = str(self.field("master_password"))

        self._config.paths.inbox = inbox
        self._config.paths.vault = vault
        self._config.model.base_url = model_url
        self._config.model.model_name = model_name
        if password:
            self._config.security.master_key_password = password
            self._config.security.master_key_provider = "FilePassword"

        self._config.save_to_file()
        super().accept()
