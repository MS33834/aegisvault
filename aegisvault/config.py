"""Configuration management for AegisVault."""

import json
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ModelConfig(BaseSettings):
    """Model service configuration."""

    base_url: str = "http://127.0.0.1:11434/v1"
    model_name: str = "qwen2.5:7b"
    ctx_size: int = 32768
    temperature: float = 0.3
    timeout: float = 120.0
    fallback_model_name: str | None = None


class SecurityConfig(BaseSettings):
    """Security configuration."""

    kdf: str = "Argon2id"
    encryption: str = "AES-256-GCM"
    master_key_provider: str = "FilePassword"  # FilePassword | DPAPI | TPM
    master_key_password: str | None = None  # Only for FilePassword provider
    windows_hello_enabled: bool = False  # Require Windows Hello before unlocking
    enable_semantic_search: bool = False
    semantic_model: str = "all-MiniLM-L6-v2"
    sandbox_enabled: bool = False
    password_vault: str = "none"  # KeePassXC | pass | none
    password_store: str = "pass"  # pass | keepassxc | none
    password_store_database: Path | None = None  # KeePassXC database
    password_store_password: str | None = None  # KeePassXC database password
    password_store_key_file: Path | None = None  # KeePassXC key file
    password_store_dir: Path | None = None  # PASSWORD_STORE_DIR


class PathConfig(BaseSettings):
    """Path configuration."""

    inbox: Path = Path.home() / "AegisVault" / "Inbox"
    vault: Path = Path.home() / "AegisVault" / "Vault"
    index: Path = Path.home() / "AegisVault" / "Index"
    logs: Path = Path.home() / "AegisVault" / "Logs"
    connections: Path = Path.home() / "AegisVault" / "Config" / "connections.json"
    settings: Path = Path.home() / "AegisVault" / "Config" / "settings.json"


class AegisConfig(BaseSettings):
    """Global application settings."""

    model_config = SettingsConfigDict(
        env_prefix="AEGISVAULT_",
        env_nested_separator="__",  # type: ignore[typeddict-unknown-key]
    )

    app_name: str = "AegisVault"
    debug: bool = False
    model: ModelConfig = Field(default_factory=ModelConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    paths: PathConfig = Field(default_factory=PathConfig)

    def save_to_file(self, path: Path | None = None) -> None:
        """Serialize the current configuration to *path* as JSON."""
        target = path or self.paths.settings
        target.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump(mode="json")
        # Never persist secrets to disk in plaintext.
        security = data.get("security", {})
        security.pop("master_key_password", None)
        security.pop("password_store_password", None)
        content = json.dumps(data, indent=2, default=str)
        tmp_path = target.with_suffix(".tmp")
        tmp_path.write_text(content, encoding="utf-8")
        tmp_path.replace(target)

    @classmethod
    def load_from_file(cls, path: Path | None = None) -> "AegisConfig":
        """Load configuration from *path*, falling back to defaults."""
        target = path or (Path.home() / "AegisVault" / "Config" / "settings.json")
        if not target.exists():
            return cls()
        data = json.loads(target.read_text(encoding="utf-8"))
        return cls(**data)


# Backwards-compatible alias.
Settings = AegisConfig
