"""Configuration management for AegisVault."""

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
    enable_semantic_search: bool = False


class PathConfig(BaseSettings):
    """Path configuration."""

    inbox: Path = Path.home() / "AegisVault" / "Inbox"
    vault: Path = Path.home() / "AegisVault" / "Vault"
    index: Path = Path.home() / "AegisVault" / "Index"
    logs: Path = Path.home() / "AegisVault" / "Logs"
    connections: Path = Path.home() / "AegisVault" / "Config" / "connections.json"


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


# Backwards-compatible alias.
Settings = AegisConfig
