"""Connection schemas for platform management."""

import ipaddress
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, SecretStr, field_validator


class PlatformType(StrEnum):
    """Built-in platform types."""

    OLLAMA = "ollama"
    LM_STUDIO = "lm_studio"
    LLAMACPP_SERVER = "llamacpp_server"
    OPENAI_COMPATIBLE = "openai_compatible"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    CUSTOM = "custom"


class AuthMethod(StrEnum):
    """Authentication methods."""

    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"


class Connection(BaseModel):
    """A configurable platform connection."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    platform_type: PlatformType
    base_url: str
    model_name: str = ""
    auth_method: AuthMethod = AuthMethod.NONE
    api_key: SecretStr = SecretStr("")
    username: str = ""
    password: SecretStr = SecretStr("")
    is_local: bool = True
    is_enabled: bool = True
    is_cloud_authorized: bool = False
    capabilities: list[str] = Field(default_factory=lambda: ["chat"])
    custom_headers: dict[str, str] = Field(default_factory=dict)
    custom_payload: dict[str, Any] = Field(default_factory=dict)
    timeout: float = 120.0
    priority: int = 0

    @field_validator("base_url")
    @classmethod
    def normalize_base_url(cls, value: str) -> str:
        """Strip trailing slash from base URL."""
        return value.rstrip("/")

    def is_trusted_local(self) -> bool:
        """Return True if connection is considered safe for sensitive tasks.

        Only plain http/https loopback URLs without embedded credentials are
        accepted. IPv6 addresses and IPv4-mapped IPv6 are normalised before
        the loopback check.
        """
        if not self.is_local:
            return False
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"}:
            return False
        # Reject URLs with embedded credentials; they complicate auditing and
        # can be used to smuggle non-loopback hosts in the userinfo section.
        if parsed.username is not None or parsed.password is not None:
            return False
        host = parsed.hostname
        if host is None:
            return False
        host = host.lower().strip()
        if host == "localhost":
            return True
        # Strip IPv6 zone index (e.g. ::1%lo0) before parsing.
        host = host.split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return addr.is_loopback or addr.is_unspecified
