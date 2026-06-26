"""Tests for OpenAI-compatible model provider."""

from http import HTTPStatus
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from pydantic import SecretStr

from aegisvault.connections.models import AuthMethod, Connection, PlatformType
from aegisvault.model.provider import (
    OpenAICompatibleProvider,
    _build_headers,
    _load_built_in_providers,
    _load_provider_plugins,
    create_provider,
    register_provider,
)


@pytest.fixture
def connection() -> Connection:
    """Default local connection fixture."""
    return Connection(
        name="test",
        platform_type=PlatformType.OPENAI_COMPATIBLE,
        base_url="http://127.0.0.1:1234",
        model_name="test-model",
    )


def test_create_provider_loads_built_ins(connection: Connection) -> None:
    """create_provider auto-registers built-in providers."""
    provider = create_provider(connection)
    assert isinstance(provider, OpenAICompatibleProvider)


def test_create_provider_lists_registered_on_unknown(
    connection: Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """create_provider error includes the list of registered providers."""
    monkeypatch.setattr(
        "aegisvault.model.provider._PROVIDER_REGISTRY", {"other": OpenAICompatibleProvider}
    )
    monkeypatch.setattr("aegisvault.model.provider._load_built_in_providers", lambda: None)
    monkeypatch.setattr("aegisvault.model.provider._load_provider_plugins", lambda: None)
    with pytest.raises(ValueError) as exc_info:
        create_provider(connection)
    assert connection.platform_type.value in str(exc_info.value)
    assert "Registered providers" in str(exc_info.value)


def test_register_provider_rejects_duplicate_by_default() -> None:
    """Duplicate provider registration is rejected unless explicitly allowed."""
    with pytest.raises(ValueError):
        register_provider("openai_compatible", OpenAICompatibleProvider)


def test_register_provider_allows_override() -> None:
    """Override is allowed when explicitly requested."""
    register_provider("openai_compatible", OpenAICompatibleProvider, allow_override=True)


async def test_chat_completion_success(connection: Connection) -> None:
    """chat_completion returns the assistant message content."""
    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = HTTPStatus.OK
    mock_response.json.return_value = {"choices": [{"message": {"content": "hello back"}}]}
    mock_response.raise_for_status.return_value = None

    provider = OpenAICompatibleProvider(connection)
    with patch.object(provider.client, "post", new=AsyncMock(return_value=mock_response)):
        result = await provider.chat_completion([{"role": "user", "content": "hi"}])

    assert result == "hello back"
    await provider.close()


async def test_chat_completion_merges_custom_payload(connection: Connection) -> None:
    """chat_completion merges connection.custom_payload into the request body."""
    connection.custom_payload = {"top_p": 0.9, "max_tokens": 42}

    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = HTTPStatus.OK
    mock_response.json.return_value = {"choices": [{"message": {"content": ""}}]}
    mock_response.raise_for_status.return_value = None

    provider = OpenAICompatibleProvider(connection)
    with patch.object(provider.client, "post", new=AsyncMock(return_value=mock_response)) as post:
        await provider.chat_completion([{"role": "user", "content": "hi"}])

    payload = post.call_args.kwargs["json"]
    assert payload["model"] == "test-model"
    assert payload["top_p"] == 0.9
    assert payload["max_tokens"] == 42
    await provider.close()


async def test_chat_completion_raises_on_http_error(connection: Connection) -> None:
    """chat_completion propagates HTTP errors."""
    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = HTTPStatus.UNAUTHORIZED
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "Unauthorized",
        request=Mock(spec=httpx.Request),
        response=mock_response,
    )

    provider = OpenAICompatibleProvider(connection)
    with patch.object(provider.client, "post", new=AsyncMock(return_value=mock_response)):
        with pytest.raises(httpx.HTTPStatusError):
            await provider.chat_completion([{"role": "user", "content": "hi"}])

    await provider.close()


async def test_health_success(connection: Connection) -> None:
    """health returns True when /v1/models responds."""
    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = HTTPStatus.OK
    mock_response.raise_for_status.return_value = None

    provider = OpenAICompatibleProvider(connection)
    with patch.object(provider.client, "get", new=AsyncMock(return_value=mock_response)):
        assert await provider.health() is True

    await provider.close()


async def test_health_failure(connection: Connection) -> None:
    """health returns False when the request fails."""
    provider = OpenAICompatibleProvider(connection)
    with patch.object(
        provider.client, "get", new=AsyncMock(side_effect=httpx.ConnectError("boom"))
    ):
        assert await provider.health() is False

    await provider.close()


def test_build_headers_bearer() -> None:
    """Bearer auth sets Authorization header."""
    conn = Connection(
        name="test",
        platform_type=PlatformType.OPENAI,
        base_url="http://localhost",
        auth_method=AuthMethod.BEARER,
        api_key="secret-token",
    )
    headers = _build_headers(conn)
    assert headers["Authorization"] == "Bearer secret-token"


def test_build_headers_api_key() -> None:
    """API key auth passes the key verbatim."""
    conn = Connection(
        name="test",
        platform_type=PlatformType.OPENAI_COMPATIBLE,
        base_url="http://localhost",
        auth_method=AuthMethod.API_KEY,
        api_key="ApiKey secret-token",
    )
    headers = _build_headers(conn)
    assert headers["Authorization"] == "ApiKey secret-token"


def test_build_headers_basic() -> None:
    """Basic auth is handled by httpx.BasicAuth, not a custom header."""
    conn = Connection(
        name="test",
        platform_type=PlatformType.OPENAI_COMPATIBLE,
        base_url="http://localhost",
        auth_method=AuthMethod.BASIC,
        username="alice",
        password="wonderland",
    )
    headers = _build_headers(conn)
    assert "Authorization" not in headers


async def test_openai_compatible_provider_uses_basic_auth() -> None:
    """Basic auth configures httpx.BasicAuth on the HTTP client."""
    conn = Connection(
        name="test",
        platform_type=PlatformType.OPENAI_COMPATIBLE,
        base_url="http://localhost",
        auth_method=AuthMethod.BASIC,
        username="alice",
        password="wonderland",
    )
    provider = OpenAICompatibleProvider(conn)
    assert isinstance(provider.client.auth, httpx.BasicAuth)
    await provider.close()


def test_build_headers_custom_headers(connection: Connection) -> None:
    """Custom headers are preserved alongside auth headers."""
    connection.custom_headers = {"X-Custom": "value"}
    connection.auth_method = AuthMethod.BEARER
    connection.api_key = SecretStr("token")
    headers = _build_headers(connection)
    assert headers["X-Custom"] == "value"
    assert headers["Authorization"] == "Bearer token"


# ---------------------------------------------------------------------------
# Provider registry coverage
# ---------------------------------------------------------------------------


def test_load_built_in_providers_registers_all_when_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_load_built_in_providers registers every built-in when registry is empty."""
    monkeypatch.setattr("aegisvault.model.provider._PROVIDER_REGISTRY", {})
    _load_built_in_providers()
    from aegisvault.model.provider import _PROVIDER_REGISTRY

    expected = {
        "openai_compatible",
        "ollama",
        "lm_studio",
        "llamacpp_server",
        "openai",
        "custom",
    }
    assert expected <= set(_PROVIDER_REGISTRY)


def test_load_provider_plugins_skips_when_already_loaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_load_provider_plugins is a no-op after the first call."""
    monkeypatch.setattr("aegisvault.model.provider._PLUGINS_LOADED", True)
    spy = Mock(side_effect=RuntimeError("should not be called"))
    monkeypatch.setattr("aegisvault.extensions.registry.load_provider_plugins", spy)
    _load_provider_plugins()
    spy.assert_not_called()


def test_load_provider_plugins_swallows_plugin_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_load_provider_plugins tolerates failures from third-party plugins."""
    monkeypatch.setattr("aegisvault.model.provider._PLUGINS_LOADED", False)
    monkeypatch.setattr(
        "aegisvault.extensions.registry.load_provider_plugins",
        Mock(side_effect=RuntimeError("plugin boom")),
    )
    _load_provider_plugins()
