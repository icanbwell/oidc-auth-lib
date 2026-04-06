"""Tests for AuthServerMetadataDiscovery — RFC 8414 and OIDC Discovery."""

import httpx
import pytest
import respx

from oidcauthlib.auth.well_known_configuration.auth_server_metadata_discovery import (
    AuthServerMetadataDiscovery,
)

_BASE = "https://mcp.example.com"
_RESOURCE_URL = f"{_BASE}/v1/mcp"
_RFC8414_URL = f"{_BASE}/.well-known/oauth-authorization-server"
_OIDC_URL = f"{_BASE}/.well-known/openid-configuration"

_VALID_METADATA = {
    "issuer": "https://auth.example.com",
    "authorization_endpoint": "https://auth.example.com/authorize",
    "token_endpoint": "https://auth.example.com/token",
    "registration_endpoint": "https://auth.example.com/register",
    "scopes_supported": ["openid", "profile", "email"],
}


@pytest.mark.asyncio
@respx.mock
async def test_rfc8414_success() -> None:
    """RFC 8414 endpoint returns valid metadata."""
    respx.get(_RFC8414_URL).mock(return_value=httpx.Response(200, json=_VALID_METADATA))

    discovery = AuthServerMetadataDiscovery()
    result = await discovery.discover(resource_url=_RESOURCE_URL)

    assert result is not None
    assert result.authorization_endpoint == "https://auth.example.com/authorize"
    assert result.token_endpoint == "https://auth.example.com/token"
    assert result.registration_endpoint == "https://auth.example.com/register"
    assert result.issuer == "https://auth.example.com"
    assert result.scopes_supported == ["openid", "profile", "email"]


@pytest.mark.asyncio
@respx.mock
async def test_rfc8414_fails_oidc_succeeds() -> None:
    """RFC 8414 returns 404, falls back to OIDC Discovery."""
    respx.get(_RFC8414_URL).mock(return_value=httpx.Response(404))
    respx.get(_OIDC_URL).mock(return_value=httpx.Response(200, json=_VALID_METADATA))

    discovery = AuthServerMetadataDiscovery()
    result = await discovery.discover(resource_url=_RESOURCE_URL)

    assert result is not None
    assert result.authorization_endpoint == "https://auth.example.com/authorize"
    assert result.token_endpoint == "https://auth.example.com/token"


@pytest.mark.asyncio
@respx.mock
async def test_both_endpoints_fail() -> None:
    """Both well-known endpoints return errors — returns None."""
    respx.get(_RFC8414_URL).mock(return_value=httpx.Response(404))
    respx.get(_OIDC_URL).mock(return_value=httpx.Response(500))

    discovery = AuthServerMetadataDiscovery()
    result = await discovery.discover(resource_url=_RESOURCE_URL)

    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_malformed_json() -> None:
    """Endpoint returns non-JSON — returns None."""
    respx.get(_RFC8414_URL).mock(return_value=httpx.Response(200, text="not json"))
    respx.get(_OIDC_URL).mock(return_value=httpx.Response(200, text="also not json"))

    discovery = AuthServerMetadataDiscovery()
    result = await discovery.discover(resource_url=_RESOURCE_URL)

    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_missing_required_endpoints() -> None:
    """Metadata without authorization_endpoint or token_endpoint — returns None."""
    respx.get(_RFC8414_URL).mock(
        return_value=httpx.Response(200, json={"issuer": "https://auth.example.com"})
    )
    respx.get(_OIDC_URL).mock(return_value=httpx.Response(404))

    discovery = AuthServerMetadataDiscovery()
    result = await discovery.discover(resource_url=_RESOURCE_URL)

    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_network_timeout() -> None:
    """Network timeout — returns None."""
    respx.get(_RFC8414_URL).mock(side_effect=httpx.ConnectTimeout("timeout"))
    respx.get(_OIDC_URL).mock(side_effect=httpx.ConnectTimeout("timeout"))

    discovery = AuthServerMetadataDiscovery()
    result = await discovery.discover(resource_url=_RESOURCE_URL)

    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_no_scopes_in_metadata() -> None:
    """Metadata without scopes_supported — scopes_supported is None."""
    metadata = {
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
    }
    respx.get(_RFC8414_URL).mock(return_value=httpx.Response(200, json=metadata))

    discovery = AuthServerMetadataDiscovery()
    result = await discovery.discover(resource_url=_RESOURCE_URL)

    assert result is not None
    assert result.scopes_supported is None


@pytest.mark.asyncio
@respx.mock
async def test_url_with_port() -> None:
    """Resource URL with custom port — base URL preserves port."""
    url = "https://mcp.example.com:8443/v1/mcp"
    respx.get(
        "https://mcp.example.com:8443/.well-known/oauth-authorization-server"
    ).mock(return_value=httpx.Response(200, json=_VALID_METADATA))

    discovery = AuthServerMetadataDiscovery()
    result = await discovery.discover(resource_url=url)

    assert result is not None
    assert result.authorization_endpoint == "https://auth.example.com/authorize"


class TestExtractBaseUrl:
    def test_strips_path(self) -> None:
        assert (
            AuthServerMetadataDiscovery._extract_base_url(
                "https://mcp.example.com/v1/mcp"
            )
            == "https://mcp.example.com"
        )

    def test_preserves_port(self) -> None:
        assert (
            AuthServerMetadataDiscovery._extract_base_url(
                "https://mcp.example.com:8443/v1/mcp"
            )
            == "https://mcp.example.com:8443"
        )

    def test_no_path(self) -> None:
        assert (
            AuthServerMetadataDiscovery._extract_base_url("https://mcp.example.com")
            == "https://mcp.example.com"
        )


@pytest.mark.asyncio
@respx.mock
async def test_no_registration_endpoint() -> None:
    """Metadata without registration_endpoint — registration_endpoint is None."""
    metadata = {
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "issuer": "https://auth.example.com",
    }
    respx.get(_RFC8414_URL).mock(return_value=httpx.Response(200, json=metadata))

    discovery = AuthServerMetadataDiscovery()
    result = await discovery.discover(resource_url=_RESOURCE_URL)

    assert result is not None
    assert result.registration_endpoint is None
    assert result.issuer == "https://auth.example.com"
