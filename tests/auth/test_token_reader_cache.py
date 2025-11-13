"""
Tests for TokenReader OIDC discovery document caching.
Verifies that well-known configs are cached at the instance level
to prevent repeated HTTP requests to the identity provider.
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from typing import List, Dict, Any
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)

# Import the shared mock from the fixture/conftest
from tests.auth.conftest import MockEnvironmentVariables
@pytest.mark.asyncio
async def test_fetch_well_known_config_caches_on_first_call() -> None:
    """
    Test that the first call to fetch_well_known_config_async fetches from HTTP
    and stores the result in the cache.
    """
    auth_config = AuthConfig(
        auth_provider="TEST_PROVIDER",
        audience="test-audience",
        issuer="https://test-provider.example.com",
        well_known_uri="https://test-provider.example.com/.well-known/openid-configuration",
    )

    env_vars = MockEnvironmentVariables(["TEST_PROVIDER"])
    auth_config_reader = AuthConfigReader(environment_variables=env_vars)

    with patch.object(
        auth_config_reader,
        "get_config_for_auth_provider",
        return_value=auth_config,
    ):
        token_reader = TokenReader(auth_config_reader=auth_config_reader)

        # Mock the HTTP client
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "issuer": "https://test-provider.example.com",
            "jwks_uri": "https://test-provider.example.com/jwks",
            "authorization_endpoint": "https://test-provider.example.com/authorize",
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("httpx.AsyncClient", return_value=mock_client):
            # First call should fetch from HTTP
            result = await token_reader.fetch_well_known_config_async(
                well_known_uri="https://test-provider.example.com/.well-known/openid-configuration"
            )

            # Verify the result
            assert result["issuer"] == "https://test-provider.example.com"
            assert result["jwks_uri"] == "https://test-provider.example.com/jwks"

            # Verify HTTP client was called
            mock_client.get.assert_called_once_with(
                "https://test-provider.example.com/.well-known/openid-configuration"
            )

            # Verify the result is now cached
            assert (
                "https://test-provider.example.com/.well-known/openid-configuration"
                in token_reader.cached_well_known_configs
            )
            assert (
                token_reader.cached_well_known_configs[
                    "https://test-provider.example.com/.well-known/openid-configuration"
                ]
                == result
            )


@pytest.mark.asyncio
async def test_fetch_well_known_config_uses_cache_on_subsequent_calls() -> None:
    """
    Test that subsequent calls to fetch_well_known_config_async use the cached
    value and do not make additional HTTP requests.
    """
    auth_config = AuthConfig(
        auth_provider="TEST_PROVIDER",
        audience="test-audience",
        issuer="https://test-provider.example.com",
        well_known_uri="https://test-provider.example.com/.well-known/openid-configuration",
    )

    env_vars = MockEnvironmentVariables(["TEST_PROVIDER"])
    auth_config_reader = AuthConfigReader(environment_variables=env_vars)

    with patch.object(
        auth_config_reader,
        "get_config_for_auth_provider",
        return_value=auth_config,
    ):
        token_reader = TokenReader(auth_config_reader=auth_config_reader)

        # Mock the HTTP client
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "issuer": "https://test-provider.example.com",
            "jwks_uri": "https://test-provider.example.com/jwks",
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("httpx.AsyncClient", return_value=mock_client):
            well_known_uri = (
                "https://test-provider.example.com/.well-known/openid-configuration"
            )

            # First call
            result1 = await token_reader.fetch_well_known_config_async(
                well_known_uri=well_known_uri
            )

            # Second call - should use cache
            result2 = await token_reader.fetch_well_known_config_async(
                well_known_uri=well_known_uri
            )

            # Third call - should use cache
            result3 = await token_reader.fetch_well_known_config_async(
                well_known_uri=well_known_uri
            )

            # Verify all results are identical
            assert result1 == result2 == result3

            # Verify HTTP client was only called ONCE (on first call)
            assert mock_client.get.call_count == 1


@pytest.mark.asyncio
async def test_fetch_well_known_config_caches_multiple_uris_independently() -> None:
    """
    Test that different well-known URIs are cached independently
    and don't interfere with each other.
    """
    auth_config = AuthConfig(
        auth_provider="TEST_PROVIDER",
        audience="test-audience",
        issuer="https://test-provider.example.com",
        well_known_uri="https://test-provider.example.com/.well-known/openid-configuration",
    )

    env_vars = MockEnvironmentVariables(["TEST_PROVIDER"])
    auth_config_reader = AuthConfigReader(environment_variables=env_vars)

    with patch.object(
        auth_config_reader,
        "get_config_for_auth_provider",
        return_value=auth_config,
    ):
        token_reader = TokenReader(auth_config_reader=auth_config_reader)

        # Create different responses for different URIs
        def mock_get_response(uri: str) -> MagicMock:
            mock_response = MagicMock()
            if "provider1" in uri:
                mock_response.json.return_value = {
                    "issuer": "https://provider1.example.com",
                    "jwks_uri": "https://provider1.example.com/jwks",
                }
            else:
                mock_response.json.return_value = {
                    "issuer": "https://provider2.example.com",
                    "jwks_uri": "https://provider2.example.com/jwks",
                }
            mock_response.raise_for_status = MagicMock()
            return mock_response

        mock_client = AsyncMock()
        mock_client.get.side_effect = lambda uri: mock_get_response(uri)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("httpx.AsyncClient", return_value=mock_client):
            uri1 = "https://provider1.example.com/.well-known/openid-configuration"
            uri2 = "https://provider2.example.com/.well-known/openid-configuration"

            # Fetch from both URIs
            result1 = await token_reader.fetch_well_known_config_async(
                well_known_uri=uri1
            )
            result2 = await token_reader.fetch_well_known_config_async(
                well_known_uri=uri2
            )

            # Verify both are cached
            assert uri1 in token_reader.cached_well_known_configs
            assert uri2 in token_reader.cached_well_known_configs

            # Verify cached values are correct
            assert result1["issuer"] == "https://provider1.example.com"
            assert result2["issuer"] == "https://provider2.example.com"

            # Fetch again - should use cache
            result1_cached = await token_reader.fetch_well_known_config_async(
                well_known_uri=uri1
            )
            result2_cached = await token_reader.fetch_well_known_config_async(
                well_known_uri=uri2
            )

            # Verify results match
            assert result1 == result1_cached
            assert result2 == result2_cached

            # Verify HTTP was only called twice total (once per URI)
            assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_cache_prevents_repeated_http_requests_in_production_scenario() -> None:
    """
    Test that simulates the production scenario where many token verifications
    happen rapidly. Verify that only ONE HTTP request is made regardless of
    how many times the well-known config is needed.
    """
    auth_config = AuthConfig(
        auth_provider="COGNITO",
        audience="test-client-id",
        issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST",
        well_known_uri="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST/.well-known/openid-configuration",
    )

    env_vars = MockEnvironmentVariables(["COGNITO"])
    auth_config_reader = AuthConfigReader(environment_variables=env_vars)

    with patch.object(
        auth_config_reader,
        "get_config_for_auth_provider",
        return_value=auth_config,
    ):
        token_reader = TokenReader(auth_config_reader=auth_config_reader)

        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST",
            "jwks_uri": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST/.well-known/jwks.json",
            "authorization_endpoint": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST/oauth2/authorize",
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("httpx.AsyncClient", return_value=mock_client):
            well_known_uri = auth_config.well_known_uri

            # Simulate 100 rapid requests (like in production with high traffic)
            results = []
            for _ in range(100):
                result = await token_reader.fetch_well_known_config_async(
                    well_known_uri=well_known_uri
                )
                results.append(result)

            # Verify all results are identical
            assert all(r == results[0] for r in results)

            # THE KEY ASSERTION: HTTP should only be called ONCE despite 100 calls
            assert (
                mock_client.get.call_count == 1
            ), f"Expected 1 HTTP call but got {mock_client.get.call_count}"

            # Verify the config is cached
            assert well_known_uri in token_reader.cached_well_known_configs


@pytest.mark.asyncio
async def test_cache_initializes_empty() -> None:
    """
    Test that the cache is initialized as an empty dictionary when
    TokenReader is instantiated.
    """
    auth_config = AuthConfig(
        auth_provider="TEST_PROVIDER",
        audience="test-audience",
        issuer="https://test-provider.example.com",
        well_known_uri="https://test-provider.example.com/.well-known/openid-configuration",
    )

    env_vars = MockEnvironmentVariables(["TEST_PROVIDER"])
    auth_config_reader = AuthConfigReader(environment_variables=env_vars)

    with patch.object(
        auth_config_reader,
        "get_config_for_auth_provider",
        return_value=auth_config,
    ):
        token_reader = TokenReader(auth_config_reader=auth_config_reader)

        # Verify cache exists and is empty
        assert hasattr(token_reader, "cached_well_known_configs")
        assert isinstance(token_reader.cached_well_known_configs, dict)
        assert len(token_reader.cached_well_known_configs) == 0
