import asyncio
from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from oidcauthlib.auth.config.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)


@pytest.mark.asyncio
async def test_get_async_caches_on_first_call() -> None:
    cache = WellKnownConfigurationCache()
    uri = "https://provider.example.com/.well-known/openid-configuration"

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "issuer": "https://provider.example.com",
        "jwks_uri": "https://provider.example.com/jwks",
    }
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await cache.get_async(well_known_uri=uri)

        assert result["issuer"] == "https://provider.example.com"
        assert result["jwks_uri"] == "https://provider.example.com/jwks"
        assert uri in cache.cache
        assert cache.size() == 1
        mock_client.get.assert_called_once_with(uri)


@pytest.mark.asyncio
async def test_get_async_uses_cache_on_subsequent_calls() -> None:
    cache = WellKnownConfigurationCache()
    uri = "https://provider.example.com/.well-known/openid-configuration"

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "issuer": "https://provider.example.com",
        "jwks_uri": "https://provider.example.com/jwks",
    }
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_client):
        r1 = await cache.get_async(well_known_uri=uri)
        r2 = await cache.get_async(well_known_uri=uri)
        r3 = await cache.get_async(well_known_uri=uri)

        assert r1 == r2 == r3
        assert mock_client.get.call_count == 1
        assert cache.size() == 1


@pytest.mark.asyncio
async def test_get_async_concurrent_single_fetch() -> None:
    cache = WellKnownConfigurationCache()
    uri = "https://provider.example.com/.well-known/openid-configuration"

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "issuer": "https://provider.example.com",
        "jwks_uri": "https://provider.example.com/jwks",
    }
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_client):
        tasks = [cache.get_async(well_known_uri=uri) for _ in range(50)]
        results = await asyncio.gather(*tasks)

        assert all(r == results[0] for r in results)
        assert mock_client.get.call_count == 1, (
            f"Expected 1 HTTP call, got {mock_client.get.call_count}"
        )
        assert cache.size() == 1


@pytest.mark.asyncio
async def test_get_async_multiple_uris_concurrent() -> None:
    cache = WellKnownConfigurationCache()
    uri1 = "https://provider1.example.com/.well-known/openid-configuration"
    uri2 = "https://provider2.example.com/.well-known/openid-configuration"

    def mock_get_response(url: str) -> MagicMock:
        mock_response = MagicMock()
        if "provider1" in url:
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
    mock_client.get.side_effect = lambda url: mock_get_response(url)
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_client):
        tasks = []
        for _ in range(30):
            tasks.append(cache.get_async(well_known_uri=uri1))
            tasks.append(cache.get_async(well_known_uri=uri2))
        results = await asyncio.gather(*tasks)

        assert len(results) == 60
        assert cache.size() == 2
        assert uri1 in cache.cache and uri2 in cache.cache
        assert mock_client.get.call_count == 2, (
            f"Expected 2 HTTP calls, got {mock_client.get.call_count}"
        )


@pytest.mark.asyncio
async def test_clear_resets_cache() -> None:
    cache = WellKnownConfigurationCache()
    uri = "https://provider.example.com/.well-known/openid-configuration"

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "issuer": "https://provider.example.com",
        "jwks_uri": "https://provider.example.com/jwks",
    }
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_client):
        await cache.get_async(well_known_uri=uri)

        assert cache.size() == 1
        cache.clear()
        assert cache.size() == 0

        # Fetch again after clear triggers new HTTP call
        await cache.get_async(well_known_uri=uri)
        assert mock_client.get.call_count == 2
