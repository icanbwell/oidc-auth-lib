import asyncio
import respx
import httpx
import pytest

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)


@pytest.mark.asyncio
async def test_get_async_caches_on_first_call() -> None:
    cache = WellKnownConfigurationCache()
    uri = "https://provider.example.com/.well-known/openid-configuration"

    with respx.mock(assert_all_called=True) as respx_mock:
        route = respx_mock.get(uri).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://provider.example.com",
                    "jwks_uri": "https://provider.example.com/jwks",
                },
            )
        )
        jwks_route = respx_mock.get("https://provider.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )
        auth_config: AuthConfig = AuthConfig(
            auth_provider="TEST_PROVIDER",
            friendly_name="Test Provider",
            audience="test_audience",
            issuer="https://provider.example.com",
            client_id="test_client_id",
            well_known_uri=uri,
            scope="openid profile email",
        )
        result = await cache.read_async(auth_config=auth_config)
        assert result is not None
        assert result["issuer"] == "https://provider.example.com"
        assert result["jwks_uri"] == "https://provider.example.com/jwks"
        assert uri in cache._cache
        assert cache.size() == 1
        assert route.called
        assert route.call_count == 1
        assert jwks_route.called
        assert jwks_route.call_count == 1


@pytest.mark.asyncio
async def test_get_async_uses_cache_on_subsequent_calls() -> None:
    cache = WellKnownConfigurationCache()
    uri = "https://provider.example.com/.well-known/openid-configuration"

    with respx.mock(assert_all_called=True) as respx_mock:
        route = respx_mock.get(uri).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://provider.example.com",
                    "jwks_uri": "https://provider.example.com/jwks",
                },
            )
        )
        jwks_route = respx_mock.get("https://provider.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )
        auth_config: AuthConfig = AuthConfig(
            auth_provider="TEST_PROVIDER",
            friendly_name="Test Provider",
            audience="test_audience",
            issuer="https://provider.example.com",
            client_id="test_client_id",
            well_known_uri=uri,
            scope="openid profile email",
        )
        r1 = await cache.read_async(auth_config=auth_config)
        r2 = await cache.read_async(auth_config=auth_config)
        r3 = await cache.read_async(auth_config=auth_config)

        assert r1 == r2 == r3
        assert route.call_count == 1
        assert jwks_route.called
        assert jwks_route.call_count == 1
        assert cache.size() == 1


@pytest.mark.asyncio
async def test_get_async_concurrent_single_fetch() -> None:
    cache = WellKnownConfigurationCache()
    uri = "https://provider.example.com/.well-known/openid-configuration"

    with respx.mock(assert_all_called=True) as respx_mock:
        route = respx_mock.get(uri).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://provider.example.com",
                    "jwks_uri": "https://provider.example.com/jwks",
                },
            )
        )
        jwks_route = respx_mock.get("https://provider.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )
        auth_config: AuthConfig = AuthConfig(
            auth_provider="TEST_PROVIDER",
            friendly_name="Test Provider",
            audience="test_audience",
            issuer="https://provider.example.com",
            client_id="test_client_id",
            well_known_uri=uri,
            scope="openid profile email",
        )
        tasks = [cache.read_async(auth_config=auth_config) for _ in range(50)]
        results = await asyncio.gather(*tasks)

        assert all(r == results[0] for r in results)
        assert route.call_count == 1, f"Expected 1 HTTP call, got {route.call_count}"
        assert jwks_route.called
        assert jwks_route.call_count == 1
        assert cache.size() == 1


@pytest.mark.asyncio
async def test_get_async_multiple_uris_concurrent() -> None:
    cache = WellKnownConfigurationCache()
    uri1 = "https://provider1.example.com/.well-known/openid-configuration"
    uri2 = "https://provider2.example.com/.well-known/openid-configuration"

    with respx.mock(assert_all_called=True) as respx_mock:
        route1 = respx_mock.get(uri1).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://provider1.example.com",
                    "jwks_uri": "https://provider1.example.com/jwks",
                },
            )
        )
        route2 = respx_mock.get(uri2).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://provider2.example.com",
                    "jwks_uri": "https://provider2.example.com/jwks",
                },
            )
        )
        jwks_route1 = respx_mock.get("https://provider1.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )
        jwks_route2 = respx_mock.get("https://provider2.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )
        tasks = []
        for _ in range(30):
            auth_config1: AuthConfig = AuthConfig(
                auth_provider="TEST_PROVIDER",
                friendly_name="Test Provider",
                audience="test_audience",
                issuer="https://provider.example.com",
                client_id="test_client_id",
                well_known_uri=uri1,
                scope="openid profile email",
            )
            auth_config2: AuthConfig = AuthConfig(
                auth_provider="TEST_PROVIDER",
                friendly_name="Test Provider",
                audience="test_audience",
                issuer="https://provider.example.com",
                client_id="test_client_id",
                well_known_uri=uri2,
                scope="openid profile email",
            )
            tasks.append(cache.read_async(auth_config=auth_config1))
            tasks.append(cache.read_async(auth_config=auth_config2))
        results = await asyncio.gather(*tasks)

        assert len(results) == 60
        assert cache.size() == 2
        assert uri1 in cache._cache and uri2 in cache._cache
        assert route1.call_count == 1, (
            f"Expected 1 HTTP call for uri1, got {route1.call_count}"
        )
        assert route2.call_count == 1, (
            f"Expected 1 HTTP call for uri2, got {route2.call_count}"
        )
        assert jwks_route1.called
        assert jwks_route1.call_count == 1
        assert jwks_route2.called
        assert jwks_route2.call_count == 1


@pytest.mark.asyncio
async def test_clear_resets_cache() -> None:
    cache = WellKnownConfigurationCache()
    uri = "https://provider.example.com/.well-known/openid-configuration"

    with respx.mock(assert_all_called=False) as respx_mock:
        route = respx_mock.get(uri).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://provider.example.com",
                    "jwks_uri": "https://provider.example.com/jwks",
                },
            )
        )
        jwks_route = respx_mock.get("https://provider.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )
        auth_config: AuthConfig = AuthConfig(
            auth_provider="TEST_PROVIDER",
            friendly_name="Test Provider",
            audience="test_audience",
            issuer="https://provider.example.com",
            client_id="test_client_id",
            well_known_uri=uri,
            scope="openid profile email",
        )
        await cache.read_async(auth_config=auth_config)

        assert cache.size() == 1
        cache.clear()
        assert cache.size() == 0

        # Fetch again after clear triggers new HTTP call
        await cache.read_async(auth_config=auth_config)
        assert route.call_count == 2
        assert jwks_route.call_count == 2
