import asyncio
import respx
import httpx
import pytest
from key_value.aio.stores.memory import MemoryStore

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache_result import (
    WellKnownConfigurationCacheResult,
)


@pytest.mark.asyncio
async def test_get_async_caches_on_first_call() -> None:
    cache = WellKnownConfigurationCache(well_known_store=MemoryStore())
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
        cache_result: WellKnownConfigurationCacheResult | None = await cache.read_async(
            auth_config=auth_config
        )
        assert cache_result is not None
        result = cache_result.well_known_config
        assert result is not None
        assert result["issuer"] == "https://provider.example.com"
        assert result["jwks_uri"] == "https://provider.example.com/jwks"
        assert uri in [auth_config.well_known_uri]
        # Use public API: ensure get_async returns the item and size reflects it
        assert await cache.get_async(auth_config=auth_config) is not None
        assert await cache.get_size_async() == 1
        assert route.called
        assert route.call_count == 1
        assert jwks_route.called
        assert jwks_route.call_count == 1


@pytest.mark.asyncio
async def test_get_async_uses_cache_on_subsequent_calls() -> None:
    cache = WellKnownConfigurationCache(well_known_store=MemoryStore())
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
        assert await cache.get_size_async() == 1


@pytest.mark.asyncio
async def test_get_async_concurrent_single_fetch() -> None:
    cache = WellKnownConfigurationCache(well_known_store=MemoryStore())
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
        assert await cache.get_size_async() == 1


@pytest.mark.asyncio
async def test_get_async_multiple_uris_concurrent() -> None:
    cache = WellKnownConfigurationCache(well_known_store=MemoryStore())
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
        assert await cache.get_size_async() == 2
        # Use public API to verify both URIs are present
        assert (
            await cache.get_async(
                auth_config=AuthConfig(
                    auth_provider="TEST_PROVIDER",
                    friendly_name="Test Provider",
                    audience="test_audience",
                    issuer="https://provider.example.com",
                    client_id="test_client_id",
                    well_known_uri=uri1,
                    scope="openid profile email",
                )
            )
            is not None
        )
        assert (
            await cache.get_async(
                auth_config=AuthConfig(
                    auth_provider="TEST_PROVIDER",
                    friendly_name="Test Provider",
                    audience="test_audience",
                    issuer="https://provider.example.com",
                    client_id="test_client_id",
                    well_known_uri=uri2,
                    scope="openid profile email",
                )
            )
            is not None
        )
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
    cache = WellKnownConfigurationCache(well_known_store=MemoryStore())
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

        assert await cache.get_size_async() == 1
        await cache.clear_async()
        assert await cache.get_size_async() == 0

        # Fetch again after clear triggers new HTTP call
        await cache.read_async(auth_config=auth_config)
        assert route.call_count == 2
        assert jwks_route.call_count == 2
