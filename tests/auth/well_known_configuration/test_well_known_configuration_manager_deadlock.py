"""
Test to verify deadlock fixes in WellKnownConfigurationManager.

This test demonstrates that concurrent initialization does not cause deadlock.
"""

import asyncio
import pytest
import respx
import httpx
from typing import override, Coroutine, Any

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)


class MockAuthConfigReader(AuthConfigReader):
    """Mock auth config reader for testing."""

    # noinspection PyMissingConstructor
    def __init__(self, auth_configs: list[AuthConfig]) -> None:
        self._auth_configs: list[AuthConfig] = auth_configs

    @override
    def get_auth_configs_for_all_auth_providers(self) -> list[AuthConfig]:
        return self._auth_configs


@pytest.mark.asyncio
async def test_concurrent_initialization_no_deadlock() -> None:
    """Test that many concurrent calls to ensure_initialized_async don't deadlock."""

    uri1 = "https://provider1.example.com/.well-known/openid-configuration"
    uri2 = "https://provider2.example.com/.well-known/openid-configuration"

    auth_configs = [
        AuthConfig(
            auth_provider="PROVIDER1",
            friendly_name="Provider 1",
            audience="aud1",
            issuer="https://provider1.example.com",
            client_id="client1",
            well_known_uri=uri1,
        ),
        AuthConfig(
            auth_provider="PROVIDER2",
            friendly_name="Provider 2",
            audience="aud2",
            issuer="https://provider2.example.com",
            client_id="client2",
            well_known_uri=uri2,
        ),
    ]

    with respx.mock:
        respx.get(uri1).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://provider1.example.com",
                    "jwks_uri": "https://provider1.example.com/jwks",
                },
            )
        )
        respx.get(uri2).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://provider2.example.com",
                    "jwks_uri": "https://provider2.example.com/jwks",
                },
            )
        )
        respx.get("https://provider1.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )
        respx.get("https://provider2.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )

        cache = WellKnownConfigurationCache()
        reader = MockAuthConfigReader(auth_configs)
        manager = WellKnownConfigurationManager(
            auth_config_reader=reader,
            cache=cache,
        )

        # Launch 50 concurrent initialization attempts
        # This should NOT deadlock
        tasks = [manager.ensure_initialized_async() for _ in range(50)]

        # Use a timeout to detect deadlock
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)
        except asyncio.TimeoutError:
            pytest.fail("Deadlock detected: initialization timed out")

        # Verify initialization completed successfully
        assert manager._loaded is True
        assert cache.size() == 2


@pytest.mark.asyncio
async def test_get_async_during_initialization_no_deadlock() -> None:
    """Test that calling get_async during initialization doesn't deadlock."""

    uri = "https://provider.example.com/.well-known/openid-configuration"

    auth_config = AuthConfig(
        auth_provider="TEST",
        friendly_name="Test",
        audience="aud",
        issuer="https://provider.example.com",
        client_id="client",
        well_known_uri=uri,
    )

    with respx.mock:
        respx.get(uri).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://provider.example.com",
                    "jwks_uri": "https://provider.example.com/jwks",
                },
            )
        )
        respx.get("https://provider.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )

        cache = WellKnownConfigurationCache()
        reader = MockAuthConfigReader([auth_config])
        manager = WellKnownConfigurationManager(
            auth_config_reader=reader,
            cache=cache,
        )

        # Mix initialization and get_async calls
        tasks: list[Coroutine[Any, Any, Any]] = []
        tasks.extend([manager.ensure_initialized_async() for _ in range(25)])
        tasks.extend([manager.get_async(auth_config) for _ in range(25)])

        # Use a timeout to detect deadlock
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)
        except asyncio.TimeoutError:
            pytest.fail("Deadlock detected: mixed operations timed out")

        # Verify all get_async calls returned the config
        get_results = results[25:]  # Last 25 results are from get_async
        assert all(r is not None for r in get_results)


@pytest.mark.asyncio
async def test_initialization_failure_retries() -> None:
    """Test that failed initialization allows retries without hanging."""

    uri = "https://provider.example.com/.well-known/openid-configuration"

    auth_config = AuthConfig(
        auth_provider="TEST",
        friendly_name="Test",
        audience="aud",
        issuer="https://provider.example.com",
        client_id="client",
        well_known_uri=uri,
    )

    call_count = 0

    def mock_response(*args: Any, **kwargs: Any) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call fails
            return httpx.Response(500, json={"error": "Server error"})
        else:
            # Subsequent calls succeed
            return httpx.Response(
                200,
                json={
                    "issuer": "https://provider.example.com",
                    "jwks_uri": "https://provider.example.com/jwks",
                },
            )

    with respx.mock:
        respx.get(uri).mock(side_effect=mock_response)
        respx.get("https://provider.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )

        cache = WellKnownConfigurationCache()
        reader = MockAuthConfigReader([auth_config])
        manager = WellKnownConfigurationManager(
            auth_config_reader=reader,
            cache=cache,
        )

        # Launch 10 concurrent initialization attempts
        # First one will fail, others should retry and succeed
        tasks = [manager.ensure_initialized_async() for _ in range(10)]

        # Some will fail, some will succeed after retry
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # At least one should fail (the first initializer)
        failures = [r for r in results if isinstance(r, Exception)]
        assert len(failures) >= 1

        # But eventually initialization should succeed
        # Call again to verify it works now
        await manager.ensure_initialized_async()
        assert manager._loaded is True


@pytest.mark.asyncio
async def test_refresh_under_concurrent_load_no_deadlock() -> None:
    """Test that refresh_async works correctly under concurrent load."""

    uri = "https://provider.example.com/.well-known/openid-configuration"

    auth_config = AuthConfig(
        auth_provider="TEST",
        friendly_name="Test",
        audience="aud",
        issuer="https://provider.example.com",
        client_id="client",
        well_known_uri=uri,
    )

    with respx.mock:
        respx.get(uri).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://provider.example.com",
                    "jwks_uri": "https://provider.example.com/jwks",
                },
            )
        )
        respx.get("https://provider.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )

        cache = WellKnownConfigurationCache()
        reader = MockAuthConfigReader([auth_config])
        manager = WellKnownConfigurationManager(
            auth_config_reader=reader,
            cache=cache,
        )

        # Initial load
        await manager.ensure_initialized_async()

        # Concurrent refresh and reads
        async def read_loop() -> None:
            for _ in range(10):
                await manager.get_async(auth_config)
                await asyncio.sleep(0.01)

        tasks = [read_loop() for _ in range(10)]
        tasks.append(manager.refresh_async())

        # Use a timeout to detect deadlock
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)
        except asyncio.TimeoutError:
            pytest.fail("Deadlock detected: refresh under load timed out")

        # Verify manager is still in valid state
        assert manager._loaded is True


@pytest.mark.asyncio
async def test_concurrent_refresh_operations() -> None:
    """Test that multiple concurrent refresh calls are properly serialized."""

    uri = "https://provider.example.com/.well-known/openid-configuration"

    auth_config = AuthConfig(
        auth_provider="TEST",
        friendly_name="Test",
        audience="aud",
        issuer="https://provider.example.com",
        client_id="client",
        well_known_uri=uri,
    )

    refresh_count = 0

    def mock_response(*args: Any, **kwargs: Any) -> httpx.Response:
        nonlocal refresh_count
        refresh_count += 1
        return httpx.Response(
            200,
            json={
                "issuer": "https://provider.example.com",
                "jwks_uri": "https://provider.example.com/jwks",
                "version": refresh_count,  # Track which refresh this is
            },
        )

    with respx.mock:
        respx.get(uri).mock(side_effect=mock_response)
        respx.get("https://provider.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": []})
        )

        cache = WellKnownConfigurationCache()
        reader = MockAuthConfigReader([auth_config])
        manager = WellKnownConfigurationManager(
            auth_config_reader=reader,
            cache=cache,
        )

        # Initial load
        await manager.ensure_initialized_async()
        auth_config_1 = await manager.get_async(auth_config)
        assert auth_config_1 is not None
        initial_version = auth_config_1.get("version")

        # Launch multiple concurrent refreshes
        # They should be serialized, not interfere with each other
        try:
            await asyncio.wait_for(
                asyncio.gather(*[manager.refresh_async() for _ in range(5)]),
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            pytest.fail("Concurrent refresh operations timed out (possible deadlock)")

        # Verify final state is valid
        assert manager._loaded is True
        auth_config_2 = await manager.get_async(auth_config)
        assert auth_config_2 is not None
        final_version = auth_config_2.get("version")

        # Version should have incremented (multiple refreshes occurred)
        assert final_version is not None
        assert initial_version is not None
        assert final_version > initial_version
