import pytest
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

from joserfc.jwk import KeySet
from key_value.aio.stores.memory import MemoryStore

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache_result import (
    WellKnownConfigurationCacheResult,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)
from simple_container.container.interfaces import IContainer
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)


@dataclass
class CacheDouble:
    cache: WellKnownConfigurationCache
    read_list: AsyncMock
    refresh: AsyncMock
    get: AsyncMock
    get_jwks: AsyncMock


@pytest.fixture
def auth_configs() -> list[AuthConfig]:
    provider_with_well_known = AuthConfig(
        auth_provider="PROVIDER_A",
        friendly_name="Provider A",
        audience="api://audience-a",
        issuer="https://issuer.example.com",
        client_id="client-a",
        client_secret=None,
        well_known_uri="https://issuer.example.com/.well-known/openid-configuration",
        scope="openid profile",
    )
    provider_without_well_known = AuthConfig(
        auth_provider="PROVIDER_B",
        friendly_name="Provider B",
        audience="api://audience-b",
        issuer="https://issuer-b.example.com",
        client_id="client-b",
        client_secret=None,
        well_known_uri=None,
        scope="openid",
    )
    return [provider_with_well_known, provider_without_well_known]


@pytest.fixture
def auth_config_reader(auth_configs: list[AuthConfig]) -> MagicMock:
    reader: MagicMock = MagicMock(spec=AuthConfigReader)
    reader.get_auth_configs_for_all_auth_providers.return_value = auth_configs
    return reader


@pytest.fixture
def cache_double(test_container: IContainer) -> CacheDouble:
    environment_variables: OidcEnvironmentVariables = test_container.resolve(OidcEnvironmentVariables)
    cache = WellKnownConfigurationCache(well_known_store=MemoryStore(), environment_variables=environment_variables)
    keyset = KeySet.import_key_set({"keys": [{"kty": "oct", "kid": "kid-1", "k": "abc"}]})
    read_mock: AsyncMock = AsyncMock(return_value=None)
    refresh_mock: AsyncMock = AsyncMock(return_value=None)
    get_mock: AsyncMock = AsyncMock(return_value=None)
    get_jwks_mock: AsyncMock = AsyncMock(return_value=keyset)
    setattr(cache, "read_list_async", read_mock)
    setattr(cache, "refresh_async", refresh_mock)
    setattr(cache, "get_async", get_mock)
    setattr(cache, "get_jwks_async", get_jwks_mock)
    return CacheDouble(cache=cache, read_list=read_mock, refresh=refresh_mock, get=get_mock, get_jwks=get_jwks_mock)


def test_init_rejects_non_cache_instance(auth_config_reader: MagicMock) -> None:
    with pytest.raises(TypeError):
        WellKnownConfigurationManager(
            auth_config_reader=auth_config_reader,
            cache=MagicMock(),
        )


@pytest.mark.asyncio
async def test_ensure_initialized_async_reads_only_providers_with_a_well_known_uri_on_every_call(
    auth_config_reader: MagicMock,
    cache_double: CacheDouble,
    auth_configs: list[AuthConfig],
) -> None:
    manager = WellKnownConfigurationManager(
        auth_config_reader=auth_config_reader,
        cache=cache_double.cache,
    )

    await manager.ensure_initialized_async()
    await manager.ensure_initialized_async()

    # No once-per-process flag: the shared store is consulted each time.
    assert cache_double.read_list.await_count == 2
    assert cache_double.read_list.await_args
    passed_configs = cache_double.read_list.await_args.kwargs["auth_configs"]
    assert passed_configs == [auth_configs[0]]


@pytest.mark.asyncio
async def test_get_jwks_async_returns_the_keyset_assembled_by_the_cache(
    auth_config_reader: MagicMock, cache_double: CacheDouble, auth_configs: list[AuthConfig]
) -> None:
    manager = WellKnownConfigurationManager(
        auth_config_reader=auth_config_reader,
        cache=cache_double.cache,
    )

    first = await manager.get_jwks_async()
    await manager.get_jwks_async()

    assert [k.kid for k in first] == ["kid-1"]
    assert cache_double.get_jwks.await_count == 2
    assert cache_double.get_jwks.await_args
    assert cache_double.get_jwks.await_args.kwargs["auth_configs"] == [auth_configs[0]]


@pytest.mark.asyncio
async def test_refresh_async_delegates_to_the_rate_limited_cache_refresh(
    auth_config_reader: MagicMock,
    cache_double: CacheDouble,
    auth_configs: list[AuthConfig],
) -> None:
    manager = WellKnownConfigurationManager(
        auth_config_reader=auth_config_reader,
        cache=cache_double.cache,
    )

    await manager.refresh_async()

    assert cache_double.refresh.await_count == 1
    assert cache_double.refresh.await_args
    assert cache_double.refresh.await_args.kwargs["auth_configs"] == [auth_configs[0]]


@pytest.mark.asyncio
async def test_get_async_returns_the_cache_result(
    auth_config_reader: MagicMock,
    cache_double: CacheDouble,
    auth_configs: list[AuthConfig],
) -> None:
    expected = WellKnownConfigurationCacheResult(
        well_known_uri=auth_configs[0].well_known_uri or "",
        well_known_config={"issuer": "https://issuer.example.com"},
        client_key_set=None,
    )
    cache_double.get.return_value = expected

    manager = WellKnownConfigurationManager(
        auth_config_reader=auth_config_reader,
        cache=cache_double.cache,
    )

    result = await manager.get_async(auth_config=auth_configs[0])

    assert result == expected
    assert cache_double.get.await_count == 1
    assert cache_double.get.await_args
    passed_auth_config = cache_double.get.await_args.kwargs["auth_config"]
    assert passed_auth_config is auth_configs[0]
