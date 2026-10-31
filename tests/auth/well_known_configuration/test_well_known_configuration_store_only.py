"""Behaviour of WellKnownConfigurationCache when every read goes to the shared store (BAI-1382)."""

import asyncio
import time
import warnings
from typing import Any, Callable, Mapping, Sequence, SupportsFloat, override
from unittest.mock import patch

import httpx
import pytest
import respx
from joserfc.jwk import RSAKey
from key_value.aio.stores.memory import MemoryStore

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache_result import (
    WellKnownConfigurationCacheResult,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)
from simple_container.container.interfaces import IContainer
from unittest.mock import MagicMock

ISSUER = "https://issuer.example.com"
WELL_KNOWN_URI = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URI = f"{ISSUER}/jwks"
TTL_SECONDS = 3600
MIN_INTERVAL_SECONDS = 60
_PATCH_VALIDATE = "oidcauthlib.auth.well_known_configuration.well_known_configuration_cache.validate_url"


class FakeStore(MemoryStore):
    """In-memory store double (the external boundary) with call counts, latency and failure injection."""

    def __init__(self, *, latency_seconds: float = 0.0) -> None:
        super().__init__()
        self.latency_seconds = latency_seconds
        self.get_calls = 0
        self.get_many_calls = 0
        self.put_calls = 0
        self.fail_get: Exception | None = None
        self.fail_put: Exception | None = None

    @override
    async def get(self, key: str, *, collection: str | None = None) -> dict[str, Any] | None:
        self.get_calls += 1
        if self.latency_seconds:
            await asyncio.sleep(self.latency_seconds)
        if self.fail_get is not None:
            raise self.fail_get
        row: dict[str, Any] | None = await super().get(key=key, collection=collection)
        return row

    @override
    async def get_many(self, keys: Sequence[str], *, collection: str | None = None) -> list[dict[str, Any] | None]:
        self.get_many_calls += 1
        if self.latency_seconds:
            await asyncio.sleep(self.latency_seconds)
        if self.fail_get is not None:
            raise self.fail_get
        rows: list[dict[str, Any] | None] = await super().get_many(keys=keys, collection=collection)
        return rows

    @property
    def read_round_trips(self) -> int:
        """Store read operations issued (a get or a batched get_many each cost one round trip)."""
        return self.get_calls + self.get_many_calls

    @override
    async def put(
        self,
        key: str,
        value: Mapping[str, Any],
        *,
        collection: str | None = None,
        ttl: SupportsFloat | None = None,
    ) -> None:
        self.put_calls += 1
        if self.fail_put is not None:
            raise self.fail_put
        await super().put(key=key, value=value, collection=collection, ttl=ttl)


class FakeClock:
    def __init__(self, *, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _public_jwk(*, kid: str) -> dict[str, Any]:
    return RSAKey.generate_key(2048, parameters={"kid": kid, "use": "sig"}).as_dict(private=False)


def _auth_config(*, uri: str | None = WELL_KNOWN_URI) -> AuthConfig:
    return AuthConfig(
        auth_provider="TEST_PROVIDER",
        friendly_name="Test Provider",
        audience="test_audience",
        issuer=ISSUER,
        client_id="test_client_id",
        well_known_uri=uri,
        scope="openid profile email",
    )


class IssuerStub:
    """respx-backed issuer whose JWKS can be rotated between calls."""

    def __init__(self, *, router: respx.MockRouter, kids: list[str]) -> None:
        self.kids = kids
        self.discovery = router.get(WELL_KNOWN_URI).mock(
            return_value=httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS_URI})
        )
        self.jwks = router.get(JWKS_URI).mock(side_effect=self._jwks_response)

    def _jwks_response(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"keys": [_public_jwk(kid=k) for k in self.kids]})


@pytest.fixture(autouse=True)
def _bypass_url_validation() -> Any:
    with patch(_PATCH_VALIDATE, side_effect=lambda url, **kw: url):
        yield


@pytest.fixture
def env(test_container: IContainer) -> OidcEnvironmentVariables:
    return test_container.resolve(OidcEnvironmentVariables)


@pytest.fixture
def issuer() -> Any:
    with respx.mock(assert_all_called=False) as router:
        yield IssuerStub(router=router, kids=["kid-1"])


def _cache(
    *, env: OidcEnvironmentVariables, store: FakeStore | None, clock: Callable[[], float] = time.time
) -> WellKnownConfigurationCache:
    return WellKnownConfigurationCache(well_known_store=store, environment_variables=env, clock=clock)


async def _put_row(*, store: FakeStore, row: dict[str, Any]) -> None:
    await MemoryStore.put(store, key=WELL_KNOWN_URI, value=row, ttl=TTL_SECONDS)


async def _stored_row(*, store: FakeStore) -> dict[str, Any]:
    row = await MemoryStore.get(store, key=WELL_KNOWN_URI)
    assert row is not None
    return dict(row)


async def test_every_read_goes_to_the_store(env: OidcEnvironmentVariables, issuer: IssuerStub) -> None:
    store = FakeStore()
    cache = _cache(env=env, store=store)

    for _ in range(3):
        assert await cache.read_async(auth_config=_auth_config()) is not None

    assert issuer.discovery.call_count == 1
    assert issuer.jwks.call_count == 1
    # one read per call, plus the double-checked read under the lock on the cold miss
    assert store.get_calls >= 3 + 1
    assert store.put_calls == 1


async def test_second_instance_sharing_a_store_sees_first_instances_fetch(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    store = FakeStore()
    pod_a, pod_b = _cache(env=env, store=store), _cache(env=env, store=store)

    await pod_a.read_async(auth_config=_auth_config())
    result_b = await pod_b.read_async(auth_config=_auth_config())

    assert result_b is not None
    assert issuer.discovery.call_count == 1


async def test_change_written_to_the_store_is_visible_immediately_to_another_instance(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    """No memory layer: a row replaced in the shared store (by another pod) is served at once."""
    store = FakeStore()
    pod_a = _cache(env=env, store=store)
    first = await pod_a.get_jwks_async(auth_configs=[_auth_config()])
    assert [k.kid for k in first] == ["kid-1"]

    rotated = await _stored_row(store=store)
    rotated["client_key_set"]["keys"] = [_public_jwk(kid="kid-2")]
    rotated["client_key_set"]["kids"] = ["kid-2"]
    await _put_row(store=store, row=rotated)

    second = await pod_a.get_jwks_async(auth_configs=[_auth_config()])
    assert [k.kid for k in second] == ["kid-2"]
    assert issuer.discovery.call_count == 1


async def test_deleting_the_row_forces_a_refetch_by_every_instance(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    store = FakeStore()
    pod_a, pod_b = _cache(env=env, store=store), _cache(env=env, store=store)
    await pod_a.read_async(auth_config=_auth_config())
    await pod_b.read_async(auth_config=_auth_config())

    await pod_a.clear_async()
    await pod_b.read_async(auth_config=_auth_config())

    assert issuer.discovery.call_count == 2


@pytest.mark.parametrize(
    ("age_seconds", "expect_refetch"),
    [
        (0, False),
        (TTL_SECONDS - 1, False),
        (TTL_SECONDS, False),
        (TTL_SECONDS + 1, True),
        (TTL_SECONDS * 10, True),
    ],
)
async def test_row_older_than_ttl_is_refetched_even_if_the_store_did_not_expire_it(
    env: OidcEnvironmentVariables, issuer: IssuerStub, age_seconds: int, expect_refetch: bool
) -> None:
    store, clock = FakeStore(), FakeClock()
    cache = _cache(env=env, store=store, clock=clock)
    await cache.read_async(auth_config=_auth_config())

    clock.now += age_seconds
    await cache.read_async(auth_config=_auth_config())

    assert issuer.discovery.call_count == (2 if expect_refetch else 1)


async def test_row_without_fetched_at_relies_on_the_store_ttl(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    store = FakeStore()
    cache = _cache(env=env, store=store)
    await cache.read_async(auth_config=_auth_config())
    legacy = await _stored_row(store=store)
    legacy.pop("fetched_at")
    await _put_row(store=store, row=legacy)

    assert await cache.read_async(auth_config=_auth_config()) is not None
    assert issuer.discovery.call_count == 1


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda row: row.update(schema_version=WellKnownConfigurationCacheResult.SCHEMA_VERSION - 1), id="old"
        ),
        pytest.param(lambda row: row.update(schema_version=0), id="missing"),
        pytest.param(lambda row: row.update(well_known_uri="https://other.example.com/x"), id="uri-mismatch"),
        pytest.param(lambda row: row.pop("well_known_config"), id="invalid-shape"),
    ],
)
async def test_unusable_row_is_treated_as_a_miss_and_refetched(
    env: OidcEnvironmentVariables,
    issuer: IssuerStub,
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    store = FakeStore()
    cache = _cache(env=env, store=store)
    await cache.read_async(auth_config=_auth_config())
    row = await _stored_row(store=store)
    mutate(row)
    await _put_row(store=store, row=row)

    result = await cache.read_async(auth_config=_auth_config())

    assert result is not None and result.is_schema_current()
    assert issuer.discovery.call_count == 2


async def test_unknown_extra_fields_in_a_newer_row_are_tolerated(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    store = FakeStore()
    cache = _cache(env=env, store=store)
    await cache.read_async(auth_config=_auth_config())
    row = await _stored_row(store=store)
    row["field_from_the_future"] = {"x": 1}
    await _put_row(store=store, row=row)

    assert await cache.read_async(auth_config=_auth_config()) is not None
    assert issuer.discovery.call_count == 1


@pytest.mark.parametrize(
    ("elapsed_seconds", "expect_refetch"),
    [
        (0, False),
        (MIN_INTERVAL_SECONDS - 1, False),
        (MIN_INTERVAL_SECONDS, True),
        (MIN_INTERVAL_SECONDS + 1, True),
    ],
)
async def test_kid_miss_refresh_is_rate_limited_by_the_stored_fetch_time(
    env: OidcEnvironmentVariables, issuer: IssuerStub, elapsed_seconds: int, expect_refetch: bool
) -> None:
    store, clock = FakeStore(), FakeClock()
    cache = _cache(env=env, store=store, clock=clock)
    await cache.read_async(auth_config=_auth_config())
    issuer.kids = ["kid-1", "kid-rotated-in"]

    clock.now += elapsed_seconds
    await cache.refresh_async(auth_configs=[_auth_config()])

    keys = await cache.get_jwks_async(auth_configs=[_auth_config()])
    assert issuer.discovery.call_count == (2 if expect_refetch else 1)
    assert ("kid-rotated-in" in [k.kid for k in keys]) is expect_refetch


async def test_kid_miss_refresh_rate_limit_is_shared_across_instances(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    store, clock = FakeStore(), FakeClock()
    pod_a, pod_b = _cache(env=env, store=store, clock=clock), _cache(env=env, store=store, clock=clock)
    await pod_a.read_async(auth_config=_auth_config())
    clock.now += MIN_INTERVAL_SECONDS

    await pod_a.refresh_async(auth_configs=[_auth_config()])
    await pod_b.refresh_async(auth_configs=[_auth_config()])

    assert issuer.discovery.call_count == 2  # initial fetch + exactly one refresh across both pods


async def test_flood_of_kid_miss_refreshes_causes_one_issuer_fetch(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    store, clock = FakeStore(), FakeClock()
    cache = _cache(env=env, store=store, clock=clock)
    await cache.read_async(auth_config=_auth_config())
    clock.now += MIN_INTERVAL_SECONDS

    await asyncio.gather(*[cache.refresh_async(auth_configs=[_auth_config()]) for _ in range(50)])

    assert issuer.discovery.call_count == 2


async def test_refresh_overwrites_the_row_without_deleting_it_first(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    store, clock = FakeStore(), FakeClock()
    cache = _cache(env=env, store=store, clock=clock)
    await cache.read_async(auth_config=_auth_config())
    clock.now += MIN_INTERVAL_SECONDS
    issuer.discovery.side_effect = httpx.ConnectError("issuer down")

    with pytest.raises(ConnectionError):
        await cache.refresh_async(auth_configs=[_auth_config()])

    assert (await _stored_row(store=store))["client_key_set"] is not None


@pytest.mark.parametrize("operation", ["read", "jwks", "refresh", "kid_lookup"])
async def test_store_read_failure_fails_closed_without_contacting_the_issuer(
    env: OidcEnvironmentVariables, issuer: IssuerStub, operation: str
) -> None:
    store = FakeStore()
    cache = _cache(env=env, store=store)
    await cache.read_async(auth_config=_auth_config())
    issuer.discovery.reset()
    store.fail_get = RuntimeError("mongo unavailable")
    config = _auth_config()
    operations: dict[str, Callable[[], Any]] = {
        "read": lambda: cache.read_async(auth_config=config),
        "jwks": lambda: cache.get_jwks_async(auth_configs=[config]),
        "refresh": lambda: cache.refresh_async(auth_configs=[config]),
        "kid_lookup": lambda: cache.get_client_key_set_for_kid_async(kid="kid-1"),
    }

    with pytest.raises(RuntimeError, match="mongo unavailable"):
        await operations[operation]()

    assert issuer.discovery.call_count == 0


async def test_store_write_failure_fails_closed(env: OidcEnvironmentVariables, issuer: IssuerStub) -> None:
    store = FakeStore()
    store.fail_put = RuntimeError("mongo write failed")
    cache = _cache(env=env, store=store)

    with pytest.raises(RuntimeError, match="mongo write failed"):
        await cache.read_async(auth_config=_auth_config())


async def test_issuer_failure_on_cold_miss_raises_and_stores_nothing(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    store = FakeStore()
    issuer.discovery.mock(return_value=httpx.Response(500))
    cache = _cache(env=env, store=store)

    with pytest.raises(ValueError):
        await cache.read_async(auth_config=_auth_config())

    assert store.put_calls == 0


@pytest.mark.parametrize("concurrency", [2, 20, 100])
async def test_concurrent_cold_start_in_one_instance_fetches_once(
    env: OidcEnvironmentVariables, issuer: IssuerStub, concurrency: int
) -> None:
    store = FakeStore(latency_seconds=0.002)
    cache = _cache(env=env, store=store)

    results = await asyncio.gather(*[cache.read_async(auth_config=_auth_config()) for _ in range(concurrency)])

    assert all(r is not None for r in results)
    assert issuer.discovery.call_count == 1
    assert store.put_calls == 1


async def test_concurrent_cold_start_across_instances_is_bounded_by_instance_count(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    """Cross-pod duplicate fetches are tolerated (upsert); each pod fetches at most once."""
    store = FakeStore(latency_seconds=0.002)
    pods = [_cache(env=env, store=store) for _ in range(3)]

    await asyncio.gather(*[p.read_async(auth_config=_auth_config()) for p in pods for _ in range(10)])

    assert 1 <= issuer.discovery.call_count <= len(pods)
    assert await pods[0].get_size_async() == 1


async def test_no_store_is_deprecated_but_still_serves_from_a_private_store(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    with pytest.warns(DeprecationWarning, match="well_known_store"):
        cache = WellKnownConfigurationCache(well_known_store=None, environment_variables=env)

    await cache.read_async(auth_config=_auth_config())
    await cache.read_async(auth_config=_auth_config())

    assert issuer.discovery.call_count == 1


async def test_with_a_store_no_deprecation_warning_is_emitted(env: OidcEnvironmentVariables) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        _cache(env=env, store=FakeStore())


def test_jwks_property_no_longer_holds_keys_in_memory(env: OidcEnvironmentVariables) -> None:
    cache = _cache(env=env, store=FakeStore())

    with pytest.raises(RuntimeError, match="get_jwks_async"):
        _ = cache.jwks


async def test_get_jwks_async_dedupes_by_kid_and_skips_configs_without_uri(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    issuer.kids = ["kid-1", "kid-1", "kid-2"]
    cache = _cache(env=env, store=FakeStore())

    keys = await cache.get_jwks_async(auth_configs=[_auth_config(), _auth_config(uri=None)])

    assert sorted(str(k.kid) for k in keys) == ["kid-1", "kid-2"]


async def test_get_client_key_set_for_kid_reads_the_store(env: OidcEnvironmentVariables, issuer: IssuerStub) -> None:
    store = FakeStore()
    cache = _cache(env=env, store=store)
    await cache.read_async(auth_config=_auth_config())

    assert await cache.get_client_key_set_for_kid_async(kid="kid-1") is not None
    assert await cache.get_client_key_set_for_kid_async(kid="nope") is None
    assert await cache.get_client_key_set_for_kid_async(kid=None) is None


async def test_manager_has_no_loaded_flag_and_reads_the_store_on_each_jwks_call(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    store = FakeStore()
    reader = MagicMock(spec=AuthConfigReader)
    reader.get_auth_configs_for_all_auth_providers.return_value = [_auth_config(), _auth_config(uri=None)]
    manager = WellKnownConfigurationManager(auth_config_reader=reader, cache=_cache(env=env, store=store))

    await manager.get_jwks_async()
    reads_after_first = store.read_round_trips
    await manager.get_jwks_async()

    assert store.read_round_trips > reads_after_first
    assert issuer.discovery.call_count == 1


async def test_manager_refresh_does_not_delete_and_is_rate_limited(
    env: OidcEnvironmentVariables, issuer: IssuerStub
) -> None:
    store, clock = FakeStore(), FakeClock()
    reader = MagicMock(spec=AuthConfigReader)
    reader.get_auth_configs_for_all_auth_providers.return_value = [_auth_config()]
    manager = WellKnownConfigurationManager(auth_config_reader=reader, cache=_cache(env=env, store=store, clock=clock))
    await manager.get_jwks_async()

    await manager.refresh_async()  # inside the interval: no refetch
    assert issuer.discovery.call_count == 1
    clock.now += MIN_INTERVAL_SECONDS
    issuer.kids = ["kid-1", "kid-new"]
    await manager.refresh_async()

    assert issuer.discovery.call_count == 2
    assert "kid-new" in [k.kid for k in await manager.get_jwks_async()]


async def test_each_validation_costs_one_store_round_trip(env: OidcEnvironmentVariables, issuer: IssuerStub) -> None:
    store = FakeStore()
    cache = _cache(env=env, store=store)
    await cache.read_async(auth_config=_auth_config())  # warm the store
    before = store.read_round_trips
    iterations = 30

    for _ in range(iterations):
        await cache.get_jwks_async(auth_configs=[_auth_config()])

    assert store.read_round_trips - before == iterations
