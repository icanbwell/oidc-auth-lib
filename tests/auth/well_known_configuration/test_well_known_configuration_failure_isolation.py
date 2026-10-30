"""One provider's outage must not affect another provider, and a failed fetch is shared (BAI-1382)."""

import asyncio
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import respx

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)
from simple_container.container.interfaces import IContainer
from tests.auth.well_known_configuration.test_well_known_configuration_store_only import (
    _PATCH_VALIDATE,
    ISSUER,
    JWKS_URI,
    MIN_INTERVAL_SECONDS,
    FakeClock,
    FakeStore,
    IssuerStub,
    _auth_config,
    _cache,
)

BROKEN_URI = "https://broken.example.com/.well-known/openid-configuration"


class HealthyAndBrokenIssuers(IssuerStub):
    """The healthy issuer from IssuerStub plus a second issuer that always returns 503."""

    def __init__(self, *, router: respx.MockRouter) -> None:
        super().__init__(router=router, kids=["kid-1"])
        self.broken = router.get(BROKEN_URI).mock(return_value=httpx.Response(503))


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
        yield HealthyAndBrokenIssuers(router=router)


def _broken_config() -> AuthConfig:
    return _auth_config(uri=BROKEN_URI)


async def test_failing_provider_does_not_block_the_keys_of_a_healthy_provider(
    env: OidcEnvironmentVariables, issuer: HealthyAndBrokenIssuers
) -> None:
    cache = _cache(env=env, store=FakeStore())

    jwks = await cache.get_jwks_async(auth_configs=[_broken_config(), _auth_config()])

    assert [key.get("kid") for key in jwks.keys] == ["kid-1"]


async def test_all_providers_failing_raises_instead_of_returning_empty_keys(
    env: OidcEnvironmentVariables, issuer: HealthyAndBrokenIssuers
) -> None:
    cache = _cache(env=env, store=FakeStore())

    with pytest.raises(ValueError, match="503"):
        await cache.get_jwks_async(auth_configs=[_broken_config()])


async def test_refresh_continues_for_healthy_providers_when_one_fails(
    env: OidcEnvironmentVariables, issuer: HealthyAndBrokenIssuers
) -> None:
    clock = FakeClock()
    cache = _cache(env=env, store=FakeStore(), clock=clock)
    await cache.read_async(auth_config=_auth_config())
    clock.now += MIN_INTERVAL_SECONDS + 1

    await cache.refresh_async(auth_configs=[_broken_config(), _auth_config()])

    assert issuer.discovery.call_count == 2


async def test_refresh_raises_when_every_provider_fails(
    env: OidcEnvironmentVariables, issuer: HealthyAndBrokenIssuers
) -> None:
    cache = _cache(env=env, store=FakeStore())

    with pytest.raises(ValueError, match="503"):
        await cache.refresh_async(auth_configs=[_broken_config()])


async def test_concurrent_callers_share_one_failed_fetch(
    env: OidcEnvironmentVariables, issuer: HealthyAndBrokenIssuers
) -> None:
    cache = _cache(env=env, store=FakeStore())

    outcomes = await asyncio.gather(
        *[cache.read_async(auth_config=_broken_config()) for _ in range(10)], return_exceptions=True
    )

    assert all(isinstance(o, ValueError) for o in outcomes)
    assert issuer.broken.call_count == 1


async def test_a_caller_arriving_after_a_failure_retries_the_issuer(
    env: OidcEnvironmentVariables, issuer: HealthyAndBrokenIssuers
) -> None:
    cache = _cache(env=env, store=FakeStore())
    with pytest.raises(ValueError):
        await cache.read_async(auth_config=_broken_config())

    with pytest.raises(ValueError):
        await cache.read_async(auth_config=_broken_config())

    assert issuer.broken.call_count == 2


async def test_cancelling_one_waiter_does_not_fail_the_others(
    env: OidcEnvironmentVariables, issuer: HealthyAndBrokenIssuers
) -> None:
    async def slow_discovery(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.05)
        return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS_URI})

    issuer.discovery.side_effect = slow_discovery
    cache = _cache(env=env, store=FakeStore())
    waiters = [asyncio.ensure_future(cache.read_async(auth_config=_auth_config())) for _ in range(3)]
    await asyncio.sleep(0.01)  # the shared fetch is now in flight
    waiters[0].cancel()

    results = await asyncio.gather(*waiters, return_exceptions=True)

    assert isinstance(results[0], asyncio.CancelledError)
    assert all(r is not None and not isinstance(r, BaseException) for r in results[1:])
    assert issuer.discovery.call_count == 1


@pytest.mark.parametrize(
    ("value", "valid"),
    [("0", True), ("60", True), ("-1", False), ("abc", False)],
)
def test_kid_miss_interval_rejects_negative_and_non_integer_values(
    monkeypatch: pytest.MonkeyPatch, env: OidcEnvironmentVariables, value: str, valid: bool
) -> None:
    monkeypatch.setenv("WELL_KNOWN_KID_MISS_REFETCH_MIN_INTERVAL_SECONDS", value)

    if valid:
        assert env.well_known_kid_miss_refetch_min_interval_seconds == int(value)
    else:
        with pytest.raises(ValueError, match="non-negative"):
            _ = env.well_known_kid_miss_refetch_min_interval_seconds
