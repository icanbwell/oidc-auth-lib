"""Store reads per token validation (BAI-1382): only the matching provider's row is read, in one round trip."""

import time
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx
from joserfc import jwt
from joserfc.jwk import ECKey

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.exceptions.authorization_bearer_token_invalid_exception import (
    AuthorizationBearerTokenInvalidException,
)
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)
from simple_container.container.interfaces import IContainer
from tests.auth.well_known_configuration.test_well_known_configuration_store_only import (
    FakeClock,
    FakeStore,
)

PROVIDER_COUNT = 8
MIN_INTERVAL_SECONDS = 60
_PATCH_VALIDATE = "oidcauthlib.auth.well_known_configuration.well_known_configuration_cache.validate_url"


def _issuer(index: int) -> str:
    return f"https://issuer{index}.example.com"


def _audience(index: int) -> str:
    return f"api://audience-{index}"


class Providers:
    """N issuers served through respx, each with its own EC key; keys can be rotated."""

    def __init__(self, *, router: respx.MockRouter, count: int) -> None:
        self.keys: dict[int, ECKey] = {}
        self.discovery_routes: dict[int, respx.Route] = {}
        for i in range(count):
            self.rotate(index=i, kid=f"kid-{i}-a")
            self.discovery_routes[i] = router.get(f"{_issuer(i)}/.well-known/openid-configuration").mock(
                return_value=httpx.Response(200, json={"issuer": _issuer(i), "jwks_uri": f"{_issuer(i)}/jwks"})
            )
            router.get(f"{_issuer(i)}/jwks").mock(side_effect=self._jwks_response(index=i))

    def rotate(self, *, index: int, kid: str) -> None:
        self.keys[index] = ECKey.generate_key("P-256", parameters={"kid": kid, "use": "sig"})

    def _jwks_response(self, *, index: int) -> Any:
        return lambda request: httpx.Response(200, json={"keys": [self.keys[index].as_dict(private=False)]})

    def token(self, *, signer: int, iss: int, aud: int) -> str:
        key = self.keys[signer]
        now = int(time.time())
        claims = {"iss": _issuer(iss), "aud": _audience(aud), "sub": "user-1", "iat": now, "exp": now + 600}
        return jwt.encode({"alg": "ES256", "kid": key.kid}, claims, key)


def _auth_configs(*, count: int) -> list[AuthConfig]:
    return [
        AuthConfig(
            auth_provider=f"PROVIDER_{i}",
            friendly_name=f"Provider {i}",
            audience=_audience(i),
            issuer=_issuer(i),
            client_id=f"client-{i}",
            well_known_uri=f"{_issuer(i)}/.well-known/openid-configuration",
            scope="openid",
        )
        for i in range(count)
    ]


@pytest.fixture(autouse=True)
def _bypass_url_validation() -> Any:
    with patch(_PATCH_VALIDATE, side_effect=lambda url, **kw: url):
        yield


@pytest.fixture
def providers() -> Any:
    with respx.mock(assert_all_called=False) as router:
        yield Providers(router=router, count=PROVIDER_COUNT)


def _reader(
    *, test_container: IContainer, store: FakeStore, clock: FakeClock, configs: list[AuthConfig]
) -> TokenReader:
    env = test_container.resolve(OidcEnvironmentVariables)
    config_reader = MagicMock(spec=AuthConfigReader)
    config_reader.get_auth_configs_for_all_auth_providers.return_value = configs
    cache = WellKnownConfigurationCache(well_known_store=store, environment_variables=env, clock=clock)
    manager = WellKnownConfigurationManager(auth_config_reader=config_reader, cache=cache)
    return TokenReader(
        auth_config_reader=config_reader,
        well_known_config_manager=manager,
        environment_variables=env,
    )


async def _warmed_reader(*, test_container: IContainer, store: FakeStore, clock: FakeClock) -> TokenReader:
    reader = _reader(
        test_container=test_container, store=store, clock=clock, configs=_auth_configs(count=PROVIDER_COUNT)
    )
    await reader._well_known_config_manager.ensure_initialized_async()
    return reader


async def test_valid_token_costs_one_store_round_trip_regardless_of_provider_count(
    test_container: IContainer, providers: Providers
) -> None:
    store, clock = FakeStore(), FakeClock()
    reader = await _warmed_reader(test_container=test_container, store=store, clock=clock)
    before = store.read_round_trips

    token = await reader.verify_token_async(token=providers.token(signer=3, iss=3, aud=3))

    assert token is not None
    assert store.read_round_trips - before == 1


@pytest.mark.parametrize("provider_count", [1, 3, PROVIDER_COUNT])
async def test_round_trips_do_not_grow_with_the_number_of_configured_providers(
    test_container: IContainer, providers: Providers, provider_count: int
) -> None:
    store, clock = FakeStore(), FakeClock()
    reader = _reader(
        test_container=test_container, store=store, clock=clock, configs=_auth_configs(count=provider_count)
    )
    await reader._well_known_config_manager.ensure_initialized_async()
    before = store.read_round_trips

    await reader.verify_token_async(token=providers.token(signer=0, iss=0, aud=0))

    assert store.read_round_trips - before == 1


async def test_unknown_issuer_is_rejected_without_any_store_read(
    test_container: IContainer, providers: Providers
) -> None:
    store, clock = FakeStore(), FakeClock()
    reader = await _warmed_reader(test_container=test_container, store=store, clock=clock)
    before = store.read_round_trips
    stranger = ECKey.generate_key("P-256", parameters={"kid": "kid-x"})
    now = int(time.time())
    claims = {"iss": "https://unknown.example.com", "aud": _audience(0), "iat": now, "exp": now + 600}
    token = jwt.encode({"alg": "ES256", "kid": "kid-x"}, claims, stranger)

    with pytest.raises(AuthorizationBearerTokenInvalidException):
        await reader.verify_token_async(token=token)

    assert store.read_round_trips == before


async def test_token_claiming_one_issuer_but_signed_by_another_providers_key_is_rejected(
    test_container: IContainer, providers: Providers
) -> None:
    """Narrowing only shrinks the key set offered to the verifier, so this is rejected."""
    store, clock = FakeStore(), FakeClock()
    reader = await _warmed_reader(test_container=test_container, store=store, clock=clock)

    with pytest.raises(AuthorizationBearerTokenInvalidException):
        await reader.verify_token_async(token=providers.token(signer=5, iss=2, aud=2))


@pytest.mark.parametrize(("iss", "aud"), [(1, 2), (2, 1), (4, 0)])
async def test_issuer_or_audience_mismatch_is_still_rejected(
    test_container: IContainer, providers: Providers, iss: int, aud: int
) -> None:
    store, clock = FakeStore(), FakeClock()
    reader = await _warmed_reader(test_container=test_container, store=store, clock=clock)

    with pytest.raises(AuthorizationBearerTokenInvalidException):
        await reader.verify_token_async(token=providers.token(signer=iss, iss=iss, aud=aud))


async def test_unverified_issuer_never_decides_validity_a_tampered_token_is_rejected(
    test_container: IContainer, providers: Providers
) -> None:
    store, clock = FakeStore(), FakeClock()
    reader = await _warmed_reader(test_container=test_container, store=store, clock=clock)
    header, payload, signature = providers.token(signer=1, iss=1, aud=1).split(".")

    with pytest.raises(AuthorizationBearerTokenInvalidException):
        await reader.verify_token_async(token=f"{header}.{payload}.{signature[:-4]}AAAA")


async def test_kid_miss_inside_the_rate_limit_window_refetches_nothing_and_fails_closed(
    test_container: IContainer, providers: Providers
) -> None:
    store, clock = FakeStore(), FakeClock()
    reader = await _warmed_reader(test_container=test_container, store=store, clock=clock)
    providers.rotate(index=3, kid="kid-3-b")
    fetches_before = providers.discovery_routes[3].call_count
    before = store.read_round_trips

    with pytest.raises(AuthorizationBearerTokenInvalidException):
        await reader.verify_token_async(token=providers.token(signer=3, iss=3, aud=3))

    assert providers.discovery_routes[3].call_count == fetches_before
    # get_many, refresh's single get (rate limited), get_many again; still only provider 3's row
    assert store.read_round_trips - before == 3


async def test_kid_miss_after_the_rate_limit_window_refetches_only_that_provider_and_succeeds(
    test_container: IContainer, providers: Providers
) -> None:
    store, clock = FakeStore(), FakeClock()
    reader = await _warmed_reader(test_container=test_container, store=store, clock=clock)
    providers.rotate(index=3, kid="kid-3-b")
    clock.now += MIN_INTERVAL_SECONDS
    counts_before = {i: r.call_count for i, r in providers.discovery_routes.items()}

    token = await reader.verify_token_async(token=providers.token(signer=3, iss=3, aud=3))

    assert token is not None
    assert providers.discovery_routes[3].call_count == counts_before[3] + 1
    assert all(providers.discovery_routes[i].call_count == counts_before[i] for i in range(PROVIDER_COUNT) if i != 3)


async def test_two_readers_sharing_one_store_both_see_a_rotation_done_by_one(
    test_container: IContainer, providers: Providers
) -> None:
    store, clock = FakeStore(), FakeClock()
    pod_a = await _warmed_reader(test_container=test_container, store=store, clock=clock)
    pod_b = await _warmed_reader(test_container=test_container, store=store, clock=clock)
    providers.rotate(index=3, kid="kid-3-b")
    clock.now += MIN_INTERVAL_SECONDS
    rotated_token = providers.token(signer=3, iss=3, aud=3)
    fetches_before = providers.discovery_routes[3].call_count

    assert await pod_a.verify_token_async(token=rotated_token) is not None  # refetches and stores
    assert await pod_b.verify_token_async(token=rotated_token) is not None  # finds the new row, no refetch

    assert providers.discovery_routes[3].call_count == fetches_before + 1


async def test_store_failure_during_validation_fails_closed(test_container: IContainer, providers: Providers) -> None:
    store, clock = FakeStore(), FakeClock()
    reader = await _warmed_reader(test_container=test_container, store=store, clock=clock)
    store.fail_get = RuntimeError("mongo unavailable")

    with pytest.raises(RuntimeError, match="mongo unavailable"):
        await reader.verify_token_async(token=providers.token(signer=3, iss=3, aud=3))
