"""Regression test for the "iat"/"nbf"/"exp" clock-skew leeway in TokenReader.verify_token_async.

A session JWT used immediately after it's minted can have an "iat" a fraction of a
second ahead of this host's clock (ordinary clock skew between the IdP and this
host, not a real "issued in the future" problem). With joserfc's default leeway=0,
that token is spuriously rejected. See the "recently signed-up user gets bounced
back to /login" symptom this was found from.

Note: joserfc's `JWTClaimsRegistry(leeway=...)` applies the same tolerance to "exp"
as it does to "iat"/"nbf" — a token also stays acceptable for up to
`clock_skew_leeway_seconds` past its stated expiration. This is intentional (the
same clock-skew problem applies symmetrically to expiry), but is covered explicitly
below since it's an easy side effect to miss.

All time-sensitive tests freeze `time.time()` via monkeypatch so they don't depend
on how much real wall-clock time elapses between minting a token and verifying it.
"""

import time
from unittest.mock import AsyncMock, Mock

import pytest
from joserfc import jwt
from joserfc.jwk import OctKey, KeySet

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.exceptions.authorization_bearer_token_expired_exception import (
    AuthorizationBearerTokenExpiredException,
)
from oidcauthlib.auth.exceptions.authorization_bearer_token_invalid_exception import (
    AuthorizationBearerTokenInvalidException,
)
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)

SECRET = "test-signing-secret-that-is-long-enough-for-hs256"


def _make_token_reader(*, clock_skew_leeway_seconds: int) -> TokenReader:
    auth_config = AuthConfig(
        auth_provider="PROVIDER1",
        friendly_name="Provider One",
        audience="audience-1",
        client_id="client-id-1",
        scope="openid",
    )
    auth_config_reader = Mock(spec=AuthConfigReader)
    auth_config_reader.get_auth_configs_for_all_auth_providers = Mock(return_value=[auth_config])

    key = OctKey.import_key(SECRET, {"kid": "key-1"})
    jwks = KeySet([key])

    well_known_config_manager = Mock(spec=WellKnownConfigurationManager)
    well_known_config_manager.get_jwks_async = AsyncMock(return_value=jwks)
    well_known_config_manager.get_well_known_urls = AsyncMock(return_value=["https://auth.example.com"])
    well_known_config_manager.refresh_async = AsyncMock(return_value=None)

    return TokenReader(
        algorithms=["HS256"],
        auth_config_reader=auth_config_reader,
        well_known_config_manager=well_known_config_manager,
        clock_skew_leeway_seconds=clock_skew_leeway_seconds,
    )


def _encode_token(*, iat: int, nbf: int, exp: int) -> str:
    header = {"alg": "HS256", "kid": "key-1"}
    claims = {
        "iss": "https://auth.example.com",
        "aud": "audience-1",
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
    }
    key = OctKey.import_key(SECRET, {"kid": "key-1"})
    return jwt.encode(header, claims, key)


def _make_token_signed_slightly_in_the_future(*, now: int, skew_seconds: int) -> str:
    """A token whose iat/nbf are `skew_seconds` ahead of `now` — simulating the
    issuing IdP's clock running fast relative to this host."""
    issued_at = now + skew_seconds
    return _encode_token(iat=issued_at, nbf=issued_at, exp=issued_at + 3600)


def _make_token_with_exp_offset(*, now: int, exp_offset_seconds: int) -> str:
    """A token issued well in the past whose "exp" is `exp_offset_seconds` from `now`
    (negative = already expired by that many seconds)."""
    return _encode_token(iat=now - 3600, nbf=now - 3600, exp=now + exp_offset_seconds)


def _freeze_time(monkeypatch: pytest.MonkeyPatch) -> int:
    """Pin `time.time()` for the duration of the test so token minting and
    verification agree on "now", independent of real elapsed wall-clock time."""
    frozen_now = int(time.time())
    monkeypatch.setattr(time, "time", lambda: float(frozen_now))
    return frozen_now


@pytest.mark.asyncio
async def test_token_issued_moments_ago_with_clock_skew_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default leeway absorbs a couple seconds of IdP/host clock skew."""
    now = _freeze_time(monkeypatch)
    token_reader = _make_token_reader(clock_skew_leeway_seconds=10)
    token = _make_token_signed_slightly_in_the_future(now=now, skew_seconds=2)

    result = await token_reader.verify_token_async(token=token)

    assert result is not None


@pytest.mark.asyncio
async def test_token_beyond_leeway_window_is_still_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Leeway isn't unlimited — a token genuinely far in the future still fails."""
    now = _freeze_time(monkeypatch)
    token_reader = _make_token_reader(clock_skew_leeway_seconds=10)
    token = _make_token_signed_slightly_in_the_future(now=now, skew_seconds=120)

    with pytest.raises(AuthorizationBearerTokenInvalidException):
        await token_reader.verify_token_async(token=token)


@pytest.mark.asyncio
async def test_zero_leeway_rejects_the_same_clock_skew(monkeypatch: pytest.MonkeyPatch) -> None:
    """Demonstrates the bug this fix addresses: with no leeway, even trivial skew 401s."""
    now = _freeze_time(monkeypatch)
    token_reader = _make_token_reader(clock_skew_leeway_seconds=0)
    token = _make_token_signed_slightly_in_the_future(now=now, skew_seconds=2)

    with pytest.raises(AuthorizationBearerTokenInvalidException):
        await token_reader.verify_token_async(token=token)


@pytest.mark.asyncio
async def test_token_expired_within_leeway_is_still_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """joserfc applies `leeway` to "exp" too: a token that expired moments ago,
    within the leeway window, is still accepted — the same tolerance that absorbs
    iat/nbf clock skew also grants a grace period past expiration."""
    now = _freeze_time(monkeypatch)
    token_reader = _make_token_reader(clock_skew_leeway_seconds=10)
    token = _make_token_with_exp_offset(now=now, exp_offset_seconds=-3)

    result = await token_reader.verify_token_async(token=token)

    assert result is not None


@pytest.mark.asyncio
async def test_token_expired_beyond_leeway_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exp grace period is bounded by leeway — a token expired well beyond it
    is still rejected as expired."""
    now = _freeze_time(monkeypatch)
    token_reader = _make_token_reader(clock_skew_leeway_seconds=10)
    token = _make_token_with_exp_offset(now=now, exp_offset_seconds=-20)

    with pytest.raises(AuthorizationBearerTokenExpiredException):
        await token_reader.verify_token_async(token=token)
