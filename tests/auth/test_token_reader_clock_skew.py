"""Regression test for the "iat"/"nbf" clock-skew leeway in TokenReader.verify_token_async.

A session JWT used immediately after it's minted can have an "iat" a fraction of a
second ahead of this host's clock (ordinary clock skew between the IdP and this
host, not a real "issued in the future" problem). With joserfc's default leeway=0,
that token is spuriously rejected. See the "recently signed-up user gets bounced
back to /login" symptom this was found from.
"""

import time
from unittest.mock import AsyncMock, Mock

import pytest
from joserfc import jwt
from joserfc.jwk import OctKey, KeySet

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
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


def _make_token_signed_slightly_in_the_future(*, skew_seconds: int) -> str:
    """A token whose iat/nbf are `skew_seconds` ahead of real now — simulating the
    issuing IdP's clock running fast relative to this host."""
    now = int(time.time()) + skew_seconds
    header = {"alg": "HS256", "kid": "key-1"}
    claims = {
        "iss": "https://auth.example.com",
        "aud": "audience-1",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
    }
    key = OctKey.import_key(SECRET, {"kid": "key-1"})
    return jwt.encode(header, claims, key)


@pytest.mark.asyncio
async def test_token_issued_moments_ago_with_clock_skew_is_accepted() -> None:
    """Default leeway absorbs a couple seconds of IdP/host clock skew."""
    token_reader = _make_token_reader(clock_skew_leeway_seconds=10)
    token = _make_token_signed_slightly_in_the_future(skew_seconds=2)

    result = await token_reader.verify_token_async(token=token)

    assert result is not None


@pytest.mark.asyncio
async def test_token_beyond_leeway_window_is_still_rejected() -> None:
    """Leeway isn't unlimited — a token genuinely far in the future still fails."""
    token_reader = _make_token_reader(clock_skew_leeway_seconds=10)
    token = _make_token_signed_slightly_in_the_future(skew_seconds=120)

    with pytest.raises(Exception):
        await token_reader.verify_token_async(token=token)


@pytest.mark.asyncio
async def test_zero_leeway_rejects_the_same_clock_skew(monkeypatch: pytest.MonkeyPatch) -> None:
    """Demonstrates the bug this fix addresses: with no leeway, even trivial skew 401s."""
    token_reader = _make_token_reader(clock_skew_leeway_seconds=0)
    token = _make_token_signed_slightly_in_the_future(skew_seconds=2)

    with pytest.raises(Exception):
        await token_reader.verify_token_async(token=token)
