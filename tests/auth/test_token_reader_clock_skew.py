"""TokenReader.verify_token_async must tolerate small clock skew on `iat`.

Without a nonzero JWTClaimsRegistry leeway, any clock drift between the
token issuer and the verifying process -- even sub-second -- makes
validate_iat reject a legitimately-issued token as "issued in the future".
Observed in practice: a local dev VM (Colima) whose clock drifted a couple
of seconds ahead of the host intermittently broke mcp-fhir-agent's e2e
tests this way.
"""

import os
from typing import List, Optional, override

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.exceptions.authorization_bearer_token_invalid_exception import (
    AuthorizationBearerTokenInvalidException,
)
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)

_PROVIDER = "PROVIDER1"
_AUDIENCE = "aud1"


class _StaticJwksManager(WellKnownConfigurationManager):
    """Minimal WellKnownConfigurationManager returning a fixed JWKS."""

    # noinspection PyMissingConstructor
    def __init__(self, *, auth_config_reader: AuthConfigReader, jwks: KeySet) -> None:
        self._auth_configs = auth_config_reader.get_auth_configs_for_all_auth_providers()
        self._jwks = jwks

    @override
    async def get_jwks_async(self) -> KeySet:
        return self._jwks

    @override
    async def refresh_async(self) -> None:
        return None

    @override
    async def get_well_known_urls(self) -> List[str]:
        return [c.well_known_uri for c in self._auth_configs if c.well_known_uri]


def _make_auth_config_reader() -> AuthConfigReader:
    os.environ["AUTH_REDIRECT_URI"] = "https://example.com/callback"
    os.environ[f"AUTH_CLIENT_ID_{_PROVIDER}"] = "client-id-1"
    os.environ[f"AUTH_CLIENT_SECRET_{_PROVIDER}"] = "client-secret-1"
    os.environ[f"AUTH_AUDIENCE_{_PROVIDER}"] = _AUDIENCE
    os.environ[f"AUTH_FRIENDLY_NAME_{_PROVIDER}"] = "Provider One"

    class _Env(OidcEnvironmentVariables):
        @property
        @override
        def auth_providers(self) -> Optional[List[str]]:
            return [_PROVIDER]

    return AuthConfigReader(environment_variables=_Env())


def _make_token_reader(*, key: RSAKey) -> TokenReader:
    """Build a TokenReader with no explicit environment_variables, so it
    reads JWT_CLOCK_SKEW_LEEWAY_SECONDS live from os.environ on every
    verify_token_async call -- callers control leeway via monkeypatch.setenv,
    kept active for the whole test (construction AND the verify call)."""
    auth_config_reader = _make_auth_config_reader()
    jwks = KeySet(keys=[key])
    well_known_config_manager = _StaticJwksManager(auth_config_reader=auth_config_reader, jwks=jwks)
    return TokenReader(
        algorithms=["RS256"],
        auth_config_reader=auth_config_reader,
        well_known_config_manager=well_known_config_manager,
    )


def _make_token(*, key: RSAKey, iat_offset_seconds: int) -> str:
    import time

    now = int(time.time())
    claims = {
        "sub": "user1",
        "iss": "https://issuer.example.com",
        "aud": _AUDIENCE,
        "iat": now + iat_offset_seconds,
        "exp": now + 3600,
    }
    return jwt.encode({"alg": "RS256", "kid": key.kid}, claims, key)


@pytest.fixture
def rsa_key() -> RSAKey:
    return RSAKey.generate_key(2048, auto_kid=True)


@pytest.mark.asyncio
async def test_tolerates_small_clock_skew_within_default_leeway(
    rsa_key: RSAKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A token issued a few seconds 'in the future' (clock skew) is accepted
    under the default (10s) leeway."""
    monkeypatch.delenv("JWT_CLOCK_SKEW_LEEWAY_SECONDS", raising=False)
    token_reader = _make_token_reader(key=rsa_key)
    token = _make_token(key=rsa_key, iat_offset_seconds=3)

    result = await token_reader.verify_token_async(token=token)

    assert result is not None


@pytest.mark.asyncio
async def test_rejects_clock_skew_beyond_configured_leeway(rsa_key: RSAKey, monkeypatch: pytest.MonkeyPatch) -> None:
    """leeway is a tolerance, not a bypass: a token issued well beyond it is
    still rejected."""
    monkeypatch.setenv("JWT_CLOCK_SKEW_LEEWAY_SECONDS", "5")
    token_reader = _make_token_reader(key=rsa_key)
    token = _make_token(key=rsa_key, iat_offset_seconds=3600)

    with pytest.raises(AuthorizationBearerTokenInvalidException):
        await token_reader.verify_token_async(token=token)


@pytest.mark.asyncio
async def test_leeway_is_configurable_via_env_var(rsa_key: RSAKey, monkeypatch: pytest.MonkeyPatch) -> None:
    """A skew that the default leeway would reject is accepted once
    JWT_CLOCK_SKEW_LEEWAY_SECONDS is raised to cover it."""
    monkeypatch.setenv("JWT_CLOCK_SKEW_LEEWAY_SECONDS", "30")
    token_reader = _make_token_reader(key=rsa_key)
    token = _make_token(key=rsa_key, iat_offset_seconds=20)

    result = await token_reader.verify_token_async(token=token)

    assert result is not None
