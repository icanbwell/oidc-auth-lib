"""
Audience matching in TokenReader.verify_token_async.

RFC 7519 4.1.3 allows the `aud` claim to be either a single string or an array of
strings. These tests cover both shapes, plus the AWS Cognito case where `client_id`
stands in for a missing `aud`, and the negative cases that must keep failing.
"""

from typing import Any, Dict, List, Optional

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, OctKey

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.exceptions.authorization_bearer_token_invalid_exception import (
    AuthorizationBearerTokenInvalidException,
)
from oidcauthlib.auth.token_reader import TokenReader

KID = "audience-test-kid"
ISSUER = "https://auth.dev.example.com/v1/apps/agentic/PROJECT/SERVER"
RESOURCE = "https://api.dev.example.com/mcp"
PROJECT_ID = "PROJECT"
DCR_CLIENT_ID = "dcr-client-id"
COGNITO_CLIENT_ID = "cognito-client-id"

_KEY = OctKey.import_key("audience-test-secret-key-material", {"kid": KID})
_JWKS = KeySet([_KEY])


def _token(*, claims: Dict[str, Any]) -> str:
    """Sign a token with the shared test key.

    `iat` is included because Token.create_from_dict requires exp, iat and iss and
    returns None without them - so a token missing it verifies fine but yields no
    Token, which would make the positive assertions below vacuous.
    """
    payload: Dict[str, Any] = {"exp": 9999999999, "iat": 1000000000, **claims}
    return jwt.encode({"alg": "HS256", "kid": KID}, payload, _KEY)


class _FakeWellKnownConfigurationManager:
    """Serves the static test JWKS; TokenReader only needs these three methods."""

    async def get_jwks_async(self) -> KeySet:
        return _JWKS

    async def get_well_known_urls(self) -> List[str]:
        return ["https://auth.dev.example.com/.well-known/openid-configuration"]

    async def refresh_async(self) -> None:
        return None


class _TestTokenReader(TokenReader):
    """TokenReader with dependencies injected directly, bypassing __init__."""

    # noinspection PyMissingConstructor
    def __init__(self, *, auth_configs: List[AuthConfig]) -> None:
        self.algorithms = ["HS256"]
        self.auth_configs = auth_configs
        self._well_known_config_manager = _FakeWellKnownConfigurationManager()  # type: ignore[assignment]


def _auth_config(
    *,
    provider: str,
    audience: str,
    issuer: Optional[str],
    client_id: Optional[str] = "configured-client-id",
) -> AuthConfig:
    return AuthConfig(
        auth_provider=provider,
        friendly_name=provider,
        audience=audience,
        issuer=issuer,
        client_id=client_id,
        scope="openid",
    )


# Mirrors a real deployment: an Inbound App provider keyed on the bare project id,
# plus an agentic MCP provider keyed on the resource identifier.
def _reader() -> _TestTokenReader:
    return _TestTokenReader(
        auth_configs=[
            _auth_config(
                provider="descope_oidc",
                audience=PROJECT_ID,
                issuer="https://api.descope.com/v1/apps/PROJECT",
            ),
            _auth_config(provider="descope_mcp", audience=RESOURCE, issuer=ISSUER),
        ]
    )


class TestArrayAudience:
    """`aud` as an array of strings."""

    @pytest.mark.asyncio
    async def test_accepts_array_containing_the_configured_audience(self) -> None:
        # The shape Descope mints for an Agentic MCP Server: the DCR client id, the
        # bare project id, and the MCP Server URL. Comparing this list to a string
        # with == is never true, so before membership matching it matched no provider.
        token = _token(claims={"iss": ISSUER, "aud": [DCR_CLIENT_ID, PROJECT_ID, RESOURCE]})

        result = await _reader().verify_token_async(token=token)

        assert result is not None

    @pytest.mark.asyncio
    async def test_accepts_single_element_array(self) -> None:
        token = _token(claims={"iss": ISSUER, "aud": [RESOURCE]})

        result = await _reader().verify_token_async(token=token)

        assert result is not None

    @pytest.mark.asyncio
    async def test_rejects_array_without_a_configured_audience(self) -> None:
        token = _token(claims={"iss": ISSUER, "aud": ["someone-else", "another-audience"]})

        with pytest.raises(AuthorizationBearerTokenInvalidException):
            await _reader().verify_token_async(token=token)

    @pytest.mark.asyncio
    async def test_rejects_matching_audience_with_wrong_issuer(self) -> None:
        # Audience membership must not be enough on its own: the issuer is what
        # separates the agentic provider from the Inbound App provider.
        token = _token(
            claims={
                "iss": "https://attacker.example.com/",
                "aud": [DCR_CLIENT_ID, PROJECT_ID, RESOURCE],
            }
        )

        with pytest.raises(AuthorizationBearerTokenInvalidException):
            await _reader().verify_token_async(token=token)


class TestScalarAudience:
    """`aud` as a single string, and the Cognito `client_id` fallback."""

    @pytest.mark.asyncio
    async def test_accepts_scalar_audience(self) -> None:
        token = _token(claims={"iss": ISSUER, "aud": RESOURCE})

        result = await _reader().verify_token_async(token=token)

        assert result is not None

    @pytest.mark.asyncio
    async def test_rejects_scalar_audience_that_does_not_match(self) -> None:
        token = _token(claims={"iss": ISSUER, "aud": "someone-else"})

        with pytest.raises(AuthorizationBearerTokenInvalidException):
            await _reader().verify_token_async(token=token)

    @pytest.mark.asyncio
    async def test_falls_back_to_client_id_when_aud_is_absent(self) -> None:
        # AWS Cognito access tokens carry no `aud`; client_id stands in for it.
        reader = _TestTokenReader(
            auth_configs=[
                _auth_config(
                    provider="apigateway",
                    audience=COGNITO_CLIENT_ID,
                    issuer=ISSUER,
                )
            ]
        )
        token = _token(claims={"iss": ISSUER, "client_id": COGNITO_CLIENT_ID})

        result = await reader.verify_token_async(token=token)

        assert result is not None

    @pytest.mark.asyncio
    async def test_rejects_token_with_neither_aud_nor_client_id(self) -> None:
        token = _token(claims={"iss": ISSUER})

        with pytest.raises(AuthorizationBearerTokenInvalidException):
            await _reader().verify_token_async(token=token)
