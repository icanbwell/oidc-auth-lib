import pytest
from typing import Any, override
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from tests.auth.minimal_env import MinimalEnv
import respx
from httpx import Response
import jwt  # pyjwt
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64


def to_b64url(val: int) -> str:
    # Helper to convert int to base64url-encoded string
    b = val.to_bytes((val.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def generate_rsa_key_and_jwk(kid: str) -> tuple[bytes, dict[str, Any]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": to_b64url(public_numbers.n),
        "e": to_b64url(public_numbers.e),
    }
    return private_bytes, jwk


def create_jwt_pyjwt(private_bytes: bytes, kid: str, claims: dict[str, Any]) -> str:
    return jwt.encode(claims, private_bytes, algorithm="RS256", headers={"kid": kid})


class MyAuthConfigReader(AuthConfigReader):
    def __init__(
        self, environment_variables: MinimalEnv, auth_configs: list[AuthConfig]
    ) -> None:
        super().__init__(environment_variables=environment_variables)
        self._auth_configs = auth_configs

    @override
    async def get_auth_configs_for_all_auth_providers(self) -> list[AuthConfig]:
        return self._auth_configs


@pytest.mark.asyncio
@respx.mock
async def test_token_reader_multiple_well_known_urls() -> None:
    kid1 = "key1"
    kid2 = "key2"
    _, jwk1 = generate_rsa_key_and_jwk(kid1)
    priv2, jwk2 = generate_rsa_key_and_jwk(kid2)
    jwks1 = {"keys": [jwk1]}
    jwks2 = {"keys": [jwk2]}
    claims = {
        "sub": "user2",
        "iss": "https://issuer2",
        "aud": "client2",
        "exp": int(time.time()) + 3600,
    }
    token = create_jwt_pyjwt(priv2, kid2, claims)

    auth_configs = [
        AuthConfig(
            auth_provider="provider1",
            audience="client1",
            well_known_uri="https://provider1/.well-known/openid-configuration",
        ),
        AuthConfig(
            auth_provider="provider2",
            audience="client2",
            well_known_uri="https://provider2/.well-known/openid-configuration",
        ),
    ]
    env = MinimalEnv(
        auth_providers=["provider1", "provider2"],
        configs={
            "provider1": auth_configs[0],
            "provider2": auth_configs[1],
        },
    )
    auth_config_reader = MyAuthConfigReader(
        environment_variables=env, auth_configs=auth_configs
    )

    respx.get("https://provider1/.well-known/openid-configuration").mock(
        return_value=Response(
            200,
            json={"jwks_uri": "https://provider1/jwks", "issuer": "https://issuer1"},
        )
    )
    respx.get("https://provider2/.well-known/openid-configuration").mock(
        return_value=Response(
            200,
            json={"jwks_uri": "https://provider2/jwks", "issuer": "https://issuer2"},
        )
    )
    respx.get("https://provider1/jwks").mock(return_value=Response(200, json=jwks1))
    respx.get("https://provider2/jwks").mock(return_value=Response(200, json=jwks2))

    token_reader = TokenReader(
        algorithms=["RS256"], auth_config_reader=auth_config_reader
    )
    result = await token_reader.verify_token_async(token=token)
    assert result is not None
    if result.claims is not None:
        assert result.claims["sub"] == "user2"
        assert result.claims["iss"] == "https://issuer2"
        assert result.claims["aud"] == "client2"
    else:
        assert False, "result.claims is None"
