"""
Tests for TokenReader with multiple OAuth providers.
Specifically tests the fix for the enumeration bug where tokens from one provider
could be incorrectly validated when multiple providers are configured.
"""
import pytest
from unittest.mock import patch, MagicMock
from typing import List
from joserfc.jwk import KeySet
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.exceptions.authorization_bearer_token_invalid_exception import (
    AuthorizationBearerTokenInvalidException,
)
from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)


class MockEnvironmentVariables(AbstractEnvironmentVariables):
    """Mock environment variables for testing"""

    def __init__(self, providers: List[str]) -> None:
        self._providers = providers

    @property
    def auth_providers(self) -> List[str]:
        return self._providers

    @property
    def oauth_cache(self) -> str:
        return "memory"

    @property
    def mongo_uri(self) -> str | None:
        return None

    @property
    def mongo_db_name(self) -> str | None:
        return None

    @property
    def mongo_db_username(self) -> str | None:
        return None

    @property
    def mongo_db_password(self) -> str | None:
        return None

    @property
    def mongo_db_auth_cache_collection_name(self) -> str | None:
        return None

    @property
    def mongo_db_cache_disable_delete(self) -> bool | None:
        return None

    @property
    def oauth_referring_email(self) -> str | None:
        return None

    @property
    def oauth_referring_subject(self) -> str | None:
        return None

    @property
    def auth_redirect_uri(self) -> str | None:
        return None


def mock_fetch_jwks_for_token_reader(token_reader: TokenReader):
    """Helper to mock JWKS fetching for a token reader"""
    async def mock_fetch_jwks() -> None:
        # Create a mock KeySet that evaluates as truthy
        mock_keyset = MagicMock(spec=KeySet)
        mock_keyset.keys = []  # Empty keys list
        mock_keyset.__bool__ = lambda self: True  # Make it truthy
        token_reader.jwks = mock_keyset

    return mock_fetch_jwks


@pytest.mark.asyncio
async def test_token_validation_with_wrong_issuer() -> None:
    """
    Test that a token with a valid signature but wrong issuer is rejected.
    This tests the fix for the enumeration bug.
    """
    # Setup two auth configs
    auth_config_1 = AuthConfig(
        auth_provider="PROVIDER1",
        audience="audience1",
        issuer="https://provider1.example.com",
        client_id="client1",
        client_secret="secret1",  # pragma: allowlist secret
        well_known_uri="https://provider1.example.com/.well-known/openid-configuration",
    )
    auth_config_2 = AuthConfig(
        auth_provider="PROVIDER2",
        audience="audience2",
        issuer="https://provider2.example.com",
        client_id="client2",
        client_secret="secret2",  # pragma: allowlist secret
        well_known_uri="https://provider2.example.com/.well-known/openid-configuration",
    )

    # Mock the auth config reader
    env_vars = MockEnvironmentVariables(["PROVIDER1", "PROVIDER2"])
    auth_config_reader = AuthConfigReader(environment_variables=env_vars)

    # Mock get_config_for_auth_provider to return our configs
    with patch.object(
        auth_config_reader,
        "get_config_for_auth_provider",
        side_effect=lambda auth_provider: auth_config_1
        if auth_provider == "PROVIDER1"
        else auth_config_2,
    ):
        # Create token reader
        token_reader = TokenReader(
            auth_config_reader=auth_config_reader, algorithms=["RS256"]
        )

        # Mock fetch_well_known_config_and_jwks_async to bypass network calls
        mock_fetch = mock_fetch_jwks_for_token_reader(token_reader)

        # Mock jwt.decode to return claims with wrong issuer and audience
        with patch.object(
            token_reader, "fetch_well_known_config_and_jwks_async", mock_fetch
        ), patch("oidcauthlib.auth.token_reader.jwt.decode") as mock_decode:
            mock_verified = MagicMock()
            mock_verified.claims = {
                "iss": "https://wrong-issuer.example.com",  # Wrong issuer
                "aud": "wrong-audience",  # Wrong audience
                "exp": 9999999999,  # Far future
                "sub": "test-user",
            }
            mock_decode.return_value = mock_verified

            # Try to verify token - should fail because issuer/audience don't match
            with pytest.raises(AuthorizationBearerTokenInvalidException) as exc_info:
                await token_reader.verify_token_async(token="fake.jwt.token")

            # Check error message mentions issuer/audience mismatch
            assert "do not match any configured auth provider" in str(exc_info.value)


@pytest.mark.asyncio
async def test_token_validation_with_correct_issuer() -> None:
    """
    Test that a token with correct issuer and audience is accepted.
    """
    # Setup auth config
    auth_config = AuthConfig(
        auth_provider="PROVIDER1",
        audience="audience1",
        issuer="https://provider1.example.com",
        client_id="client1",
        client_secret="secret1",  # pragma: allowlist secret
        well_known_uri="https://provider1.example.com/.well-known/openid-configuration",
    )

    # Mock the auth config reader
    env_vars = MockEnvironmentVariables(["PROVIDER1"])
    auth_config_reader = AuthConfigReader(environment_variables=env_vars)

    with patch.object(
        auth_config_reader,
        "get_config_for_auth_provider",
        return_value=auth_config,
    ):
        token_reader = TokenReader(
            auth_config_reader=auth_config_reader, algorithms=["RS256"]
        )

        mock_fetch = mock_fetch_jwks_for_token_reader(token_reader)

        # Mock jwt.decode with correct issuer and audience
        with patch.object(
            token_reader, "fetch_well_known_config_and_jwks_async", mock_fetch
        ), patch("oidcauthlib.auth.token_reader.jwt.decode") as mock_decode, patch(
            "oidcauthlib.auth.token_reader.jwt.JWTClaimsRegistry"
        ) as mock_claims_registry:

            mock_verified = MagicMock()
            mock_verified.claims = {
                "iss": "https://provider1.example.com",  # Correct issuer
                "aud": "audience1",  # Correct audience
                "exp": 9999999999,
                "sub": "test-user",
            }
            mock_decode.return_value = mock_verified

            # Mock claims registry validation
            mock_registry_instance = MagicMock()
            mock_claims_registry.return_value = mock_registry_instance

            # Verify token - should succeed
            token = await token_reader.verify_token_async(token="fake.jwt.token")
            assert token is not None
            assert token.token == "fake.jwt.token"


@pytest.mark.asyncio
async def test_token_validation_matches_audience_not_issuer() -> None:
    """
    Test that a token is accepted if audience matches even if issuer is not configured.
    This handles cases where issuer might not be set in auth config.
    """
    # Setup auth config without issuer
    auth_config = AuthConfig(
        auth_provider="PROVIDER1",
        audience="audience1",
        issuer=None,  # No issuer configured
        client_id="client1",
        client_secret="secret1",  # pragma: allowlist secret
        well_known_uri="https://provider1.example.com/.well-known/openid-configuration",
    )

    env_vars = MockEnvironmentVariables(["PROVIDER1"])
    auth_config_reader = AuthConfigReader(environment_variables=env_vars)

    with patch.object(
        auth_config_reader,
        "get_config_for_auth_provider",
        return_value=auth_config,
    ):
        token_reader = TokenReader(
            auth_config_reader=auth_config_reader, algorithms=["RS256"]
        )

        mock_fetch = mock_fetch_jwks_for_token_reader(token_reader)

        # Mock jwt.decode with any issuer but correct audience
        with patch.object(
            token_reader, "fetch_well_known_config_and_jwks_async", mock_fetch
        ), patch("oidcauthlib.auth.token_reader.jwt.decode") as mock_decode, patch(
            "oidcauthlib.auth.token_reader.jwt.JWTClaimsRegistry"
        ) as mock_claims_registry:

            mock_verified = MagicMock()
            mock_verified.claims = {
                "iss": "https://any-issuer.example.com",
                "aud": "audience1",  # Correct audience
                "exp": 9999999999,
                "sub": "test-user",
            }
            mock_decode.return_value = mock_verified

            mock_registry_instance = MagicMock()
            mock_claims_registry.return_value = mock_registry_instance

            # Verify token - should succeed because audience matches
            token = await token_reader.verify_token_async(token="fake.jwt.token")
            assert token is not None


@pytest.mark.asyncio
async def test_token_validation_with_matching_issuer_only() -> None:
    """
    Test that a token is accepted if issuer matches even if audience is different.
    This handles cases where audience validation is more flexible.
    """
    # Setup auth config
    auth_config = AuthConfig(
        auth_provider="PROVIDER1",
        audience="audience1",
        issuer="https://provider1.example.com",
        client_id="client1",
        client_secret="secret1",  # pragma: allowlist secret
        well_known_uri="https://provider1.example.com/.well-known/openid-configuration",
    )

    env_vars = MockEnvironmentVariables(["PROVIDER1"])
    auth_config_reader = AuthConfigReader(environment_variables=env_vars)

    with patch.object(
        auth_config_reader,
        "get_config_for_auth_provider",
        return_value=auth_config,
    ):
        token_reader = TokenReader(
            auth_config_reader=auth_config_reader, algorithms=["RS256"]
        )

        mock_fetch = mock_fetch_jwks_for_token_reader(token_reader)

        # Mock jwt.decode with correct issuer but different audience
        with patch.object(
            token_reader, "fetch_well_known_config_and_jwks_async", mock_fetch
        ), patch("oidcauthlib.auth.token_reader.jwt.decode") as mock_decode, patch(
            "oidcauthlib.auth.token_reader.jwt.JWTClaimsRegistry"
        ) as mock_claims_registry:

            mock_verified = MagicMock()
            mock_verified.claims = {
                "iss": "https://provider1.example.com",  # Correct issuer
                "aud": "different-audience",  # Different audience
                "exp": 9999999999,
                "sub": "test-user",
            }
            mock_decode.return_value = mock_verified

            mock_registry_instance = MagicMock()
            mock_claims_registry.return_value = mock_registry_instance

            # Verify token - should succeed because issuer matches
            token = await token_reader.verify_token_async(token="fake.jwt.token")
            assert token is not None


@pytest.mark.asyncio
async def test_token_validation_with_multiple_providers_first_matches() -> None:
    """
    Test that when multiple providers are configured, token validation succeeds
    if it matches the first provider.
    """
    auth_config_1 = AuthConfig(
        auth_provider="PROVIDER1",
        audience="audience1",
        issuer="https://provider1.example.com",
        client_id="client1",
        client_secret="secret1",  # pragma: allowlist secret
        well_known_uri="https://provider1.example.com/.well-known/openid-configuration",
    )
    auth_config_2 = AuthConfig(
        auth_provider="PROVIDER2",
        audience="audience2",
        issuer="https://provider2.example.com",
        client_id="client2",
        client_secret="secret2",  # pragma: allowlist secret
        well_known_uri="https://provider2.example.com/.well-known/openid-configuration",
    )

    env_vars = MockEnvironmentVariables(["PROVIDER1", "PROVIDER2"])
    auth_config_reader = AuthConfigReader(environment_variables=env_vars)

    with patch.object(
        auth_config_reader,
        "get_config_for_auth_provider",
        side_effect=lambda auth_provider: auth_config_1
        if auth_provider == "PROVIDER1"
        else auth_config_2,
    ):
        token_reader = TokenReader(
            auth_config_reader=auth_config_reader, algorithms=["RS256"]
        )
        mock_fetch = mock_fetch_jwks_for_token_reader(token_reader)

        # Token from first provider
        with patch.object(
            token_reader, "fetch_well_known_config_and_jwks_async", mock_fetch
        ), patch("oidcauthlib.auth.token_reader.jwt.decode") as mock_decode, patch(
            "oidcauthlib.auth.token_reader.jwt.JWTClaimsRegistry"
        ) as mock_claims_registry:

            mock_verified = MagicMock()
            mock_verified.claims = {
                "iss": "https://provider1.example.com",
                "aud": "audience1",
                "exp": 9999999999,
                "sub": "test-user",
            }
            mock_decode.return_value = mock_verified
            mock_claims_registry.return_value = MagicMock()

            token = await token_reader.verify_token_async(token="fake.jwt.token")
            assert token is not None


@pytest.mark.asyncio
async def test_token_validation_with_multiple_providers_second_matches() -> None:
    """
    Test that when multiple providers are configured, token validation succeeds
    if it matches the second provider. This ensures we're checking ALL providers,
    not just the first one (which was the bug).
    """
    auth_config_1 = AuthConfig(
        auth_provider="PROVIDER1",
        audience="audience1",
        issuer="https://provider1.example.com",
        client_id="client1",
        client_secret="secret1",  # pragma: allowlist secret
        well_known_uri="https://provider1.example.com/.well-known/openid-configuration",
    )
    auth_config_2 = AuthConfig(
        auth_provider="PROVIDER2",
        audience="audience2",
        issuer="https://provider2.example.com",
        client_id="client2",
        client_secret="secret2",  # pragma: allowlist secret
        well_known_uri="https://provider2.example.com/.well-known/openid-configuration",
    )

    env_vars = MockEnvironmentVariables(["PROVIDER1", "PROVIDER2"])
    auth_config_reader = AuthConfigReader(environment_variables=env_vars)

    with patch.object(
        auth_config_reader,
        "get_config_for_auth_provider",
        side_effect=lambda auth_provider: auth_config_1
        if auth_provider == "PROVIDER1"
        else auth_config_2,
    ):
        token_reader = TokenReader(
            auth_config_reader=auth_config_reader, algorithms=["RS256"]
        )
        mock_fetch = mock_fetch_jwks_for_token_reader(token_reader)

        # Token from SECOND provider
        with patch.object(
            token_reader, "fetch_well_known_config_and_jwks_async", mock_fetch
        ), patch("oidcauthlib.auth.token_reader.jwt.decode") as mock_decode, patch(
            "oidcauthlib.auth.token_reader.jwt.JWTClaimsRegistry"
        ) as mock_claims_registry:

            mock_verified = MagicMock()
            mock_verified.claims = {
                "iss": "https://provider2.example.com",  # Second provider
                "aud": "audience2",  # Second provider
                "exp": 9999999999,
                "sub": "test-user",
            }
            mock_decode.return_value = mock_verified
            mock_claims_registry.return_value = MagicMock()

            # This should succeed - the bug would cause this to fail
            token = await token_reader.verify_token_async(token="fake.jwt.token")
            assert token is not None
