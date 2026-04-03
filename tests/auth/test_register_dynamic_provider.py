from typing import Any, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import pytest
from simple_container.container.interfaces import IContainer

from oidcauthlib.auth.auth_manager import AuthManager
from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.dcr.dcr_registration import DcrRegistration

pytestmark = pytest.mark.asyncio


@pytest.fixture(scope="function")
async def test_container() -> AsyncGenerator[None, None]:
    """Override parent conftest fixture to skip DI container setup."""
    yield None


@pytest.fixture(scope="function", autouse=True)
async def initialize_caches(test_container: IContainer) -> AsyncGenerator[None, None]:
    """Override parent conftest autouse fixture to skip MongoDB setup."""
    yield


def _mock_register(manager: AuthManager) -> Any:
    """Return the mock register callable with proper typing for test assertions."""
    return manager._oauth.register


def _make_auth_manager(*, dcr_manager: Any = None) -> AuthManager:
    """Create AuthManager with mocked dependencies."""
    manager = object.__new__(AuthManager)
    manager.environment_variables = MagicMock()
    manager.auth_config_reader = MagicMock()
    manager.auth_config_reader.get_auth_configs_for_all_auth_providers.return_value = []
    manager.auth_configs = []
    manager.token_reader = MagicMock()
    manager.well_known_configuration_manager = MagicMock()
    manager.well_known_configuration_manager.get_async = AsyncMock(return_value=None)
    manager.cache = MagicMock()
    manager.redirect_uri = "http://localhost:5050/auth/callback"
    manager._oauth = MagicMock()
    manager._oauth.register = MagicMock()
    manager._registered_dynamic_providers = set()
    manager._dcr_manager = dcr_manager
    return manager


class TestRegisterDynamicProviderExplicitEndpoints:
    async def test_registers_with_explicit_endpoints(self) -> None:
        manager = _make_auth_manager()
        config = AuthConfig(
            auth_provider="test-provider",
            friendly_name="Test",
            audience="test-audience",
            client_id="test-client",
            scope="openid",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        await manager.register_dynamic_provider(auth_config=config)
        mock_register = _mock_register(manager)
        mock_register.assert_called_once()
        call_kwargs = mock_register.call_args[1]
        assert call_kwargs["name"] == "test-provider"
        assert call_kwargs["client_id"] == "test-client"
        assert call_kwargs["authorize_url"] == "https://auth.example.com/authorize"
        assert call_kwargs["access_token_url"] == "https://auth.example.com/token"
        assert "server_metadata_url" not in call_kwargs


class TestRegisterDynamicProviderDiscovery:
    async def test_registers_with_discovery(self) -> None:
        manager = _make_auth_manager()
        config = AuthConfig(
            auth_provider="test-provider",
            friendly_name="Test",
            audience="test-audience",
            client_id="test-client",
            scope="openid",
            well_known_uri="https://idp.example.com/.well-known/openid-configuration",
        )
        await manager.register_dynamic_provider(auth_config=config)
        call_kwargs = _mock_register(manager).call_args[1]
        assert (
            call_kwargs["server_metadata_url"]
            == "https://idp.example.com/.well-known/openid-configuration"
        )
        assert "authorize_url" not in call_kwargs
        assert "access_token_url" not in call_kwargs


class TestRegisterDynamicProviderPKCE:
    async def test_pkce_s256(self) -> None:
        manager = _make_auth_manager()
        config = AuthConfig(
            auth_provider="test",
            friendly_name="Test",
            audience="aud",
            client_id="cid",
            scope="openid",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            use_pkce=True,
            pkce_method="S256",
        )
        await manager.register_dynamic_provider(auth_config=config)
        call_kwargs = _mock_register(manager).call_args[1]
        assert call_kwargs["client_kwargs"]["code_challenge_method"] == "S256"

    async def test_pkce_plain(self) -> None:
        manager = _make_auth_manager()
        config = AuthConfig(
            auth_provider="test",
            friendly_name="Test",
            audience="aud",
            client_id="cid",
            scope="openid",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            use_pkce=True,
            pkce_method="plain",
        )
        await manager.register_dynamic_provider(auth_config=config)
        call_kwargs = _mock_register(manager).call_args[1]
        assert call_kwargs["client_kwargs"]["code_challenge_method"] == "plain"

    async def test_pkce_disabled(self) -> None:
        manager = _make_auth_manager()
        config = AuthConfig(
            auth_provider="test",
            friendly_name="Test",
            audience="aud",
            client_id="cid",
            scope="openid",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            use_pkce=False,
        )
        await manager.register_dynamic_provider(auth_config=config)
        call_kwargs = _mock_register(manager).call_args[1]
        assert "code_challenge_method" not in call_kwargs["client_kwargs"]


class TestRegisterDynamicProviderDeduplication:
    async def test_does_not_register_twice(self) -> None:
        manager = _make_auth_manager()
        config = AuthConfig(
            auth_provider="test",
            friendly_name="Test",
            audience="aud",
            client_id="cid",
            scope="openid",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        await manager.register_dynamic_provider(auth_config=config)
        await manager.register_dynamic_provider(auth_config=config)
        assert _mock_register(manager).call_count == 1

    async def test_adds_to_auth_configs(self) -> None:
        manager = _make_auth_manager()
        config = AuthConfig(
            auth_provider="test",
            friendly_name="Test",
            audience="aud",
            client_id="cid",
            scope="openid",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        await manager.register_dynamic_provider(auth_config=config)
        assert config in manager.auth_configs


class TestEnsureInitializedDelegatesToRegisterDynamic:
    async def test_explicit_endpoints_skip_well_known(self) -> None:
        """ensure_initialized_async should not call well_known_manager for explicit-endpoint configs."""
        manager = _make_auth_manager()
        config = AuthConfig(
            auth_provider="explicit",
            friendly_name="Explicit",
            audience="aud",
            client_id="cid",
            scope="openid",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        manager.auth_configs = [config]

        await manager.ensure_initialized_async()

        manager.well_known_configuration_manager.get_async.assert_not_called()  # type: ignore[attr-defined]
        call_kwargs = _mock_register(manager).call_args[1]
        assert call_kwargs["authorize_url"] == "https://auth.example.com/authorize"
        assert call_kwargs["access_token_url"] == "https://auth.example.com/token"
        assert "server_metadata_url" not in call_kwargs

    async def test_well_known_config_calls_manager(self) -> None:
        """ensure_initialized_async should call well_known_manager for discovery configs."""
        manager = _make_auth_manager()
        config = AuthConfig(
            auth_provider="discovery",
            friendly_name="Discovery",
            audience="aud",
            client_id="cid",
            scope="openid",
            well_known_uri="https://idp.example.com/.well-known/openid-configuration",
        )
        manager.auth_configs = [config]

        await manager.ensure_initialized_async()

        manager.well_known_configuration_manager.get_async.assert_called_once_with(  # type: ignore[attr-defined]
            auth_config=config
        )
        call_kwargs = _mock_register(manager).call_args[1]
        assert call_kwargs["server_metadata_url"] == config.well_known_uri

    async def test_deduplication_across_ensure_and_register(self) -> None:
        """Providers registered via ensure_initialized should not be re-registered by register_dynamic_provider."""
        manager = _make_auth_manager()
        config = AuthConfig(
            auth_provider="test",
            friendly_name="Test",
            audience="aud",
            client_id="cid",
            scope="openid",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        manager.auth_configs = [config]

        await manager.ensure_initialized_async()
        await manager.register_dynamic_provider(auth_config=config)

        assert _mock_register(manager).call_count == 1

    async def test_mixed_configs(self) -> None:
        """ensure_initialized_async handles a mix of discovery and explicit-endpoint configs."""
        manager = _make_auth_manager()
        discovery_config = AuthConfig(
            auth_provider="discovery",
            friendly_name="Discovery",
            audience="aud",
            client_id="cid1",
            scope="openid",
            well_known_uri="https://idp.example.com/.well-known/openid-configuration",
        )
        explicit_config = AuthConfig(
            auth_provider="explicit",
            friendly_name="Explicit",
            audience="aud",
            client_id="cid2",
            scope="openid",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        manager.auth_configs = [discovery_config, explicit_config]

        await manager.ensure_initialized_async()

        assert _mock_register(manager).call_count == 2
        manager.well_known_configuration_manager.get_async.assert_called_once_with(  # type: ignore[attr-defined]
            auth_config=discovery_config
        )


class TestRegisterDynamicProviderDCR:
    """Tests for the DCR integration in register_dynamic_provider."""

    async def test_dcr_resolves_client_id_when_missing(self) -> None:
        """When client_id is None and DcrManager is provided, DCR should be called."""
        from datetime import UTC, datetime

        from bson import ObjectId

        dcr_result = DcrRegistration(
            _id=ObjectId(),
            created=datetime.now(UTC),
            auth_provider="dcr-provider",
            registration_url="https://auth.example.com/register",
            client_id="dcr-resolved-id",
            client_secret="dcr-resolved-secret",  # pragma: allowlist secret
            client_secret_expires_at=0,
            registration_response={},
        )
        mock_dcr_manager = MagicMock()
        mock_dcr_manager.resolve_dcr_credentials = AsyncMock(return_value=dcr_result)

        manager = _make_auth_manager(dcr_manager=mock_dcr_manager)
        config = AuthConfig(
            auth_provider="dcr-provider",
            friendly_name="DCR Provider",
            audience="aud",
            scope="openid",
            registration_url="https://auth.example.com/register",
            well_known_uri="https://idp.example.com/.well-known/openid-configuration",
        )

        await manager.register_dynamic_provider(auth_config=config)

        mock_dcr_manager.resolve_dcr_credentials.assert_called_once_with(
            auth_provider="dcr-provider",
            registration_url="https://auth.example.com/register",
        )
        call_kwargs = _mock_register(manager).call_args[1]
        assert call_kwargs["client_id"] == "dcr-resolved-id"
        assert (
            call_kwargs["client_secret"] == "dcr-resolved-secret"
        )  # pragma: allowlist secret

    async def test_dcr_raises_when_no_dcr_manager(self) -> None:
        """When client_id is None and no DcrManager, should raise ValueError."""
        manager = _make_auth_manager(dcr_manager=None)
        config = AuthConfig(
            auth_provider="no-dcr",
            friendly_name="No DCR",
            audience="aud",
            scope="openid",
            registration_url="https://auth.example.com/register",
            well_known_uri="https://idp.example.com/.well-known/openid-configuration",
        )

        with pytest.raises(ValueError, match="no DcrManager is configured"):
            await manager.register_dynamic_provider(auth_config=config)

    async def test_dcr_not_called_when_client_id_present(self) -> None:
        """When client_id is provided, DCR should not be invoked."""
        mock_dcr_manager = MagicMock()
        mock_dcr_manager.resolve_dcr_credentials = AsyncMock()

        manager = _make_auth_manager(dcr_manager=mock_dcr_manager)
        config = AuthConfig(
            auth_provider="pre-registered",
            friendly_name="Pre-registered",
            audience="aud",
            client_id="existing-id",
            scope="openid",
            well_known_uri="https://idp.example.com/.well-known/openid-configuration",
        )

        await manager.register_dynamic_provider(auth_config=config)

        mock_dcr_manager.resolve_dcr_credentials.assert_not_called()
        call_kwargs = _mock_register(manager).call_args[1]
        assert call_kwargs["client_id"] == "existing-id"
