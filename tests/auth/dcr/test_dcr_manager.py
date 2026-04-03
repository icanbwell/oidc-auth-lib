import time
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from bson import ObjectId

from oidcauthlib.auth.dcr.dcr_manager import DcrManager
from oidcauthlib.auth.dcr.dcr_registration import DcrRegistration

# All tests patch validate_url because the repository and dcr_client are
# already mocked — no real network calls are made, so DNS resolution of
# test hostnames is irrelevant.
_PATCH_VALIDATE = "oidcauthlib.auth.dcr.dcr_manager.validate_url"


def _make_manager(
    *,
    find_many_return: list[DcrRegistration] | None = None,
) -> DcrManager:
    manager = object.__new__(DcrManager)
    manager._collection_name = "dcr_registrations"
    manager._redirect_uri = "http://localhost:5050/auth/callback"
    manager._repository = AsyncMock()
    manager._repository.find_many = AsyncMock(return_value=find_many_return or [])
    manager._repository.insert_or_update = AsyncMock()
    manager._dcr_client = AsyncMock()
    return manager


class TestPreRegisteredPassthrough:
    async def test_returns_none_when_client_id_provided(self) -> None:
        manager = _make_manager()
        result = await manager.resolve_dcr_credentials(
            auth_provider="test",
            registration_url="https://auth.example.com/register",
            client_id="already-known",
        )
        assert result is None
        manager._repository.find_many.assert_not_called()  # type: ignore[attr-defined]


class TestCachedCredentials:
    @patch(_PATCH_VALIDATE)
    async def test_returns_cached_registration(self, _mock_validate: object) -> None:
        cached = DcrRegistration(
            _id=ObjectId(),
            created=datetime.now(UTC),
            auth_provider="test",
            registration_url="https://auth.example.com/register",
            client_id="cached-id",
            client_secret="cached-secret",
            client_secret_expires_at=0,
            registration_response={},
        )
        manager = _make_manager(find_many_return=[cached])

        result = await manager.resolve_dcr_credentials(
            auth_provider="test",
            registration_url="https://auth.example.com/register",
        )

        assert result is not None
        assert result.client_id == "cached-id"
        assert result.client_secret == "cached-secret"


class TestExpiredCredentials:
    @patch(_PATCH_VALIDATE)
    async def test_re_registers_when_expired(self, _mock_validate: object) -> None:
        expired = DcrRegistration(
            _id=ObjectId(),
            created=datetime.now(UTC),
            auth_provider="test",
            registration_url="https://auth.example.com/register",
            client_id="old-id",
            client_secret="old-secret",
            client_secret_expires_at=int(time.time()) - 3600,
            registration_response={},
        )
        manager = _make_manager(find_many_return=[expired])
        manager._dcr_client.register = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "client_id": "new-id",
                "client_secret": "new-secret",
                "client_secret_expires_at": 0,
            }
        )

        result = await manager.resolve_dcr_credentials(
            auth_provider="test",
            registration_url="https://auth.example.com/register",
            client_name="Test",
        )

        assert result is not None
        assert result.client_id == "new-id"
        manager._repository.insert_or_update.assert_called_once()  # type: ignore[attr-defined]


class TestNewRegistration:
    @patch(_PATCH_VALIDATE)
    async def test_performs_dcr_and_persists(self, _mock_validate: object) -> None:
        manager = _make_manager()
        manager._dcr_client.register = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "client_id": "fresh-id",
                "client_secret": "fresh-secret",
                "client_secret_expires_at": 0,
            }
        )

        result = await manager.resolve_dcr_credentials(
            auth_provider="test",
            registration_url="https://auth.example.com/register",
            client_name="My Client",
            contacts=["admin@test.com"],
        )

        assert result is not None
        assert result.client_id == "fresh-id"
        assert result.client_secret == "fresh-secret"
        manager._dcr_client.register.assert_called_once()
        manager._repository.insert_or_update.assert_called_once()  # type: ignore[attr-defined]


class TestMissingRegistrationUrl:
    async def test_raises_when_no_registration_url_and_no_client_id(self) -> None:
        manager = _make_manager()
        with pytest.raises(ValueError, match="registration_url is required"):
            await manager.resolve_dcr_credentials(
                auth_provider="test",
                registration_url=None,
            )


class TestUrlValidation:
    async def test_validates_url_before_cache_lookup(self) -> None:
        """URL validation must fire before any cache or HTTP work."""
        manager = _make_manager()
        with pytest.raises(ValueError, match="blocked"):
            await manager.resolve_dcr_credentials(
                auth_provider="test",
                registration_url="https://localhost/register",
            )
        # No cache lookup or HTTP call should have been attempted
        manager._repository.find_many.assert_not_called()  # type: ignore[attr-defined]
        manager._dcr_client.register.assert_not_called()  # type: ignore[attr-defined]

    async def test_rejects_private_ip_hostname(self) -> None:
        manager = _make_manager()
        with pytest.raises(ValueError, match="raw IP address"):
            await manager.resolve_dcr_credentials(
                auth_provider="test",
                registration_url="https://10.0.0.1/register",
            )
        manager._repository.find_many.assert_not_called()  # type: ignore[attr-defined]

    async def test_rejects_http_scheme(self) -> None:
        manager = _make_manager()
        with pytest.raises(ValueError, match="scheme must be https"):
            await manager.resolve_dcr_credentials(
                auth_provider="test",
                registration_url="http://auth.example.com/register",
            )
        manager._repository.find_many.assert_not_called()  # type: ignore[attr-defined]
