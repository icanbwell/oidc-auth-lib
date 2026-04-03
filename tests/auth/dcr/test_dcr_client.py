from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from oidcauthlib.auth.dcr.dcr_client import DcrClient


class TestDcrClient:
    async def test_register_sends_correct_payload(self) -> None:
        client = DcrClient()
        dcr_response = {
            "client_id": "new-id",
            "client_secret": "new-secret",
            "client_secret_expires_at": 0,
        }
        with patch("oidcauthlib.auth.dcr.dcr_client.httpx.AsyncClient") as mock_httpx:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = dcr_response
            mock_response.raise_for_status = MagicMock()
            mock_client_instance = AsyncMock()
            mock_client_instance.post = AsyncMock(return_value=mock_response)
            mock_client_instance.__aenter__ = AsyncMock(
                return_value=mock_client_instance
            )
            mock_client_instance.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.return_value = mock_client_instance

            result = await client.register(
                registration_url="https://auth.example.com/register",
                redirect_uri="http://localhost:5050/auth/callback",
                client_name="My Client",
                client_uri="https://myapp.com",
                logo_uri="https://myapp.com/logo.png",
                contacts=["admin@myapp.com"],
            )

        assert result["client_id"] == "new-id"
        assert result["client_secret"] == "new-secret"

        call_kwargs = mock_client_instance.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["redirect_uris"] == ["http://localhost:5050/auth/callback"]
        assert payload["grant_types"] == ["authorization_code", "refresh_token"]
        assert payload["response_types"] == ["code"]
        assert payload["token_endpoint_auth_method"] == "none"
        assert payload["client_name"] == "My Client"
        assert payload["client_uri"] == "https://myapp.com"

    async def test_register_without_optional_metadata(self) -> None:
        client = DcrClient()
        dcr_response = {"client_id": "new-id", "client_secret_expires_at": 0}
        with patch("oidcauthlib.auth.dcr.dcr_client.httpx.AsyncClient") as mock_httpx:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = dcr_response
            mock_response.raise_for_status = MagicMock()
            mock_client_instance = AsyncMock()
            mock_client_instance.post = AsyncMock(return_value=mock_response)
            mock_client_instance.__aenter__ = AsyncMock(
                return_value=mock_client_instance
            )
            mock_client_instance.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.return_value = mock_client_instance

            result = await client.register(
                registration_url="https://auth.example.com/register",
                redirect_uri="http://localhost:5050/auth/callback",
            )

        assert result["client_id"] == "new-id"
        payload = mock_client_instance.post.call_args.kwargs.get("json")
        assert "client_name" not in payload

    async def test_register_raises_on_missing_client_id(self) -> None:
        client = DcrClient()
        with patch("oidcauthlib.auth.dcr.dcr_client.httpx.AsyncClient") as mock_httpx:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"no_client_id": True}
            mock_response.raise_for_status = MagicMock()
            mock_client_instance = AsyncMock()
            mock_client_instance.post = AsyncMock(return_value=mock_response)
            mock_client_instance.__aenter__ = AsyncMock(
                return_value=mock_client_instance
            )
            mock_client_instance.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.return_value = mock_client_instance

            with pytest.raises(ValueError, match="missing 'client_id'"):
                await client.register(
                    registration_url="https://auth.example.com/register",
                    redirect_uri="http://localhost:5050/auth/callback",
                )
