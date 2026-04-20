import logging
from typing import Any

import httpx

from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS
from oidcauthlib.utilities.url_validator import validate_url

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


_DEFAULT_TIMEOUT_SECONDS: int = 10


class DcrClient:
    """RFC 7591 Dynamic Client Registration HTTP client."""

    def __init__(self, *, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS) -> None:
        self._timeout_seconds = timeout_seconds

    async def register(
        self,
        *,
        registration_url: str,
        redirect_uri: str,
        client_name: str | None = None,
        client_uri: str | None = None,
        logo_uri: str | None = None,
        contacts: list[str] | None = None,
    ) -> dict[str, Any]:
        validate_url(registration_url)

        payload: dict[str, Any] = {
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
        if client_name:
            payload["client_name"] = client_name
        if client_uri:
            payload["client_uri"] = client_uri
        if logo_uri:
            payload["logo_uri"] = logo_uri
        if contacts:
            payload["contacts"] = contacts

        logger.info(
            "DCR: Sending registration request to '%s' with payload keys: %s",
            registration_url,
            sorted(payload.keys()),
        )
        logger.debug(
            "DCR: Full registration payload for '%s': %s",
            registration_url,
            payload,
        )

        async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
            response = await client.post(
                registration_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                logger.error(
                    "DCR: Registration failed at '%s' — HTTP %s. Response body: %s",
                    registration_url,
                    e.response.status_code,
                    e.response.text[:500],
                )
                raise ValueError(
                    f"DCR registration failed at '{registration_url}' with status {e.response.status_code}"
                ) from e
            dcr_response: dict[str, Any] = response.json()

        if "client_id" not in dcr_response:
            response_keys: list[str] = sorted(dcr_response.keys())
            logger.error(
                "DCR: Response from '%s' missing 'client_id'. Keys present: %s",
                registration_url,
                response_keys,
            )
            raise ValueError(
                f"DCR response from '{registration_url}' missing 'client_id'. Response keys: {response_keys}"
            )

        logger.info(
            "DCR: Registration successful at '%s' — client_id=%s, has_secret=%s, expires_at=%s",
            registration_url,
            dcr_response["client_id"],
            "client_secret" in dcr_response,
            dcr_response.get("client_secret_expires_at", "not_set"),
        )
        logger.debug(
            "DCR: Full response from '%s': %s",
            registration_url,
            {k: v for k, v in dcr_response.items() if k != "client_secret"},
        )
        return dcr_response
