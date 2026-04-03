import logging
from typing import Any

import httpx

from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class DcrClient:
    """RFC 7591 Dynamic Client Registration HTTP client."""

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

        logger.info("Performing DCR at '%s'", registration_url)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                registration_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            dcr_response: dict[str, Any] = response.json()

        if "client_id" not in dcr_response:
            response_keys: list[str] = sorted(dcr_response.keys())
            raise ValueError(
                f"DCR response from '{registration_url}' missing 'client_id'. "
                f"Response keys: {response_keys}"
            )

        logger.info(
            "DCR successful at '%s': client_id=%s",
            registration_url,
            dcr_response["client_id"],
        )
        return dcr_response
