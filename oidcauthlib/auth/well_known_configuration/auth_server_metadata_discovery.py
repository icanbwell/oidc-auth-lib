import logging
from typing import Protocol, Any
from urllib.parse import urlparse

import httpx

from oidcauthlib.auth.well_known_configuration.auth_server_metadata import (
    AuthServerMetadata,
)
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])

_DISCOVERY_TIMEOUT = httpx.Timeout(10.0)


class AuthServerMetadataDiscoveryProtocol(Protocol):
    """Protocol for discovering OAuth authorization server metadata from a resource URL."""

    async def discover(self, *, resource_url: str) -> AuthServerMetadata | None: ...


class AuthServerMetadataDiscovery:
    """Discovers OAuth authorization server metadata from a resource server URL.

    Implements RFC 8414 (OAuth 2.0 Authorization Server Metadata) with a
    fallback to OpenID Connect Discovery.  Given a resource URL, extracts
    the origin (scheme + host + port) and attempts to fetch:

    1. ``{origin}/.well-known/oauth-authorization-server`` (RFC 8414)
    2. ``{origin}/.well-known/openid-configuration`` (OIDC Discovery)

    Returns an ``AuthServerMetadata`` with the discovered endpoints, or
    ``None`` if neither well-known URL returns valid metadata.
    """

    @staticmethod
    def _extract_base_url(url: str) -> str:
        parsed = urlparse(url)
        port_suffix = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{parsed.hostname}{port_suffix}"

    @staticmethod
    def _parse_metadata(metadata: dict[str, Any]) -> AuthServerMetadata | None:
        authorization_endpoint = metadata.get("authorization_endpoint")
        token_endpoint = metadata.get("token_endpoint")
        if not authorization_endpoint or not token_endpoint:
            logger.warning(
                "Discovered metadata missing required endpoints "
                "(authorization_endpoint=%s, token_endpoint=%s)",
                authorization_endpoint,
                token_endpoint,
            )
            return None

        scopes: list[str] | None = None
        scopes_supported = metadata.get("scopes_supported")
        if isinstance(scopes_supported, list):
            scopes = [s for s in scopes_supported if isinstance(s, str)]

        return AuthServerMetadata(
            authorization_endpoint=authorization_endpoint,
            token_endpoint=token_endpoint,
            registration_endpoint=metadata.get("registration_endpoint"),
            issuer=metadata.get("issuer"),
            scopes_supported=scopes,
        )

    async def discover(self, *, resource_url: str) -> AuthServerMetadata | None:
        """Discover OAuth authorization server metadata for a resource URL.

        Args:
            resource_url: The URL of the resource server (e.g. an MCP server).

        Returns:
            AuthServerMetadata if discovery succeeds, None otherwise.
        """
        base_url = self._extract_base_url(resource_url)

        well_known_urls = [
            f"{base_url}/.well-known/oauth-authorization-server",
            f"{base_url}/.well-known/openid-configuration",
        ]

        async with httpx.AsyncClient(timeout=_DISCOVERY_TIMEOUT) as client:
            for url in well_known_urls:
                try:
                    response = await client.get(url)
                    if response.status_code != 200:
                        logger.debug(
                            "Discovery fetch %s returned status %s, skipping",
                            url,
                            response.status_code,
                        )
                        continue
                    metadata = response.json()
                    result = self._parse_metadata(metadata)
                    if result is not None:
                        logger.info(
                            "Discovered auth server metadata from %s for resource %s",
                            url,
                            resource_url,
                        )
                        return result
                except httpx.TimeoutException:
                    logger.debug("Discovery fetch %s timed out", url)
                except (httpx.HTTPError, ValueError) as e:
                    logger.debug("Discovery fetch %s failed: %s", url, e)

        logger.info("No auth server metadata discovered for resource %s", resource_url)
        return None
