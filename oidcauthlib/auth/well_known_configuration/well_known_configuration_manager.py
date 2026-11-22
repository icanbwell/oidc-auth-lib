import logging
from typing import List

from joserfc.jwk import KeySet

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache_result import (
    WellKnownConfigurationCacheResult,
)
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class WellKnownConfigurationManager:
    """Coordinates retrieval and caching of OIDC well-known configurations and JWKS.

    Purpose:
    - Centralize initialization and refresh of discovery documents and JWKS.
    - Provide a safe, deadlock-free orchestration layer over WellKnownConfigurationCache under high concurrency.

    Responsibilities:
    - Read well-known configurations for all configured providers from the shared store.
    - Assemble the JWKS per call via the cache and expose it for token verification.
    - Trigger a rate-limited refetch when a token's kid is unknown.

    This class holds no discovery or JWKS data and has no "loaded" flag; it is a thin,
    stateless coordinator over WellKnownConfigurationCache.

    Public API:
    - get_jwks_async(): Return a freshly assembled JWKS KeySet.
    - ensure_initialized_async(): Read (and fetch if missing) every provider's config.
    - refresh_async(): Rate-limited refetch for an unknown kid.
    - get_async(auth_config): Read-through for a specific provider.

    Notes:
    - OpenTelemetry spans use enums from oidcauthlib.open_telemetry.span_names.
    - Logging avoids printing sensitive tokens or PII; only statuses and counts.
    """

    def __init__(
        self,
        *,
        auth_config_reader: AuthConfigReader,
        cache: WellKnownConfigurationCache,
    ) -> None:
        self._auth_configs: List[AuthConfig] = auth_config_reader.get_auth_configs_for_all_auth_providers()
        self._cache: WellKnownConfigurationCache = cache
        if not isinstance(self._cache, WellKnownConfigurationCache):
            raise TypeError(
                f"cache must be an instance of WellKnownConfigurationCache, got {type(self._cache).__name__}"
            )

    def _configs_with_well_known_uri(self) -> List[AuthConfig]:
        return [c for c in self._auth_configs if c.well_known_uri]

    def _configs_for_issuer(self, *, issuer: str | None) -> List[AuthConfig]:
        """Providers that could have issued a token claiming ``issuer``.

        This only chooses which provider rows to READ; it is never the validation decision.
        Providers with a configured issuer are included only on an exact match (the same rule
        TokenReader applies afterwards); providers without a configured issuer are always
        included; an unreadable issuer (None) selects every provider.
        """
        configs = self._configs_with_well_known_uri()
        if issuer is None:
            return configs
        return [c for c in configs if c.issuer is None or c.issuer == issuer]

    async def get_jwks_for_issuer_async(self, *, issuer: str | None) -> KeySet:
        """Like get_jwks_async but reads only the providers that could match ``issuer``.

        ``issuer`` comes from the token's UNVERIFIED claims and only narrows the keys offered
        to signature verification (a subset of get_jwks_async's keys), so it can make
        validation stricter but never more permissive.
        """
        return await self._cache.get_jwks_async(auth_configs=self._configs_for_issuer(issuer=issuer))

    async def refresh_for_issuer_async(self, *, issuer: str | None) -> None:
        """Like refresh_async but refetches only the providers that could match ``issuer``."""
        await self._cache.refresh_async(auth_configs=self._configs_for_issuer(issuer=issuer))

    async def get_jwks_async(self) -> KeySet:
        """Return a freshly assembled JWKS KeySet for configured providers.

        Every call reads the backing store (and fetches from the issuer on a miss or
        expired row). Nothing is held in this process between calls.
        """
        return await self._cache.get_jwks_async(auth_configs=self._configs_with_well_known_uri())

    async def ensure_initialized_async(self) -> None:
        """Read (fetching if missing or expired) every provider's configuration.

        Not a once-per-process flag: it consults the shared store each time.
        """
        logger.debug("Manager reading well-known configurations and JWKS from the store.")
        await self._cache.read_list_async(auth_configs=self._configs_with_well_known_uri())
        return None

    async def refresh_async(self) -> None:
        """Refetch the issuers because a token presented an unknown kid.

        Rate limited (shared across pods) by the cache; when limited this is a no-op and
        the caller's validation fails closed against the stored keys.
        """
        await self._cache.refresh_async(auth_configs=self._configs_with_well_known_uri())

    async def get_async(self, auth_config: AuthConfig) -> WellKnownConfigurationCacheResult | None:
        """Retrieve the well-known configuration for a specific provider (read-through).

        Args:
            auth_config: Provider configuration specifying well_known_uri.
        Returns:
            WellKnownConfigurationCacheResult, or None if the provider has no well_known_uri.
        """
        return await self._cache.get_async(auth_config=auth_config)

    async def get_well_known_urls(self) -> List[str]:
        """Return a list of well-known URLs for all configured providers."""
        return [c.well_known_uri for c in self._auth_configs if c.well_known_uri]
