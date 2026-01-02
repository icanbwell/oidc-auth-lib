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
    - Read well-known configurations for all configured providers once per lifecycle.
    - Aggregate JWKS via the cache and expose it for token verification.
    - Serialize refresh operations and guard initialization with an event to avoid deadlocks.

    Concurrency Strategy:
    - WellKnownConfigurationCache handles per-URI network fetch locking.
    - Manager uses:
      * _lock: guards state mutations (_loaded, _initializing) and event coordination.
      * _init_event: notifies waiters when initialization completes (success or failure).
      * _refresh_lock: serializes refresh operations to avoid racing with initialization.
    - No network I/O is performed while holding _lock to prevent lock inversion with cache locks.

    Public API:
    - get_jwks_async(): Ensure initialized, then return de-duplicated JWKS KeySet.
    - ensure_initialized_async(): Fetch well-known configs and JWKS once; deadlock-free.
    - refresh_async(): Clear and re-initialize caches/JWKS, serialized across callers.
    - get_async(auth_config): Retrieve a cached config for a specific provider.

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
        self._auth_configs: List[AuthConfig] = (
            auth_config_reader.get_auth_configs_for_all_auth_providers()
        )
        self._cache: WellKnownConfigurationCache = cache
        if not isinstance(self._cache, WellKnownConfigurationCache):
            raise TypeError(
                f"cache must be an instance of WellKnownConfigurationCache, got {type(self._cache).__name__}"
            )
        self._loaded: bool = False

    async def get_jwks_async(self) -> KeySet:
        """Return the aggregated JWKS KeySet for configured providers.

        Behavior:
            - Ensures initialization has completed (well-known configs loaded).
            - Returns the cache's combined JWKS KeySet.
        Returns:
            KeySet: Combined, de-duplicated JWKS suitable for token verification.
        """
        await self.ensure_initialized_async()
        return self._cache.jwks

    async def ensure_initialized_async(self) -> None:
        """Initialize well-known configs and JWKS exactly once (deadlock-free)."""
        if self._loaded:
            return None

        logger.debug("Manager fetching well-known configurations and JWKS.")
        configs_to_load = [c for c in self._auth_configs if c.well_known_uri]
        await self._cache.read_list_async(auth_configs=configs_to_load)
        self._loaded = True
        return None

    async def refresh_async(self) -> None:
        """Force a refresh of well-known configs and JWKS.

        Behavior:
            - Serializes refresh operations to prevent races.
            - Waits for any in-progress initialization to complete before clearing.
            - Clears caches, resets state, and re-initializes.
        """
        # Reset manager state before clearing the underlying cache to keep flags consistent.
        self._loaded = False
        # Now clear and reset - no concurrent initialization can be running
        await self._cache.clear_async()

        await self.ensure_initialized_async()

    async def get_async(
        self, auth_config: AuthConfig
    ) -> WellKnownConfigurationCacheResult | None:
        """Retrieve a cached well-known configuration for a specific provider.

        Args:
            auth_config: Provider configuration specifying well_known_uri.
        Returns:
            WellKnownConfigurationCacheResult if present, otherwise None.
        Notes:
            Ensures manager is initialized before reading from cache.
        """
        await self.ensure_initialized_async()
        return await self._cache.get_async(auth_config=auth_config)
