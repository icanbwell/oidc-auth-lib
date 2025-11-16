import asyncio
import logging
from typing import List, Any

from joserfc.jwk import KeySet

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class WellKnownConfigurationManager:
    """Manages retrieval and caching of OIDC well-known configs and JWKS.

    This wraps the previously inlined logic inside TokenReader for fetching
    discovery documents and building a de-duplicated JWKS KeySet under high concurrency.

    Concurrency Strategy:
    - Per-URI locking for well-known discovery handled by WellKnownConfigurationCache.
    - A single JWKS initialization lock ensures JWKS is fetched only once.

    Public API:
    - ensure_initialized_async(): Fetch well-known configs + JWKS once.
    - fetch_well_known_config_async(well_known_uri): Delegates to cache.
    - refresh_async(): Force re-fetch (clears cache + jwks) (optional).
    - Properties: jwks, well_known_configs, cached_well_known_configs.
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
        self._lock = asyncio.Lock()
        self._loaded: bool = False

    async def get_jwks_async(self) -> KeySet:
        await self.ensure_initialized_async()
        return self._cache.jwks

    async def ensure_initialized_async(self) -> None:
        """Ensure well-known configs and JWKS are loaded exactly once."""
        # Fast path
        if self._loaded:
            return

        async with self._lock:
            if self._loaded:
                logger.debug(
                    "JWKS already initialized by another coroutine (manager fast path)."
                )
                return

            logger.debug("Manager fetching well-known configurations and JWKS.")
            for auth_config in [c for c in self._auth_configs if c.well_known_uri]:
                await self._cache.read_async(auth_config=auth_config)
            self._loaded = True

    async def refresh_async(self) -> None:
        """Force a refresh of well-known configs and JWKS (clears caches)."""
        async with self._lock:
            self._cache.clear()
            self._loaded = False
        await self.ensure_initialized_async()

    async def get_async(self, auth_config: AuthConfig) -> dict[str, Any] | None:
        await self.ensure_initialized_async()
        return await self._cache.get_async(auth_config=auth_config)
