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
        self._initializing: bool = False
        self._init_event: asyncio.Event = asyncio.Event()
        self._refresh_lock: asyncio.Lock = (
            asyncio.Lock()
        )  # Serializes refresh operations

    async def get_jwks_async(self) -> KeySet:
        await self.ensure_initialized_async()
        return self._cache.jwks

    async def ensure_initialized_async(self) -> None:
        """Ensure well-known configs and JWKS are loaded exactly once.

        Uses an event-based approach to prevent deadlock:
        - Only one coroutine performs initialization
        - Other coroutines wait on an event
        - No locks held during I/O operations to prevent deadlock with cache locks
        """
        # Fast path - no lock needed for read
        if self._loaded:
            return None

        async with self._lock:
            # Double-check after acquiring lock
            if self._loaded:
                logger.debug(
                    "JWKS already initialized by another coroutine (manager fast path)."
                )
                return None

            # If already initializing, release lock and wait
            if self._initializing:
                # Need to wait outside the lock
                should_wait = True
            else:
                # We're the first, mark as initializing
                self._initializing = True
                self._init_event.clear()
                should_wait = False

        # Wait for initialization if another coroutine is doing it
        if should_wait:
            await self._init_event.wait()
            # After waking, check if initialization succeeded
            # If it failed, we need to retry (become the new initializer)
            if not self._loaded:
                return await self.ensure_initialized_async()
            return None

        # We are the initializer
        try:
            logger.debug("Manager fetching well-known configurations and JWKS.")
            # Load configs WITHOUT holding the manager lock to avoid deadlock
            # The cache has its own locking mechanism
            configs_to_load = [c for c in self._auth_configs if c.well_known_uri]

            for auth_config in configs_to_load:
                await self._cache.read_async(auth_config=auth_config)

            # Mark as loaded (acquire lock to prevent race with refresh)
            async with self._lock:
                self._loaded = True
            logger.debug("Manager initialization complete.")
        except Exception:
            # Reset initializing flag so next coroutine can retry
            self._initializing = False
            # Set event to unblock waiting coroutines (they will retry)
            self._init_event.set()
            raise
        else:
            # Success: signal all waiting coroutines
            self._init_event.set()

    async def refresh_async(self) -> None:
        """Force a refresh of well-known configs and JWKS (clears caches).

        Serializes refresh operations to prevent race conditions.
        """
        # Serialize refresh operations - only one refresh at a time
        async with self._refresh_lock:
            # First, wait for any in-progress initialization to complete
            # This prevents race conditions with concurrent initializations
            async with self._lock:
                if self._initializing:
                    should_wait = True
                else:
                    should_wait = False

            if should_wait:
                # Wait outside the lock for initialization to complete
                await self._init_event.wait()

            # Now clear and reset - no concurrent initialization can be running
            async with self._lock:
                self._cache.clear()
                self._loaded = False
                self._initializing = False
                self._init_event.clear()

            await self.ensure_initialized_async()

    async def get_async(self, auth_config: AuthConfig) -> dict[str, Any] | None:
        await self.ensure_initialized_async()
        return await self._cache.get_async(auth_config=auth_config)
