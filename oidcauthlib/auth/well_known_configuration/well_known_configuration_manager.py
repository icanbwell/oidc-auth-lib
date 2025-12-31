import asyncio
import logging
from typing import List

from joserfc.jwk import KeySet
from opentelemetry import trace

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache_result import (
    WellKnownConfigurationCacheResult,
)
from oidcauthlib.open_telemetry.span_names import OidcOpenTelemetrySpanNames
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
        self._lock = asyncio.Lock()
        self._loaded: bool = False
        self._initializing: bool = False
        self._init_event: asyncio.Event = asyncio.Event()
        self._refresh_lock: asyncio.Lock = (
            asyncio.Lock()
        )  # Serializes refresh operations

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
        """Initialize well-known configs and JWKS exactly once (deadlock-free).

        Strategy:
            - Fast path: return if already loaded.
            - Single initializer sets _initializing and clears _init_event.
            - Waiters release _lock and wait on _init_event; on failure they retry.
            - No locks held during network I/O to avoid deadlock with cache.

        Error Handling:
            - On exception during initialization, resets _initializing and sets _init_event
              so waiters can wake and retry.
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
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(
            OidcOpenTelemetrySpanNames.POPULATE_WELL_KNOWN_CONFIG_CACHE,
        ):
            try:
                logger.debug("Manager fetching well-known configurations and JWKS.")
                # Load configs WITHOUT holding the manager lock to avoid deadlock
                # The cache has its own locking mechanism
                configs_to_load = [c for c in self._auth_configs if c.well_known_uri]

                await self._cache.read_list_async(auth_configs=configs_to_load)

                # Mark as loaded (acquire lock to prevent race with refresh)
                async with self._lock:
                    self._loaded = True
                    # Initialization completed successfully; reset flag
                    self._initializing = False
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
        """Force a refresh of well-known configs and JWKS.

        Behavior:
            - Serializes refresh operations to prevent races.
            - Waits for any in-progress initialization to complete before clearing.
            - Clears caches, resets state, and re-initializes.
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
            # Avoid performing I/O while holding the manager lock
            await self._cache.clear_async()
            async with self._lock:
                self._loaded = False
                self._initializing = False
                self._init_event.clear()

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
