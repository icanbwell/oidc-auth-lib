import base64
import logging
from typing import List

from joserfc.jwk import KeySet

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.models.client_key_set import ClientKeySet
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
        self._hmac_keys_added: bool = False

    async def get_jwks_async(self) -> KeySet:
        """Return the aggregated JWKS KeySet for configured providers.

        Behavior:
            - Ensures initialization has completed (well-known configs loaded).
            - Returns the cache's combined JWKS KeySet.
        Returns:
            KeySet: Combined, de-duplicated JWKS suitable for token verification.
        """
        await self.ensure_initialized_async()
        if not self._hmac_keys_added:
            self._append_hmac_jwks()
            self._hmac_keys_added = True
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
        self._hmac_keys_added = False
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

    def _append_hmac_jwks(self) -> None:
        symmetric_configs = [
            config
            for config in self._auth_configs
            if config.hmac_secret and "HS256" in config.signing_algorithms
        ]
        if not symmetric_configs:
            return

        key_sets: list[ClientKeySet] = []
        for config in symmetric_configs:
            if not config.hmac_secret:
                raise ValueError(
                    f"HMAC secret is required for auth provider {config.auth_provider} to create HS256 JWK."
                )
            kid = config.hmac_key_id or f"{config.auth_provider}-hs256"
            jwk = {
                "kty": "oct",
                "k": self._encode_hmac_secret(config.hmac_secret),
                "alg": "HS256",
                "use": "sig",
                "kid": kid,
            }
            key_sets.append(
                ClientKeySet(
                    auth_config=config,
                    well_known_config=None,
                    kids=[kid],
                    keys=[jwk],
                )
            )

        self._cache.read_jwks_from_key_sets(key_sets=key_sets)

    @staticmethod
    def _encode_hmac_secret(secret: str) -> str:
        raw_bytes = secret.encode("utf-8")
        encoded = base64.urlsafe_b64encode(raw_bytes).decode("utf-8")
        return encoded.rstrip("=")
