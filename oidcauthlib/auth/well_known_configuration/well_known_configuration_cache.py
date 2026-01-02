import asyncio
import logging
from typing import Dict, Any, cast

import httpx
from httpx import ConnectError
from joserfc.jwk import KeySet
from key_value.aio.stores.base import BaseStore
from key_value.aio.stores.memory import MemoryStore
from opentelemetry import trace

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.models.client_key_set import ClientKeySet
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache_result import (
    WellKnownConfigurationCacheResult,
)
from oidcauthlib.open_telemetry.span_names import OidcOpenTelemetrySpanNames
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS
from oidcauthlib.open_telemetry.attribute_names import OidcOpenTelemetryAttributeNames

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class WellKnownConfigurationCache:
    """Async cache for OpenID Connect discovery documents (well-known configurations).

    Responsibilities:
    - Fetch an OIDC discovery document from its well-known URI exactly once per URI.
    - Cache results using an in-memory async key-value store for the lifetime of the instance.
    - Provide a fast path for cache hits without acquiring locks.
    - Use per-URI asyncio locks to prevent race conditions under high concurrency.

    Concurrency Strategy:
    - A global lock protects creation of per-URI locks ("_locks_lock").
    - Each URI has its own asyncio.Lock that serializes the remote HTTP fetch so only
      one coroutine performs the network call for a given URI while others await.
    - Double-checked caching (check before and after acquiring the per-URI lock) avoids
      redundant fetches when multiple coroutines race to initialize a URI.

    Public API:
    - read_list_async(auth_configs): fetch and cache discovery documents for multiple configs.
    - read_async(auth_config): fetch and cache a single discovery document.
    - get_async(auth_config): retrieve a cached discovery document.
    - get_client_key_set_for_kid_async(kid): retrieve the ClientKeySet containing a given kid.
    - get_size_async(): return number of cached entries.
    - clear_async(): empty the cache (primarily for tests).

    Notes:
    - The internal cache store is a MemoryStore (key_value.aio) and all interactions are async.
    - OpenTelemetry span and attribute names are sourced from enums to avoid hardcoded strings.
    """

    def __init__(self, *, well_known_store: BaseStore | None) -> None:
        # Replace dict cache with a memory-backed store
        self._cache_store: MemoryStore = MemoryStore()
        self._jwks: KeySet = KeySet(keys=[])
        self._loaded: bool = False
        self._locks: Dict[str, asyncio.Lock] = {}
        self._locks_lock: asyncio.Lock = asyncio.Lock()
        self.well_known_store: BaseStore | None = well_known_store
        if well_known_store is not None and not isinstance(well_known_store, BaseStore):
            raise TypeError(
                f"well_known_store must be an instance of BaseStore: {type(well_known_store)}"
            )

    @property
    def jwks(self) -> KeySet:
        """Return the cached JWKS KeySet.

        Returns:
            KeySet: The combined JWKS key set aggregated from fetched ClientKeySet entries.
        Note:
            Empty when no ClientKeySet keys have been read or after clear_async().
        """
        return self._jwks

    async def read_list_async(
        self, *, auth_configs: list[AuthConfig]
    ) -> None:
        """Fetch and cache discovery documents for multiple auth configs.

        Args:
            auth_configs: List of OIDC authorization configurations (must have well_known_uri).
        Returns:
            A list of WellKnownConfigurationCacheResult for successfully fetched configs.
        Notes:
            - Populates the in-memory cache and optional backing store.
            - Aggregates JWKS into the class-level jwks KeySet.
        """
        if self._loaded:
            return None

        # now check if the well-known configs are already in the disk store
        results: list[WellKnownConfigurationCacheResult] = []
        has_missing_well_known_cache: bool = False
        for auth_config in auth_configs:
            if not auth_config.well_known_uri:
                raise ValueError(
                    f"AuthConfig {auth_config} is missing well_known_uri"
                )
            well_known_uri: str | None = auth_config.well_known_uri
            if not well_known_uri:
                return None

            # Fast path: cache hit via store
            cached_config_dict: dict[str, Any] | None = await self.well_known_store.get(key=well_known_uri)
            if cached_config_dict is None:
                has_missing_well_known_cache = True
            else:
                results.append(
                    WellKnownConfigurationCacheResult.model_validate(cached_config_dict)
                )

        if not has_missing_well_known_cache:
            logger.info(
                "All well-known configurations already cached; skipping read."
            )
            self.read_jwks_from_key_sets(
                key_sets=[
                    result.client_key_set
                    for result in results
                    if result.client_key_set is not None
                ]
            )
            self._loaded = True
            return None

        # not found in memory cache or disk cache so fetch them
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(
            OidcOpenTelemetrySpanNames.POPULATE_WELL_KNOWN_CONFIG_CACHE,
        ):
            tasks = []
            for auth_config in auth_configs:
                tasks.append(self.read_async(auth_config=auth_config))
            results = [
                result for result in await asyncio.gather(*tasks) if result is not None
            ]
            self.read_jwks_from_key_sets(
                key_sets=[
                    result.client_key_set
                    for result in results
                    if result.client_key_set is not None
                ]
            )
            self._loaded = True
            return None

    async def read_async(
        self, *, auth_config: AuthConfig
    ) -> WellKnownConfigurationCacheResult | None:
        """Fetch and cache the discovery document for a single auth config.

        Args:
            auth_config: OIDC authorization configuration providing well_known_uri.
        Returns:
            WellKnownConfigurationCacheResult or None if no well_known_uri provided.
        Raises:
            ValueError: Missing well_known_uri or required fields from responses.
            ConnectionError: Network connectivity problems when calling remote endpoints.
        Behavior:
            - Uses fast-path cache hit from MemoryStore.
            - Falls back to optional backing store.
            - Serializes remote fetch per URI via asyncio.Lock.
        """
        if auth_config is None:
            raise ValueError("well_known_uri is not set")

        well_known_uri: str | None = auth_config.well_known_uri
        if not well_known_uri:
            return None

        # Fast path: cache hit via store
        cached_config_dict: dict[str, Any] | None = await self._cache_store.get(key=well_known_uri)
        if cached_config_dict is not None:
            logger.info(
                f"\u2713 Using cached OIDC discovery document for {well_known_uri}"
            )
            return WellKnownConfigurationCacheResult.model_validate(cached_config_dict)

        # check if this well_known_uri is in the well_known_store
        stored_config: dict[str, Any] | None = (
            await self.well_known_store.get(
                key=well_known_uri,
            )
            if self.well_known_store is not None
            else None
        )
        if stored_config:
            logger.info(
                f"\u2713 Using stored OIDC discovery document from store for {well_known_uri}"
            )
            # write-through to memory cache store
            await self._cache_store.put(
                key=well_known_uri,
                value=stored_config,
            )
            return WellKnownConfigurationCacheResult.model_validate(stored_config)

        # Acquire or reuse a URI-specific lock to limit network calls per provider
        async with self._locks_lock:
            if well_known_uri not in self._locks:
                self._locks[well_known_uri] = asyncio.Lock()
            uri_lock = self._locks[well_known_uri]

        async with uri_lock:
            # Double-check after waiting: another coroutine may have filled the cache already
            cached_config_dict = await self._cache_store.get(key=well_known_uri)
            if cached_config_dict is not None:
                logger.info(
                    f"\u2713 Using cached OIDC discovery document (fetched by another coroutine) for {well_known_uri}"
                )
                return WellKnownConfigurationCacheResult.model_validate(
                    cached_config_dict
                )

            logger.info(
                # len via count() if available; fallback to 0 if not supported
                f"Cache miss for {well_known_uri}. Cache has {await self._safe_cache_count()} entries."
            )
            tracer = trace.get_tracer(__name__)
            with tracer.start_as_current_span(
                OidcOpenTelemetrySpanNames.READ_WELL_KNOWN_CONFIGURATION,
            ) as span:
                span.set_attribute(
                    OidcOpenTelemetryAttributeNames.WELL_KNOWN_URI, well_known_uri
                )
                async with httpx.AsyncClient() as client:
                    try:
                        logger.info(
                            f"Fetching OIDC discovery document from {well_known_uri}"
                        )
                        response = await client.get(well_known_uri)
                        response.raise_for_status()
                        config = cast(Dict[str, Any], response.json())
                        well_known_configuration_cache_result = (
                            WellKnownConfigurationCacheResult(
                                well_known_uri=well_known_uri,
                                well_known_config=config,
                                client_key_set=await self._read_jwks_async(
                                    auth_config=auth_config,
                                    well_known_config=config,
                                ),
                            )
                        )
                        # write to memory cache store
                        await self._cache_store.put(
                            key=well_known_uri,
                            value=well_known_configuration_cache_result.model_dump(),
                        )
                        if self.well_known_store is not None:
                            await self.well_known_store.put(
                                key=well_known_uri,
                                value=well_known_configuration_cache_result.model_dump(),
                            )
                            logger.info(
                                f"Cached OIDC discovery document for {well_known_uri}"
                            )
                        return well_known_configuration_cache_result
                    except httpx.HTTPStatusError as e:
                        raise ValueError(
                            f"Failed to fetch OIDC discovery document from {well_known_uri} with status {e.response.status_code} : {e}"
                        )
                    except ConnectError as e:
                        raise ConnectionError(
                            f"Failed to connect to OIDC discovery document: {well_known_uri}: {e}"
                        )

    @staticmethod
    async def _read_jwks_uri_async(*, well_known_config: Dict[str, Any]) -> str | None:
        """Extract the JWKS URI from the discovery document.

        Args:
            well_known_config: Parsed discovery document.
        Returns:
            JWKS URI string if present.
        Raises:
            ValueError: If jwks_uri or issuer is missing.
        """
        jwks_uri: str | None = well_known_config.get("jwks_uri")
        issuer = well_known_config.get("issuer")
        if not jwks_uri:
            raise ValueError(
                f"jwks_uri not found in well-known configuration: {well_known_config}"
            )
        if not issuer:
            raise ValueError(
                f"issuer not found in well-known configuration: {well_known_config}"
            )
        return jwks_uri

    @staticmethod
    async def _read_jwks_from_uri_async(*, jwks_uri: str) -> list[Dict[str, Any]]:
        """Fetch JWKS keys from the given JWKS URI.

        Args:
            jwks_uri: HTTPS URL to retrieve JWKS.
        Returns:
            A list of key dicts (deduplicated by kid) from the JWKS response.
        Raises:
            ValueError: Non-2xx HTTP status.
            ConnectionError: When unable to reach the JWKS endpoint.
        Security:
            - Keys are not logged; only counts are logged to avoid PII/token leakage.
        """
        async with httpx.AsyncClient() as client:
            try:
                logger.info(f"Fetching JWKS from {jwks_uri}")
                response = await client.get(jwks_uri)
                response.raise_for_status()
                jwks_data: Dict[str, Any] = response.json()
                keys: list[Dict[str, Any]] = []
                for key in jwks_data.get("keys", []):
                    if not any([k.get("kid") == key.get("kid") for k in keys]):
                        keys.append(key)
                logger.info(
                    f"Successfully fetched JWKS from {jwks_uri}, keys= {len(keys)}"
                )
                return keys
            except httpx.HTTPStatusError as e:
                logger.exception(e)
                raise ValueError(
                    f"Failed to fetch JWKS from {jwks_uri} with status {e.response.status_code} : {e}"
                )
            except ConnectError as e:
                raise ConnectionError(f"Failed to connect to JWKS URI: {jwks_uri}: {e}")

    async def _read_jwks_async(
        self, *, auth_config: AuthConfig, well_known_config: dict[str, Any]
    ) -> ClientKeySet | None:
        """Build a ClientKeySet by fetching keys from jwks_uri.

        Args:
            auth_config: The related OIDC config for context in ClientKeySet.
            well_known_config: Discovery document containing jwks_uri.
        Returns:
            ClientKeySet with kids and keys, or None if jwks_uri missing or no keys.
        """
        jwks_uri = await self._read_jwks_uri_async(well_known_config=well_known_config)
        if not jwks_uri:
            logger.warning(
                f"AuthConfig {auth_config} does not have a JWKS URI, skipping JWKS fetch."
            )
            return None

        keys: list[Dict[str, Any]] = await self._read_jwks_from_uri_async(
            jwks_uri=jwks_uri
        )

        if len(keys) > 0:
            return ClientKeySet(
                auth_config=auth_config,
                well_known_config=well_known_config,
                kids=[
                    cast(str, key.get("kid"))
                    for key in keys
                    if key.get("kid") is not None
                ],
                keys=keys,
            )
        else:
            return None

    def read_jwks_from_key_sets(self, *, key_sets: list[ClientKeySet]) -> None:
        """Aggregate multiple ClientKeySet objects into the jwks KeySet.

        Args:
            key_sets: List of ClientKeySet instances with keys.
        Side Effects:
            Updates self.jwks with any new keys (deduplicated by kid).
        """
        keys: list[Dict[str, Any]] = [key for ks in key_sets for key in (ks.keys or [])]

        existing_kids = {key.kid for key in self._jwks}
        new_keys = [key for key in keys if key.get("kid") not in existing_kids]

        all_keys = new_keys + [ek.as_dict() for ek in self._jwks]
        if all_keys:
            self._jwks = KeySet.import_key_set({"keys": all_keys})

    async def get_size_async(self) -> int:
        """Return the number of cached discovery documents.

        Returns:
            Count of entries currently stored in the in-memory cache.
        """
        return await self._safe_cache_count()

    async def _safe_cache_count(self) -> int:
        try:
            keys = await self._cache_store.keys()
            return len(keys) if keys is not None else 0
        except Exception:
            return 0

    async def clear_async(self) -> None:
        """Clear the cache and reset JWKS state.

        Behavior:
            - Deletes all keys from the in-memory store and optional backing store.
            - Resets jwks to an empty KeySet and loaded flag to False.
        """
        # Delete all known keys from both stores
        keys = await self._cache_store.keys()
        if keys:
            await self._cache_store.delete_many(keys)
        if self.well_known_store is not None and keys:
            await self.well_known_store.delete_many(keys)
        self._jwks = KeySet(keys=[])
        self._loaded = False

    async def get_client_key_set_for_kid_async(
        self, *, kid: str | None
    ) -> ClientKeySet | None:
        """Return the ClientKeySet containing the given kid, if present.

        Args:
            kid: Key ID to search for.
        Returns:
            ClientKeySet that includes the kid, or None if not found or input is None.
        Notes:
            Performs an async search across cached entries; efficient for small caches.
        """
        if kid is None:
            return None

        keys = await self._cache_store.keys()
        for cache_key in keys or []:
            item: dict[str, Any] | None = await self._cache_store.get(key=cache_key)
            if item is None:
                continue
            wkr = WellKnownConfigurationCacheResult.model_validate(item)
            client_key_set = wkr.client_key_set
            if client_key_set and client_key_set.kids and kid in client_key_set.kids:
                return client_key_set
        return None

    async def get_async(
        self, *, auth_config: AuthConfig
    ) -> WellKnownConfigurationCacheResult | None:
        """Retrieve a cached discovery document for the given auth config.

        Args:
            auth_config: OIDC authorization configuration (must provide well_known_uri).
        Returns:
            WellKnownConfigurationCacheResult if present in cache, else None.
        Raises:
            ValueError: If not found in cache (suggest calling read_list_async() first).
        """
        well_known_uri: str | None = auth_config.well_known_uri
        if not well_known_uri:
            return None

        cached_config_dict: dict[str, Any] | None = await self._cache_store.get(
            key=well_known_uri
        )
        if cached_config_dict is None:
            raise ValueError(
                f"JWKS for well-known URI {well_known_uri} not found in cache.  Call read_list_async() first."
            )

        return WellKnownConfigurationCacheResult.model_validate(cached_config_dict)
