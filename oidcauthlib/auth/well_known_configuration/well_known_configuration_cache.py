import asyncio
import logging
from typing import Dict, Any, cast

import httpx
from httpx import ConnectError
from joserfc.jwk import KeySet

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.models.client_key_set import ClientKeySet
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class WellKnownConfigurationCache:
    """Async cache for OpenID Connect discovery documents (well-known configurations).

    Responsibilities:
    - Fetch an OIDC discovery document from its well-known URI exactly once per URI.
    - Cache results in-memory for the lifetime of the instance.
    - Provide a fast path for cache hits without acquiring locks.
    - Use per-URI asyncio locks to prevent race conditions under high concurrency.

    Concurrency Strategy:
    - A global lock protects creation of per-URI locks ("_locks_lock").
    - Each URI has its own asyncio.Lock that serializes the remote HTTP fetch so only
      one coroutine performs the network call for a given URI while others await.
    - Double-checked caching (check before and after acquiring the per-URI lock) avoids
      redundant fetches when multiple coroutines race to initialize a URI.

    Public API:
    - await get_async(well_known_uri): returns the discovery document dict.
    - size(): returns number of cached entries.
    - clear(): empties the cache (primarily for tests).
    - __contains__(uri): True if uri in cache.

    Backward Compatibility:
    TokenReader exposes a property `cached_well_known_configs` that proxies the internal
    cache dict so existing tests and callers continue to function unchanged.
    """

    def __init__(self) -> None:
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.client_key_sets: list[
            ClientKeySet
        ] = []  # will be loaded asynchronously later
        self._jwks: KeySet = KeySet(keys=[])
        self._loaded: bool = False
        self._locks: Dict[str, asyncio.Lock] = {}
        self._locks_lock: asyncio.Lock = asyncio.Lock()  # protects _locks dict mutation

    @property
    def jwks(self) -> KeySet:
        """Return the cached JWKS KeySet, if available."""
        return self._jwks

    async def read_async(self, *, auth_config: AuthConfig) -> Dict[str, Any] | None:
        """Retrieve (and cache) the OIDC discovery document for the given well-known URI.

        Args:
            auth_config (OIDCAuthConfig): OIDC authorization configuration.
        Returns:
            Dict[str, Any]: Parsed JSON discovery document.
        Raises:
            ValueError: If URI is empty or required fields cannot be fetched.
            ConnectionError: On connection failures.
        """
        if auth_config is None:
            raise ValueError("well_known_uri is not set")

        # Fast path: cache hit without acquiring any locks
        well_known_uri: str | None = auth_config.well_known_uri
        if not well_known_uri:
            return None

        if well_known_uri in self._cache:
            logger.info(
                f"\u2713 Using cached OIDC discovery document for {well_known_uri}"
            )
            return self._cache[well_known_uri]

        # Acquire global lock to create/retrieve the per-URI lock safely
        async with self._locks_lock:
            if well_known_uri not in self._locks:
                self._locks[well_known_uri] = asyncio.Lock()
            uri_lock = self._locks[well_known_uri]

        # Serialize remote fetch for this URI
        async with uri_lock:
            # Double-check after waiting: another coroutine may have filled the cache already
            if well_known_uri in self._cache:
                logger.info(
                    f"\u2713 Using cached OIDC discovery document (fetched by another coroutine) for {well_known_uri}"
                )
                return self._cache[well_known_uri]

            logger.info(
                f"Cache miss for {well_known_uri}. Cache has {len(self._cache)} entries."
            )
            async with httpx.AsyncClient() as client:
                try:
                    logger.info(
                        f"Fetching OIDC discovery document from {well_known_uri}"
                    )
                    response = await client.get(well_known_uri)
                    response.raise_for_status()
                    # Format: https://docs.authlib.org/en/latest/oauth/oidc/discovery.html#openid-connect-discovery
                    config = cast(Dict[str, Any], response.json())
                    self._cache[well_known_uri] = config
                    await self.read_jwks_async(
                        auth_config=auth_config,
                        well_known_config=config,
                    )
                    logger.info(f"Cached OIDC discovery document for {well_known_uri}")
                    return config
                except httpx.HTTPStatusError as e:
                    raise ValueError(
                        f"Failed to fetch OIDC discovery document from {well_known_uri} with status {e.response.status_code} : {e}"
                    )
                except ConnectError as e:
                    raise ConnectionError(
                        f"Failed to connect to OIDC discovery document: {well_known_uri}: {e}"
                    )

    @staticmethod
    async def read_jwks_uri_async(*, well_known_config: Dict[str, Any]) -> str | None:
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

    async def read_jwks_async(
        self, *, auth_config: AuthConfig, well_known_config: dict[str, Any]
    ) -> None:
        """Return the list of cached ClientKeySet objects (JWKS).

        Returns:
            List[ClientKeySet]: List of cached ClientKeySet objects.
        """
        jwks_uri = await self.read_jwks_uri_async(well_known_config=well_known_config)
        if not jwks_uri:
            logger.warning(
                f"AuthConfig {auth_config} does not have a JWKS URI, skipping JWKS fetch."
            )
            return None

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
                if len(keys) > 0:
                    self.client_key_sets.append(
                        ClientKeySet(
                            auth_config=auth_config,
                            well_known_config=well_known_config,
                            jwks=KeySet.import_key_set({"keys": keys}),
                            kids=[
                                cast(str, key.get("kid"))
                                for key in keys
                                if key.get("kid")
                            ],
                        )
                    )
                    existing_kids = {key.kid for key in self._jwks}
                    new_keys = [
                        key for key in keys if key.get("kid") not in existing_kids
                    ]
                    self._jwks = KeySet.import_key_set(
                        {"keys": new_keys + [ek.as_dict() for ek in self._jwks]}
                    )
            except httpx.HTTPStatusError as e:
                logger.exception(e)
                raise ValueError(
                    f"Failed to fetch JWKS from {jwks_uri} with status {e.response.status_code} : {e}"
                )
            except ConnectError as e:
                raise ConnectionError(f"Failed to connect to JWKS URI: {jwks_uri}: {e}")

    def size(self) -> int:
        """Return number of cached discovery documents."""
        return len(self._cache)

    def clear(self) -> None:
        """Clear all cached discovery documents (useful for tests)."""
        self._cache.clear()
        self.client_key_sets.clear()
        self._jwks = KeySet(keys=[])
        self._loaded = False

    def get_client_key_set_for_kid(self, *, kid: str | None) -> ClientKeySet | None:
        """
        Retrieves the ClientKeySet that contains the specified Key ID (kid).
        :param kid:
        :return:
        """
        if kid is None:
            return None

        for client_key_set in self.client_key_sets:
            if client_key_set.kids and kid in client_key_set.kids:
                return client_key_set
        return None

    async def get_async(self, auth_config: AuthConfig) -> dict[str, Any] | None:
        """Get the cached OIDC discovery document for the given auth config.

        Args:
            auth_config (OIDCAuthConfig): OIDC authorization configuration.
        Returns:
            Dict[str, Any]: Parsed JSON discovery document.
        """
        well_known_uri: str | None = auth_config.well_known_uri
        if not well_known_uri:
            return None

        if well_known_uri in self._cache:
            return self._cache[well_known_uri]

        return await self.read_async(auth_config=auth_config)
