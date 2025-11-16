import asyncio
import logging
from typing import Dict, Any, cast

import httpx
from httpx import ConnectError

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
        self._locks: Dict[str, asyncio.Lock] = {}
        self._locks_lock: asyncio.Lock = asyncio.Lock()  # protects _locks dict mutation

    async def get_async(self, *, well_known_uri: str) -> Dict[str, Any]:
        """Retrieve (and cache) the OIDC discovery document for the given well-known URI.

        Args:
            well_known_uri: The full HTTPS URI of the OIDC discovery document.
        Returns:
            Dict[str, Any]: Parsed JSON discovery document.
        Raises:
            ValueError: If URI is empty or required fields cannot be fetched.
            ConnectionError: On connection failures.
        """
        if not well_known_uri:
            raise ValueError("well_known_uri is not set")

        # Fast path: cache hit without acquiring any locks
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
                    config = cast(Dict[str, Any], response.json())
                    self._cache[well_known_uri] = config
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

    def size(self) -> int:
        """Return number of cached discovery documents."""
        return len(self._cache)

    def clear(self) -> None:
        """Clear all cached discovery documents (useful for tests)."""
        self._cache.clear()

    def __contains__(self, well_known_uri: str) -> bool:  # pragma: no cover (trivial)
        return well_known_uri in self._cache

    @property
    def cache(self) -> Dict[str, Dict[str, Any]]:  # pragma: no cover (simple accessor)
        return self._cache
