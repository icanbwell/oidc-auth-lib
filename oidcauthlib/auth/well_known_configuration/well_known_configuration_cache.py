import asyncio
import logging
import time
import warnings
from functools import partial
from typing import Awaitable, Callable, Dict, Any, TypeVar, cast

import httpx
from httpx import ConnectError
from joserfc.jwk import KeySet
from key_value.aio.stores.base import BaseStore
from key_value.aio.stores.memory import MemoryStore
from opentelemetry import trace
from pydantic import ValidationError

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.models.client_key_set import ClientKeySet
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache_result import (
    WellKnownConfigurationCacheResult,
)
from oidcauthlib.open_telemetry.span_names import OidcOpenTelemetrySpanNames
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS
from oidcauthlib.open_telemetry.attribute_names import OidcOpenTelemetryAttributeNames
from oidcauthlib.utilities.url_validator import validate_url

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])

_T = TypeVar("_T")


class WellKnownConfigurationCache:
    """Read-through accessor for OpenID Connect discovery documents and their JWKS.

    Every read goes to the backing store (``well_known_store``; MongoDB in our services),
    which is shared by all pods. This class keeps NO in-process copy of a discovery
    document or of the JWKS, so a pod can never serve keys another pod has already
    refreshed away. When no store is supplied (deprecated) a private ``MemoryStore`` is
    used as the backing store, which keeps the old single-process behaviour.

    Read path: store hit -> return. Store miss, expired row, bad row or stale schema ->
    fetch from the issuer over HTTPS, upsert into the store with a TTL, return.

    Single flight:
    - Within a pod, concurrent callers for the same URI share one in-flight task and its
      outcome, success or failure, so an unreachable issuer costs one timeout rather than one
      per queued caller. The task is dropped as soon as it finishes; it never holds data. The
      store is re-read inside the task so a row another pod just wrote is reused.
    - Across pods, duplicate fetches are tolerated: the fetch is idempotent, the write is an
      upsert, and the cost is at most one issuer fetch per pod per URI per TTL window. An
      advisory lock is deliberately not used; a stuck lock would put a new failure mode on
      the authentication path.

    Expiry and key rotation:
    - Rows are written with ``well_known_cache_ttl_seconds`` and carry ``fetched_at``; rows
      older than the TTL are treated as misses even if the store did not expire them.
    - ``refresh_async`` (called when a token's kid is unknown) refetches the issuer, but is
      rate limited by the stored row's ``fetched_at`` (shared across pods), so a flood of
      tokens with random kids cannot cause a refetch storm.

    Failure behaviour (fail closed): store read/write errors and issuer errors propagate to
    the caller. Nothing here ever skips signature validation or falls back to stale keys.

    Public API:
    - read_list_async(auth_configs): read-through for multiple configs.
    - read_async(auth_config): read-through for one config.
    - get_async(auth_config): read-through for one config (kept for compatibility).
    - get_jwks_async(auth_configs): assemble a fresh KeySet from the store.
    - refresh_async(auth_configs): rate-limited refetch for unknown-kid.
    - get_client_key_set_for_kid_async(kid): look a kid up in the store.
    - get_size_async(): number of readable rows for URIs this instance has seen.
    - clear_async(): delete the rows for URIs this instance has seen.
    """

    def __init__(
        self,
        *,
        well_known_store: BaseStore | None,
        environment_variables: OidcEnvironmentVariables,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if well_known_store is not None and not isinstance(well_known_store, BaseStore):
            raise TypeError(f"well_known_store must be an instance of BaseStore: {type(well_known_store)}")
        self.environment_variables: OidcEnvironmentVariables = environment_variables
        if not isinstance(environment_variables, OidcEnvironmentVariables):
            raise TypeError(
                f"environment_variables must be an instance of OidcEnvironmentVariables, got {type(environment_variables).__name__}"
            )
        self.well_known_store: BaseStore | None = well_known_store
        if well_known_store is None:
            message = (
                "WellKnownConfigurationCache created without a well_known_store: discovery documents and JWKS "
                "are held in this process only, so pods will not share or refresh them together. "
                "Pass a shared BaseStore (e.g. MongoDB); store-less operation is deprecated."
            )
            logger.warning(message)
            warnings.warn(message, DeprecationWarning, stacklevel=2)
        self._store: BaseStore = well_known_store if well_known_store is not None else MemoryStore()
        self._clock: Callable[[], float] = clock
        # In-flight fetches within this process, keyed by (operation, URI). Entries exist only
        # while the fetch runs and hold no cached data.
        self._in_flight: Dict[tuple[str, str], asyncio.Future[Any]] = {}
        # URIs this instance has been asked about (configuration, not cached data). The store
        # has no key listing, so kid lookup and clear need to know which rows to consult.
        self._known_uris: set[str] = set()

    @property
    def jwks(self) -> KeySet:
        """Removed: the JWKS is no longer held in memory.

        Raises:
            RuntimeError: always. Use ``await get_jwks_async(auth_configs=...)``, which
            assembles a KeySet from the backing store on every call.
        """
        raise RuntimeError(
            "WellKnownConfigurationCache no longer holds a JWKS in memory; use get_jwks_async(auth_configs=...)"
        )

    async def read_list_async(self, *, auth_configs: list[AuthConfig]) -> None:
        """Read (and fetch if missing or expired) discovery documents for multiple configs.

        Configs without a ``well_known_uri`` are skipped.
        """
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(
            OidcOpenTelemetrySpanNames.POPULATE_WELL_KNOWN_CONFIG_CACHE,
        ):
            await asyncio.gather(*[self.read_async(auth_config=c) for c in auth_configs if c.well_known_uri])
        return None

    async def get_jwks_async(self, *, auth_configs: list[AuthConfig]) -> KeySet:
        """Assemble a KeySet from the backing store for the given configs.

        The KeySet is built per call and not retained. Keys are de-duplicated by kid
        (first provider wins), matching the previous behaviour.
        """
        results = await self._read_many_async(auth_configs=[c for c in auth_configs if c.well_known_uri])
        keys: list[Dict[str, Any]] = []
        seen_kids: set[Any] = set()
        for result in results:
            if result is None or result.client_key_set is None:
                continue
            for key in result.client_key_set.keys or []:
                kid = key.get("kid")
                if kid is not None and kid in seen_kids:
                    continue
                seen_kids.add(kid)
                keys.append(key)
        if not keys:
            return KeySet(keys=[])
        return KeySet.import_key_set({"keys": keys})

    async def _read_many_async(
        self, *, auth_configs: list[AuthConfig]
    ) -> list[WellKnownConfigurationCacheResult | None]:
        """Read rows for several configs with ONE store round trip (get_many).

        Configs whose row is missing, expired or unusable fall back to the single-config
        read-through path (which fetches the issuer). A failing provider does not take down
        the others: its error is logged and its keys are simply absent, so its own tokens
        still fail closed. If no provider has a usable row and every fallback read fails, the first error is raised.
        """
        if not auth_configs:
            return []
        uris = [cast(str, c.well_known_uri) for c in auth_configs]
        self._known_uris.update(uris)
        rows = await self._store.get_many(keys=uris)
        usable_rows = [self._parse_row(well_known_uri=uri, cached=row) for uri, row in zip(uris, rows)]
        missing = [c for c, usable in zip(auth_configs, usable_rows) if usable is None]
        fetched = iter(
            self._tolerate_partial_failure(
                outcomes=await asyncio.gather(
                    *[self.read_async(auth_config=c) for c in missing],
                    return_exceptions=True,
                ),
                uris=[cast(str, c.well_known_uri) for c in missing],
                has_usable_rows=any(usable is not None for usable in usable_rows),
            )
        )
        return [usable if usable is not None else next(fetched) for usable in usable_rows]

    @staticmethod
    def _tolerate_partial_failure(
        *, outcomes: list[_T | BaseException], uris: list[str], has_usable_rows: bool
    ) -> list[_T | None]:
        """Turn per-provider failures into None unless every provider failed.

        Isolates providers from each other's outages. Providers whose stored row was already
        usable count as healthy: the error is raised only when no provider has a usable row and
        every fetch failed, so there is nothing healthy to protect (fail closed, caller sees the cause).
        """
        failures = [o for o in outcomes if isinstance(o, BaseException)]
        if outcomes and len(failures) == len(outcomes) and not has_usable_rows:
            raise failures[0]
        results: list[_T | None] = []
        for uri, outcome in zip(uris, outcomes):
            if isinstance(outcome, BaseException):
                logger.error(f"Could not read OIDC configuration for {uri}; continuing without it: {outcome!r}")
                results.append(None)
            else:
                results.append(outcome)
        return results

    def _is_fresh(self, *, result: WellKnownConfigurationCacheResult) -> bool:
        if result.fetched_at is None:
            # Row written before fetched_at existed: rely on the store's own TTL.
            return True
        age = self._clock() - result.fetched_at
        return age <= self.environment_variables.well_known_cache_ttl_seconds

    async def _read_stored_async(self, *, well_known_uri: str) -> WellKnownConfigurationCacheResult | None:
        """Read one row from the store; None for a miss, unreadable, stale-schema, mismatched or expired row.

        Store errors propagate (fail closed).
        """
        cached: dict[str, Any] | None = await self._store.get(key=well_known_uri)
        return self._parse_row(well_known_uri=well_known_uri, cached=cached)

    def _parse_row(
        self, *, well_known_uri: str, cached: dict[str, Any] | None
    ) -> WellKnownConfigurationCacheResult | None:
        """Validate a raw stored row; None if absent, unreadable, stale-schema, mismatched or expired."""
        if cached is None:
            return None
        try:
            result = WellKnownConfigurationCacheResult.model_validate(cached)
        except ValidationError as ve:
            logger.info(
                f"Stored data for {well_known_uri} failed validation ({ve.error_count()} error(s)); treating as miss"
            )
            return None
        if not result.is_schema_current():
            logger.info(
                f"Stale schema version in store for {well_known_uri} "
                f"(stored={result.schema_version}, current={WellKnownConfigurationCacheResult.SCHEMA_VERSION}); "
                f"treating as miss"
            )
            return None
        if result.well_known_uri != well_known_uri:
            logger.warning(f"Stored row for {well_known_uri} names a different URI; treating as miss")
            return None
        if not self._is_fresh(result=result):
            logger.info(f"Stored row for {well_known_uri} is older than the TTL; treating as miss")
            return None
        return result

    def _discard_flight(self, key: tuple[str, str], flight: "asyncio.Future[Any]") -> None:
        if self._in_flight.get(key) is flight:
            del self._in_flight[key]

    async def _single_flight_async(
        self, *, operation: str, well_known_uri: str, work: Callable[[], Awaitable[_T]]
    ) -> _T:
        """Run ``work`` once per (operation, URI) at a time; concurrent callers share its outcome.

        Success or failure is shared with everyone who arrived while it ran, so callers do not
        queue up and repeat a timed-out fetch one after another. A caller arriving after it has
        finished starts a new run. The entry is removed on completion and holds no data.
        """
        key = (operation, well_known_uri)
        flight = self._in_flight.get(key)
        if flight is None:
            flight = asyncio.ensure_future(work())
            self._in_flight[key] = flight
            flight.add_done_callback(partial(self._discard_flight, key))
        # shield: one waiter being cancelled must not cancel the fetch the others share
        return cast(_T, await asyncio.shield(flight))

    async def read_async(self, *, auth_config: AuthConfig) -> WellKnownConfigurationCacheResult | None:
        """Return the discovery document for one config, reading the store on every call.

        Args:
            auth_config: OIDC authorization configuration providing well_known_uri.
        Returns:
            The result, or None if the config has no well_known_uri.
        Raises:
            ValueError: Missing required fields or non-2xx from the issuer.
            ConnectionError: Network problems reaching the issuer.
            Exception: Any store error (fail closed).
        """
        if auth_config is None:
            raise ValueError("well_known_uri is not set")
        well_known_uri: str | None = auth_config.well_known_uri
        if not well_known_uri:
            return None
        self._known_uris.add(well_known_uri)

        stored = await self._read_stored_async(well_known_uri=well_known_uri)
        if stored is not None:
            return stored

        async def _read_or_fetch_async() -> WellKnownConfigurationCacheResult:
            # Another pod may have filled the row since the read above.
            stored = await self._read_stored_async(well_known_uri=well_known_uri)
            if stored is not None:
                return stored
            logger.info(f"Store miss for {well_known_uri}; fetching from issuer")
            return await self._fetch_and_store_async(auth_config=auth_config, well_known_uri=well_known_uri)

        return await self._single_flight_async(
            operation="read", well_known_uri=well_known_uri, work=_read_or_fetch_async
        )

    async def refresh_async(self, *, auth_configs: list[AuthConfig]) -> None:
        """Refetch discovery documents and JWKS because a token presented an unknown kid.

        Rate limited per URI: if the stored row was fetched less than
        ``well_known_kid_miss_refetch_min_interval_seconds`` ago (by any pod), the refetch is
        skipped and the caller's validation proceeds against the stored keys and fails closed.
        The row is overwritten, never deleted first, so there is no window with no row.
        One provider failing to refetch does not stop the others; if all fail the first error is raised.
        """
        targets = [c for c in auth_configs if c.well_known_uri]
        self._tolerate_partial_failure(
            outcomes=await asyncio.gather(
                *[self._refresh_one_async(auth_config=c) for c in targets], return_exceptions=True
            ),
            uris=[cast(str, c.well_known_uri) for c in targets],
            has_usable_rows=False,
        )

    async def _refresh_one_async(self, *, auth_config: AuthConfig) -> None:
        well_known_uri = cast(str, auth_config.well_known_uri)
        self._known_uris.add(well_known_uri)

        async def _rate_limited_refetch_async() -> None:
            stored = await self._read_stored_async(well_known_uri=well_known_uri)
            if stored is not None and stored.fetched_at is not None:
                age = self._clock() - stored.fetched_at
                if age < self.environment_variables.well_known_kid_miss_refetch_min_interval_seconds:
                    logger.info(f"Skipping kid-miss refetch for {well_known_uri}: row is {age:.0f}s old (rate limited)")
                    return
            await self._fetch_and_store_async(auth_config=auth_config, well_known_uri=well_known_uri)

        await self._single_flight_async(
            operation="refresh", well_known_uri=well_known_uri, work=_rate_limited_refetch_async
        )

    async def _fetch_and_store_async(
        self, *, auth_config: AuthConfig, well_known_uri: str
    ) -> WellKnownConfigurationCacheResult:
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(
            OidcOpenTelemetrySpanNames.READ_WELL_KNOWN_CONFIGURATION,
        ) as span:
            span.set_attribute(OidcOpenTelemetryAttributeNames.WELL_KNOWN_URI, well_known_uri)
            validate_url(well_known_uri)
            async with httpx.AsyncClient() as client:
                try:
                    logger.info(f"Fetching OIDC discovery document from {well_known_uri}")
                    response = await client.get(
                        well_known_uri,
                        timeout=self.environment_variables.well_known_config_http_timeout_seconds,
                    )
                    response.raise_for_status()
                    config = cast(Dict[str, Any], response.json())
                    result = WellKnownConfigurationCacheResult(
                        schema_version=WellKnownConfigurationCacheResult.SCHEMA_VERSION,
                        well_known_uri=well_known_uri,
                        well_known_config=config,
                        client_key_set=await self._read_jwks_async(
                            auth_config=auth_config,
                            well_known_config=config,
                        ),
                        fetched_at=self._clock(),
                    )
                except httpx.HTTPStatusError as e:
                    raise ValueError(
                        f"Failed to fetch OIDC discovery document from {well_known_uri} with status {e.response.status_code} : {e}"
                    )
                except ConnectError as e:
                    raise ConnectionError(f"Failed to connect to OIDC discovery document: {well_known_uri}: {e}")
        await self._store.put(
            key=well_known_uri,
            value=result.model_dump(),
            ttl=self.environment_variables.well_known_cache_ttl_seconds,
        )
        logger.info(f"Stored OIDC discovery document for {well_known_uri}")
        return result

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
            raise ValueError(f"jwks_uri not found in well-known configuration: {well_known_config}")
        if not issuer:
            raise ValueError(f"issuer not found in well-known configuration: {well_known_config}")
        return jwks_uri

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
            logger.warning(f"AuthConfig {auth_config} does not have a JWKS URI, skipping JWKS fetch.")
            return None

        keys: list[Dict[str, Any]] = await self._read_jwks_from_uri_async(jwks_uri=jwks_uri)

        if len(keys) > 0:
            return ClientKeySet(
                auth_config=auth_config,
                well_known_config=well_known_config,
                kids=[cast(str, key.get("kid")) for key in keys if key.get("kid") is not None],
                keys=keys,
            )
        else:
            return None

    async def get_size_async(self) -> int:
        """Return the number of readable rows for the URIs this instance has seen."""
        results = await asyncio.gather(*[self._read_stored_async(well_known_uri=u) for u in set(self._known_uris)])
        return sum(1 for r in results if r is not None)

    async def clear_async(self) -> None:
        """Delete the stored rows for the URIs this instance has seen.

        In a shared store this removes the rows for every pod; the next read refetches.
        """
        if self._known_uris:
            await self._store.delete_many(keys=list(self._known_uris))

    async def get_client_key_set_for_kid_async(self, *, kid: str | None) -> ClientKeySet | None:
        """Return the ClientKeySet containing the given kid, reading the store; None if absent."""
        if kid is None:
            return None
        for well_known_uri in set(self._known_uris):
            result = await self._read_stored_async(well_known_uri=well_known_uri)
            client_key_set = result.client_key_set if result else None
            if client_key_set and client_key_set.kids and kid in client_key_set.kids:
                return client_key_set
        return None

    async def get_async(self, *, auth_config: AuthConfig) -> WellKnownConfigurationCacheResult | None:
        """Return the discovery document for the config (read-through; fetches on miss)."""
        return await self.read_async(auth_config=auth_config)

    async def _read_jwks_from_uri_async(self, *, jwks_uri: str) -> list[Dict[str, Any]]:
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
        validate_url(jwks_uri)
        async with httpx.AsyncClient() as client:
            try:
                logger.info(f"Fetching JWKS from {jwks_uri}")
                response = await client.get(
                    jwks_uri,
                    timeout=self.environment_variables.well_known_config_http_timeout_seconds,
                )
                response.raise_for_status()
                jwks_data: Dict[str, Any] = response.json()
                keys: list[Dict[str, Any]] = []
                for key in jwks_data.get("keys", []):
                    if not any([k.get("kid") == key.get("kid") for k in keys]):
                        keys.append(key)
                logger.info(f"Successfully fetched JWKS from {jwks_uri}, keys= {len(keys)}")
                return keys
            except httpx.HTTPStatusError as e:
                logger.exception(e)
                raise ValueError(f"Failed to fetch JWKS from {jwks_uri} with status {e.response.status_code} : {e}")
            except ConnectError as e:
                raise ConnectionError(f"Failed to connect to JWKS URI: {jwks_uri}: {e}")
