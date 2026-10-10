import hashlib
import logging
from collections.abc import Sequence
from typing import Any
from urllib.parse import quote

import httpx
from key_value.aio.protocols.key_value import AsyncKeyValueProtocol
from opentelemetry import trace
from pydantic import BaseModel, Field

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.models.token import Token
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)
from oidcauthlib.open_telemetry.span_names import OidcOpenTelemetrySpanNames
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class OidcUserInfoCacheEntry(BaseModel):
    """Document stored for one cached scope list."""

    cache_version: int = Field(description="Version of the cache entry format.")
    client_id: str | None = Field(default=None)
    value: dict[str, Any] = Field(description="Cached payload: {'scopes': [...]}.")


class OidcUserInfoManager:
    """Resolves a token's effective scopes using the OIDC userinfo endpoint, cached in a key-value store.

    Some providers (e.g. Okta employee access tokens) only carry ``openid profile email groups`` in the
    JWT; the scopes that authorize a caller appear only on the userinfo response.

    Behavior:
    - The provider is matched to the token's ``iss`` claim (exact ``issuer``, then ``iss`` contained in the
      provider's ``well_known_uri``), then to its client id. A token matching no provider is an error:
      the bearer token is never sent to an unrelated provider.
    - The userinfo endpoint is discovered through ``WellKnownConfigurationManager``.
    - Scopes are derived the way fhir-server-ui's ``jwtParser`` does: the ``scope`` claim (plus ``scp``,
      which Okta uses), the claims named in ``scope_claims``, and each claim named in ``group_claims``
      with its values taken whole as scopes. Commas are treated as separators, the result is
      de-duplicated, and ``scope_remove_prefixes`` are stripped (first match wins). No claim is read by
      default beyond ``scope``/``scp``: group and extra scope claims are configuration.
    - The result is the union of the scopes derived from the token's own claims and from the userinfo
      response.
    - Only the scopes derived from the userinfo response are cached, never the response itself, under
      ``oidc-userinfo-scopes:<issuer>:<client_id>:<sub>|v<CACHE_VERSION>`` (each segment percent-encoded). The token's own scopes are always
      re-derived from the presented token, so a narrower token never inherits a broader cached set.
      Bumping ``CACHE_VERSION`` obsoletes every existing entry.
    - A token without ``sub`` is never cached: the key would be shared by every user of the client.
    - An empty scope list is never cached: it is also what an account with no scopes looks like, and
      caching it would pin that result for the whole TTL.
    - A cache write failure is logged and swallowed; it never fails the lookup.

    The store and collection are supplied by the caller, so each service keeps its own database. A cached
    scope list outlives a change to the user's entitlements by up to ``cache_ttl_seconds``.

    Failures of the lookup itself (no matching provider, HTTP error, unreadable cache entry) are raised so
    the caller decides whether to fail closed or degrade.
    """

    CACHE_VERSION = 1
    _KEY_PREFIX = "oidc-userinfo-scopes"

    def __init__(
        self,
        *,
        auth_config_reader: AuthConfigReader,
        well_known_configuration_manager: WellKnownConfigurationManager,
        store: AsyncKeyValueProtocol,
        cache_collection: str,
        cache_ttl_seconds: float,
        fetch_timeout_seconds: float,
        scope_claims: Sequence[str] = (),
        group_claims: Sequence[str] = (),
        scope_remove_prefixes: Sequence[str] = (),
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """
        Args:
            auth_config_reader: Reads the configured auth providers.
            well_known_configuration_manager: Supplies the provider's discovery document.
            store: Key-value store holding the cached scopes.
            cache_collection: Collection of ``store`` the entries are written to.
            cache_ttl_seconds: How long a cached entry lives.
            fetch_timeout_seconds: Timeout of the userinfo request.
            scope_claims: Extra claims, besides ``scope`` and ``scp``, whose values are scopes.
            group_claims: Claims whose values are group names, taken whole as scopes.
            scope_remove_prefixes: Prefixes stripped from each scope (first match wins).
            transport: httpx transport, for tests.
        """
        self._auth_config_reader = auth_config_reader
        self._well_known_configuration_manager = well_known_configuration_manager
        self._store = store
        self._cache_collection = cache_collection
        self._cache_ttl_seconds = cache_ttl_seconds
        self._fetch_timeout_seconds = fetch_timeout_seconds
        self._scope_claims = tuple(scope_claims)
        self._group_claims = tuple(group_claims)
        self._scope_remove_prefixes = tuple(scope_remove_prefixes)
        self._transport = transport

    def resolve_auth_config(self, *, access_token: Token) -> AuthConfig:
        """The configuration of the provider that issued ``access_token``.

        Raises:
            ValueError: no configured provider matches the token's issuer or client id.
        """
        issuer = access_token.issuer or (access_token.claims or {}).get("iss")
        configs = self._auth_config_reader.get_auth_configs_for_all_auth_providers()
        if issuer:
            for config in configs:
                if config.issuer and config.issuer == issuer:
                    return config
            for config in configs:
                if config.well_known_uri and self._is_under_issuer(uri=config.well_known_uri, issuer=issuer):
                    return config
        client_id = access_token.client_id
        if client_id:
            auth_provider = self._auth_config_reader.get_provider_for_client_id(client_id=client_id)
            if auth_provider:
                auth_config = self._auth_config_reader.get_config_for_auth_provider(auth_provider=auth_provider)
                if auth_config:
                    return auth_config
        raise ValueError(f"No auth provider matches token issuer {issuer!r} or client id {client_id!r}")

    @staticmethod
    def _is_under_issuer(*, uri: str, issuer: str) -> bool:
        """True when ``uri`` is the issuer itself or a path beneath it.

        A bare substring test would also match ``https://a.example.com.au/...`` for the issuer
        ``https://a.example.com`` and send the token to the wrong provider.
        """
        base = issuer.rstrip("/")
        return uri == base or uri.startswith(f"{base}/")

    @staticmethod
    def _loggable(*, cache_key: str) -> str:
        """Short digest of ``cache_key``: the key embeds the user's ``sub``, which must not reach logs."""
        return hashlib.sha256(cache_key.encode()).hexdigest()[:12]

    async def get_user_info_async(self, *, access_token: Token) -> dict[str, Any]:
        """Fetch the userinfo response for ``access_token``.

        ``access_token`` must already have been verified by the caller; its claims are trusted.

        Raises:
            ValueError: the token, auth config, discovery document or response is unusable.
            httpx.HTTPError: the userinfo request failed.
        """
        if not access_token.token:
            raise ValueError("Raw access token is required")

        auth_config = self.resolve_auth_config(access_token=access_token)

        well_known_result = await self._well_known_configuration_manager.get_async(auth_config=auth_config)
        well_known_config = well_known_result.well_known_config if well_known_result else None
        if not well_known_config:
            raise ValueError("Well-known configuration not found for auth config")

        userinfo_endpoint = well_known_config.get("userinfo_endpoint")
        if not userinfo_endpoint or not isinstance(userinfo_endpoint, str):
            raise ValueError("Userinfo endpoint not found in well-known configuration")

        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(OidcOpenTelemetrySpanNames.GET_USER_INFO_FROM_OIDC_ENDPOINT):
            async with httpx.AsyncClient(transport=self._transport) as client:
                response = await client.get(
                    userinfo_endpoint,
                    headers={
                        "Authorization": f"Bearer {access_token.token}",
                        "Accept": "application/json",
                    },
                    timeout=self._fetch_timeout_seconds,
                )
                response.raise_for_status()
                user_info = response.json()
            if not isinstance(user_info, dict):
                raise ValueError("User info response is not a valid JSON object")
            return user_info

    async def get_scopes_from_user_info_async(self, *, access_token: Token) -> list[str]:
        """Effective scopes of ``access_token``: its own plus those of the userinfo endpoint.

        The userinfo scopes come from the cache when present, else from the endpoint (then cached).

        Raises:
            ValueError: the cached entry has an unexpected shape, or no provider matches the token.
            httpx.HTTPError: the userinfo request failed.
        """
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(OidcOpenTelemetrySpanNames.GET_SCOPES_FROM_OIDC_USERINFO):
            token_scopes = self.build_scopes(claims=access_token.claims or {})
            cache_key = self.build_cache_key(
                issuer=access_token.issuer or (access_token.claims or {}).get("iss"),
                client_id=access_token.client_id,
                subject=access_token.subject,
            )

            user_info_scopes: list[str] | None = None
            if cache_key is not None:
                user_info_scopes = await self._read_cached_scopes(cache_key=cache_key)

            if user_info_scopes is None:
                user_info = await self.get_user_info_async(access_token=access_token)
                user_info_scopes = self.build_scopes(claims=user_info)
                if cache_key is not None and user_info_scopes:
                    await self._write_cached_scopes(cache_key=cache_key, scopes=user_info_scopes)

            return list(dict.fromkeys([*token_scopes, *user_info_scopes]))

    def build_scopes(self, *, claims: dict[str, Any]) -> list[str]:
        """Scopes carried by ``claims`` (a token's payload or a userinfo response)."""
        scopes: list[str] = []

        for claim_name in ("scope", "scp"):
            scopes.extend(self._claim_values(value=claims.get(claim_name)))

        for claim_name in self._scope_claims:
            scopes.extend(self._claim_values(value=claims.get(claim_name)))

        for claim_name in self._group_claims:
            scopes.extend(self._claim_values(value=claims.get(claim_name)))

        scopes = list(dict.fromkeys(scopes))
        if self._scope_remove_prefixes:
            scopes = [self._strip_prefix(scope=s) for s in scopes]
        return scopes

    @staticmethod
    def _claim_values(*, value: Any) -> list[str]:
        """String or list claim value as separate tokens; commas separate like spaces (as in jwtParser)."""
        if isinstance(value, str):
            return value.replace(",", " ").split()
        if isinstance(value, list):
            return [token for item in value if isinstance(item, str) for token in item.replace(",", " ").split()]
        return []

    def _strip_prefix(self, *, scope: str) -> str:
        for prefix in self._scope_remove_prefixes:
            if scope.startswith(prefix):
                return scope[len(prefix) :]
        return scope

    @classmethod
    def build_cache_key(cls, *, issuer: str | None, client_id: str | None, subject: str | None) -> str | None:
        """Versioned key for one user of one client of one issuer, or None when the token has no ``sub``.

        Each segment is percent-encoded, so a ``:`` inside an issuer, client id or subject can never move a
        segment boundary and make two different users share a key. A missing issuer or client id is an
        empty segment, which no encoded value can equal.
        """
        if not subject:
            return None
        segments = [quote(value or "", safe="") for value in (issuer, client_id, subject)]
        return f"{':'.join([cls._KEY_PREFIX, *segments])}|v{cls.CACHE_VERSION}"

    async def _read_cached_scopes(self, *, cache_key: str) -> list[str] | None:
        raw = await self._store.get(cache_key, collection=self._cache_collection)
        key_id = self._loggable(cache_key=cache_key)
        if raw is None:
            logger.debug(f"OIDC userinfo scopes cache miss for key: {key_id}")
            return None
        try:
            entry = OidcUserInfoCacheEntry.model_validate(raw)
        except ValueError as exc:
            raise ValueError(f"OIDC userinfo scopes cache entry has invalid shape for key: {key_id}") from exc
        scopes = entry.value.get("scopes")
        if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
            raise ValueError(f"OIDC userinfo scopes cache entry has invalid shape for key: {key_id}. {type(scopes)}")
        return scopes

    async def _write_cached_scopes(self, *, cache_key: str, scopes: list[str]) -> None:
        entry = OidcUserInfoCacheEntry(
            cache_version=self.CACHE_VERSION,
            client_id=None,
            value={"scopes": scopes},
        )
        try:
            await self._store.put(
                cache_key,
                entry.model_dump(),
                collection=self._cache_collection,
                ttl=self._cache_ttl_seconds,
            )
            logger.debug(f"Cached OIDC userinfo scopes for key: {self._loggable(cache_key=cache_key)}")
        except Exception:
            # A cache write failure must not break the auth flow.
            logger.exception(f"Failed to cache OIDC userinfo scopes for key: {self._loggable(cache_key=cache_key)}")
