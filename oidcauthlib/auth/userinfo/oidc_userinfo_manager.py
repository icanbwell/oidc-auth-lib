import hashlib
import logging
from collections.abc import Sequence
from typing import Any
from urllib.parse import SplitResult, quote, urlsplit

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

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Okta org-server access tokens carry the login in ``sub`` and the stable user id in this claim.
_OKTA_USER_ID_CLAIM = "uid"


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
    - The provider is matched to the token's ``iss`` claim (exact ``issuer``, else a ``well_known_uri`` on the
      same scheme, host and port whose path segments start with the issuer's). Only a token with no ``iss`` at
      all is matched by its client id. A token matching no provider is an error: the bearer token is never
      sent to an unrelated provider.
    - For a token that has a ``sub``, the userinfo response must carry the same ``sub`` (OIDC Core 5.3.2); a
      missing or different one fails the lookup and nothing is cached.
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
    - A token without ``sub`` or without an issuer is never cached: the key would be shared by every user of
      the client, or by every provider that issues tokens without ``iss``.
    - An empty scope list is never cached: it is also what an account with no scopes looks like, and
      caching it would pin that result for the whole TTL.
    - The cache is an optimization and never fails a lookup: a write failure is logged and swallowed, and a
      read failure or an entry of the wrong shape is logged and treated as a miss (the refetched scopes
      overwrite a bad entry).

    The store and collection are supplied by the caller, so each service keeps its own database. A cached
    scope list outlives a change to the user's entitlements by up to ``cache_ttl_seconds``.

    Failures of the lookup itself (no matching provider, HTTP error, mismatched subject) are raised so the
    caller decides whether to fail closed or degrade.
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

        The token's issuer decides: an exact ``issuer`` match, else a ``well_known_uri`` on the same scheme, host
        and port whose path segments start with the issuer's. The client id is only used for a token that has
        no issuer at all; a token whose issuer matches no provider is never routed by its client id, which
        would send it to whichever provider owns that client id.

        Raises:
            ValueError: no configured provider matches the token.
        """
        issuer = access_token.issuer or (access_token.claims or {}).get("iss")
        if issuer:
            configs = self._auth_config_reader.get_auth_configs_for_all_auth_providers()
            for config in configs:
                if config.issuer and config.issuer == issuer:
                    return config
            for config in configs:
                if config.well_known_uri and self._is_under_issuer(uri=config.well_known_uri, issuer=issuer):
                    return config
            raise ValueError(f"No auth provider matches token issuer {issuer!r}")
        client_id = access_token.client_id
        if client_id:
            auth_provider = self._auth_config_reader.get_provider_for_client_id(client_id=client_id)
            if auth_provider:
                auth_config = self._auth_config_reader.get_config_for_auth_provider(auth_provider=auth_provider)
                if auth_config:
                    return auth_config
        raise ValueError(f"No auth provider matches token client id {client_id!r}")

    @staticmethod
    def _effective_port(*, parts: SplitResult) -> int | None:
        if parts.port is not None:
            return parts.port
        return _DEFAULT_PORTS.get(parts.scheme.lower())

    @staticmethod
    def _is_under_issuer(*, uri: str, issuer: str) -> bool:
        """True when ``uri`` is on the issuer's origin and its path is the issuer's path or beneath it.

        Scheme, host (case-insensitive), port (default ports normalized) and path *segments* are compared.
        A string prefix test would match ``https://a.example.com.au/...`` for ``https://a.example.com``,
        ``/realms/ab`` for ``/realms/a``, and every https URL for the degenerate issuer ``https://``.
        """
        try:
            issuer_parts = urlsplit(issuer)
            uri_parts = urlsplit(uri)
            issuer_port = OidcUserInfoManager._effective_port(parts=issuer_parts)
            uri_port = OidcUserInfoManager._effective_port(parts=uri_parts)
        except ValueError:
            return False
        if not issuer_parts.scheme or not issuer_parts.hostname or not uri_parts.hostname:
            return False
        if uri_parts.scheme.lower() != issuer_parts.scheme.lower():
            return False
        if uri_parts.hostname.lower() != issuer_parts.hostname.lower() or uri_port != issuer_port:
            return False
        issuer_segments = [segment for segment in issuer_parts.path.split("/") if segment]
        uri_segments = [segment for segment in uri_parts.path.split("/") if segment]
        return uri_segments[: len(issuer_segments)] == issuer_segments

    @staticmethod
    def _loggable(*, cache_key: str) -> str:
        """Short digest of ``cache_key``: the key embeds the user's ``sub``, which must not reach logs."""
        return hashlib.sha256(cache_key.encode()).hexdigest()[:12]

    @staticmethod
    def _user_id(*, access_token: Token) -> str | None:
        """The token's stable user id claim, when it has a ``sub`` to alias and the claim is a non-empty string."""
        user_id = (access_token.claims or {}).get(_OKTA_USER_ID_CLAIM)
        if access_token.subject and isinstance(user_id, str) and user_id:
            return user_id
        return None

    @staticmethod
    def _token_subjects(*, access_token: Token) -> set[str]:
        """Identifiers a userinfo ``sub`` may legitimately equal for this token; empty for a token without ``sub``.

        Okta org-server access tokens carry the login in ``sub`` and the user id in ``uid``, while the userinfo
        response's ``sub`` is that user id; so the token's ``uid`` counts as the same subject as its ``sub``.
        The alias is not issuer-specific and relies on the caller having verified the token (the userinfo
        request is made with that same token, so the response is always for the token's own user).
        """
        subject = access_token.subject
        if not subject:
            return set()
        if not isinstance(subject, str):
            # A malformed ``sub`` can never be shown to equal the response's; fail closed like any mismatch.
            raise ValueError("User info response subject is missing or differs from the token's subject")
        user_id = OidcUserInfoManager._user_id(access_token=access_token)
        return {subject} | ({user_id} if user_id else set())

    async def get_user_info_async(self, *, access_token: Token) -> dict[str, Any]:
        """Fetch the userinfo response for ``access_token``.

        ``access_token`` must already have been verified by the caller; its claims are trusted.

        Per OIDC Core 5.3.2 the response must carry a ``sub`` equal to the token's ``sub`` (or its ``uid``, see
        ``_token_subjects``); a response without one, or with a different one, cannot be shown to describe the
        token's user and is rejected. A token that has no ``sub`` has nothing to compare (its ``uid`` is not
        consulted), so its response is accepted (and never cached).

        Raises:
            ValueError: the token, auth config, discovery document or response is unusable, or the response's
                subject is missing or differs from the token's.
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
            token_subjects = self._token_subjects(access_token=access_token)
            if token_subjects and user_info.get("sub") not in token_subjects:
                # Missing or different: ``sub`` is required in the response, and one that cannot be shown
                # to be the token's subject must not be turned into scopes. Neither subject is logged.
                raise ValueError("User info response subject is missing or differs from the token's subject")
            return user_info

    async def get_scopes_from_user_info_async(self, *, access_token: Token) -> list[str]:
        """Effective scopes of ``access_token``: its own plus those of the userinfo endpoint.

        The userinfo scopes come from the cache when present, else from the endpoint (then cached).

        Raises:
            ValueError: no provider matches the token, or the userinfo response is for another subject.
            httpx.HTTPError: the userinfo request failed.
        """
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(OidcOpenTelemetrySpanNames.GET_SCOPES_FROM_OIDC_USERINFO):
            token_scopes = self.build_scopes(claims=access_token.claims or {})
            cache_key = self.build_cache_key(
                issuer=access_token.issuer or (access_token.claims or {}).get("iss"),
                client_id=access_token.client_id,
                # The stable user id when the token has one: a login can be reassigned to another user.
                subject=self._user_id(access_token=access_token) or access_token.subject,
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
        """Versioned key for one user of one client of one issuer, or None when the token is not cacheable.

        A token without ``sub`` or without an issuer is not cacheable: the key would be shared by every user
        of the client, or by every provider that issues tokens without an ``iss`` claim.

        Each segment is percent-encoded, so a ``:`` inside an issuer, client id or subject can never move a
        segment boundary and make two different users share a key. A missing client id is an empty segment,
        which no encoded value can equal.
        """
        if not subject or not issuer:
            return None
        segments = [quote(value or "", safe="") for value in (issuer, client_id, subject)]
        return f"{':'.join([cls._KEY_PREFIX, *segments])}|v{cls.CACHE_VERSION}"

    async def _read_cached_scopes(self, *, cache_key: str) -> list[str] | None:
        """Cached userinfo scopes, or None for a miss.

        A store failure or an entry of the wrong shape is logged and treated as a miss: the cache is an
        optimization, so one bad entry (or a store outage) must not fail every request for that key until the
        TTL expires. The refetched scopes then overwrite the bad entry.
        """
        key_id = self._loggable(cache_key=cache_key)
        try:
            raw = await self._store.get(cache_key, collection=self._cache_collection)
        except Exception:
            logger.exception(f"Failed to read OIDC userinfo scopes from the cache for key: {key_id}")
            return None
        if raw is None:
            logger.debug(f"OIDC userinfo scopes cache miss for key: {key_id}")
            return None
        try:
            entry = OidcUserInfoCacheEntry.model_validate(raw)
        except ValueError:
            logger.warning(f"OIDC userinfo scopes cache entry has invalid shape for key: {key_id}; refetching")
            return None
        scopes = entry.value.get("scopes")
        if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
            logger.warning(
                f"OIDC userinfo scopes cache entry has invalid scopes ({type(scopes).__name__}) for key: {key_id}; "
                "refetching"
            )
            return None
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
