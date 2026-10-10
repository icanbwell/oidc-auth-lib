from typing import Any, override
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from key_value.aio.stores.memory import MemoryStore

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.models.token import Token
from oidcauthlib.auth.userinfo.oidc_userinfo_manager import OidcUserInfoManager
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache_result import (
    WellKnownConfigurationCacheResult,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)

ISSUER = "https://issuer.example.com"
USERINFO_URL = f"{ISSUER}/userinfo"
COLLECTION = "oidc-user-info-cache"
KEY = "oidc-userinfo-scopes:client-a:user-1|v1"


def _auth_config(
    *,
    provider: str = "PROVIDER_A",
    issuer: str | None = ISSUER,
    client_id: str = "client-a",
) -> AuthConfig:
    return AuthConfig(
        auth_provider=provider,
        friendly_name=provider,
        audience="api://audience-a",
        issuer=issuer,
        client_id=client_id,
        client_secret=None,
        well_known_uri=f"{issuer or ISSUER}/.well-known/openid-configuration",
        scope="openid",
    )


def _token(*, claims: dict[str, Any] | None = None, raw: str = "raw-token") -> Token:
    default = {"sub": "user-1", "client_id": "client-a", "iss": ISSUER}
    return Token(token=raw, claims=default if claims is None else claims)


class _WriteFailingStore(MemoryStore):
    @override
    async def put(self, *args: Any, **kwargs: Any) -> None:
        raise ConnectionError("mongo down")


class _ReadFailingStore(MemoryStore):
    @override
    async def get(self, *args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("mongo down")


class _Fixture:
    def __init__(
        self,
        *,
        userinfo: httpx.Response | None = None,
        endpoint: str | None = USERINFO_URL,
        store: MemoryStore | None = None,
    ) -> None:
        self.requests: list[httpx.Request] = []
        self.userinfo = userinfo or httpx.Response(200, json={"scope": "access/*.* team/admins"})
        self.store = store or MemoryStore()
        self.configs = [_auth_config()]

        reader = MagicMock(spec=AuthConfigReader)
        reader.get_auth_configs_for_all_auth_providers.side_effect = lambda: self.configs
        reader.get_provider_for_client_id.return_value = "PROVIDER_A"
        reader.get_config_for_auth_provider.return_value = self.configs[0]
        self.reader = reader

        well_known = MagicMock(spec=WellKnownConfigurationManager)
        well_known.get_async = AsyncMock(
            return_value=(
                WellKnownConfigurationCacheResult(
                    well_known_uri="x",
                    well_known_config={"userinfo_endpoint": endpoint},
                    client_key_set=None,
                )
                if endpoint
                else None
            )
        )
        self.well_known = well_known

    def _handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.userinfo

    def manager(self, **overrides: Any) -> OidcUserInfoManager:
        kwargs: dict[str, Any] = {
            "auth_config_reader": self.reader,
            "well_known_configuration_manager": self.well_known,
            "store": self.store,
            "cache_collection": COLLECTION,
            "cache_ttl_seconds": 60,
            "fetch_timeout_seconds": 5,
            "transport": httpx.MockTransport(self._handler),
        }
        kwargs.update(overrides)
        return OidcUserInfoManager(**kwargs)


class TestBuildScopes:
    def test_reads_only_scope_and_scp_by_default(self) -> None:
        scopes = (
            _Fixture()
            .manager()
            .build_scopes(
                claims={
                    "scope": "a/*.* b/*.write",
                    "scp": ["openid", "a/*.*"],
                    "groups": ["/okta/team/admins"],
                    "custom:scope": "ignored",
                }
            )
        )
        assert scopes == ["a/*.*", "b/*.write", "openid"]

    def test_commas_separate_like_spaces(self) -> None:
        assert _Fixture().manager().build_scopes(claims={"scope": "a,b c", "scp": ["d,e"]}) == [
            "a",
            "b",
            "c",
            "d",
            "e",
        ]

    def test_group_claims_are_taken_whole_by_default(self) -> None:
        manager = _Fixture().manager(group_claims=["groups"])
        assert manager.build_scopes(claims={"groups": ["/okta/team/admins", "solo"]}) == [
            "/okta/team/admins",
            "solo",
        ]

    def test_scp_as_string(self) -> None:
        assert _Fixture().manager().build_scopes(claims={"scp": "one two"}) == [
            "one",
            "two",
        ]

    def test_ignores_non_string_and_malformed_claims(self) -> None:
        manager = _Fixture().manager()
        manager = _Fixture().manager(group_claims=["groups"])
        assert manager.build_scopes(claims={"scope": 3, "groups": [1, None, ""]}) == []
        assert manager.build_scopes(claims={"groups": {"a": 1}}) == []

    def test_configured_scope_and_group_claims(self) -> None:
        manager = _Fixture().manager(scope_claims=["custom:scope"], group_claims=["cognito:groups"])
        scopes = manager.build_scopes(
            claims={
                "custom:scope": "x y",
                "cognito:groups": ["/okta/team/admins"],
                "groups": ["ignored"],
            }
        )
        assert scopes == ["x", "y", "/okta/team/admins"]

    def test_remove_prefixes_first_match_wins(self) -> None:
        manager = _Fixture().manager(scope_remove_prefixes=["fhir/prod/", "fhir/"])
        assert manager.build_scopes(claims={"scope": "fhir/prod/Patient.read fhir/Obs.read Other"}) == [
            "Patient.read",
            "Obs.read",
            "Other",
        ]


class TestBuildCacheKey:
    def test_includes_client_id_subject_and_version(self) -> None:
        assert OidcUserInfoManager.build_cache_key(client_id="client-a", subject="user-1") == KEY

    def test_omits_missing_client_id(self) -> None:
        assert OidcUserInfoManager.build_cache_key(client_id=None, subject="user-1") == "oidc-userinfo-scopes:user-1|v1"

    @pytest.mark.parametrize("subject", [None, ""])
    def test_no_subject_yields_no_key(self, subject: str | None) -> None:
        assert OidcUserInfoManager.build_cache_key(client_id="client-a", subject=subject) is None


class TestResolveAuthConfig:
    def test_exact_issuer_match(self) -> None:
        fx = _Fixture()
        other = _auth_config(provider="OTHER", issuer="https://other.example.com", client_id="client-b")
        fx.configs[:] = [other, fx.configs[0]]
        assert fx.manager().resolve_auth_config(access_token=_token()).auth_provider == "PROVIDER_A"

    def test_issuer_contained_in_well_known_uri(self) -> None:
        fx = _Fixture()
        fx.configs[:] = [_auth_config(provider="BY_URI", issuer=None, client_id="client-b")]
        token = _token(claims={"sub": "u", "iss": ISSUER})
        assert fx.manager().resolve_auth_config(access_token=token).auth_provider == "BY_URI"

    def test_issuer_is_not_matched_as_a_bare_substring_of_another_host(self) -> None:
        fx = _Fixture()
        lookalike = _auth_config(provider="LOOKALIKE", issuer=None, client_id="client-b")
        lookalike.well_known_uri = "https://issuer.example.com.evil.test/.well-known/openid-configuration"
        fx.configs[:] = [lookalike]
        fx.reader.get_provider_for_client_id.return_value = None
        with pytest.raises(ValueError, match="No auth provider matches"):
            fx.manager().resolve_auth_config(access_token=_token())

    def test_falls_back_to_client_id(self) -> None:
        fx = _Fixture()
        fx.configs[:] = [_auth_config(provider="OTHER", issuer="https://other.example.com")]
        fx.reader.get_config_for_auth_provider.return_value = _auth_config(provider="BY_CLIENT")
        token = _token(
            claims={
                "sub": "u",
                "client_id": "client-a",
                "iss": "https://unknown.example.com",
            }
        )
        assert fx.manager().resolve_auth_config(access_token=token).auth_provider == "BY_CLIENT"

    def test_no_match_raises_instead_of_using_first_provider(self) -> None:
        fx = _Fixture()
        fx.reader.get_provider_for_client_id.return_value = None
        token = _token(claims={"sub": "u", "iss": "https://unknown.example.com"})
        with pytest.raises(ValueError, match="No auth provider matches"):
            fx.manager().resolve_auth_config(access_token=token)


@pytest.mark.asyncio
class TestGetUserInfo:
    async def test_sends_bearer_token_and_returns_json(self) -> None:
        fx = _Fixture()
        info = await fx.manager().get_user_info_async(access_token=_token())
        assert info["scope"] == "access/*.* team/admins"
        assert fx.requests[0].headers["Authorization"] == "Bearer raw-token"
        assert str(fx.requests[0].url) == USERINFO_URL

    async def test_missing_well_known_raises(self) -> None:
        with pytest.raises(ValueError, match="Well-known configuration"):
            await _Fixture(endpoint=None).manager().get_user_info_async(access_token=_token())

    async def test_missing_userinfo_endpoint_raises(self) -> None:
        fx = _Fixture()
        fx.well_known.get_async = AsyncMock(
            return_value=WellKnownConfigurationCacheResult(
                well_known_uri="x",
                well_known_config={"issuer": "x"},
                client_key_set=None,
            )
        )
        with pytest.raises(ValueError, match="Userinfo endpoint"):
            await fx.manager().get_user_info_async(access_token=_token())

    async def test_http_error_raises(self) -> None:
        fx = _Fixture(userinfo=httpx.Response(500))
        with pytest.raises(httpx.HTTPStatusError):
            await fx.manager().get_user_info_async(access_token=_token())

    async def test_non_object_response_raises(self) -> None:
        fx = _Fixture(userinfo=httpx.Response(200, json=["nope"]))
        with pytest.raises(ValueError, match="valid JSON object"):
            await fx.manager().get_user_info_async(access_token=_token())


@pytest.mark.asyncio
class TestGetScopes:
    async def test_miss_fetches_and_persists_only_userinfo_scopes(self) -> None:
        fx = _Fixture()
        token = _token(
            claims={
                "sub": "user-1",
                "client_id": "client-a",
                "iss": ISSUER,
                "scp": ["openid"],
            }
        )
        scopes = await fx.manager().get_scopes_from_user_info_async(access_token=token)
        assert scopes == ["openid", "access/*.*", "team/admins"]
        assert await fx.store.get(KEY, collection=COLLECTION) == {
            "cache_version": 1,
            "client_id": None,
            "value": {"scopes": ["access/*.*", "team/admins"]},
        }

    async def test_hit_skips_userinfo_but_rederives_token_scopes(self) -> None:
        fx = _Fixture()
        manager = fx.manager()
        await manager.get_scopes_from_user_info_async(access_token=_token())
        narrower = _token(
            raw="a-new-token",
            claims={
                "sub": "user-1",
                "client_id": "client-a",
                "iss": ISSUER,
                "scp": ["profile"],
            },
        )
        assert await manager.get_scopes_from_user_info_async(access_token=narrower) == [
            "profile",
            "access/*.*",
            "team/admins",
        ]
        assert len(fx.requests) == 1

    async def test_accepts_entries_with_extra_fields(self) -> None:
        fx = _Fixture()
        await fx.store.put(
            KEY,
            {
                "cache_version": 1,
                "client_id": None,
                "value": {"scopes": ["x/y"]},
                "extra": 1,
            },
            collection=COLLECTION,
        )
        assert await fx.manager().get_scopes_from_user_info_async(access_token=_token()) == ["x/y"]
        assert fx.requests == []

    @pytest.mark.parametrize(
        "raw",
        [
            {"unexpected": "shape"},
            {"cache_version": 1, "client_id": None, "value": {}},
            {"cache_version": 1, "client_id": None, "value": {"scopes": "a"}},
            {"cache_version": 1, "client_id": None, "value": {"scopes": [1]}},
        ],
    )
    async def test_invalid_entry_raises_without_the_subject_in_the_message(self, raw: dict[str, Any]) -> None:
        fx = _Fixture()
        await fx.store.put(KEY, raw, collection=COLLECTION)
        with pytest.raises(ValueError, match="invalid shape") as error:
            await fx.manager().get_scopes_from_user_info_async(access_token=_token())
        assert "user-1" not in str(error.value)

    async def test_other_cache_version_is_a_miss(self) -> None:
        fx = _Fixture()
        await fx.store.put(
            "oidc-userinfo-scopes:client-a:user-1|v0",
            {"cache_version": 0, "client_id": None, "value": {"scopes": ["stale"]}},
            collection=COLLECTION,
        )
        assert "access/*.*" in await fx.manager().get_scopes_from_user_info_async(access_token=_token())

    async def test_token_without_subject_is_not_cached(self) -> None:
        fx = _Fixture()
        manager = fx.manager()
        token = _token(claims={"client_id": "client-a", "iss": ISSUER})
        await manager.get_scopes_from_user_info_async(access_token=token)
        await manager.get_scopes_from_user_info_async(access_token=token)
        assert len(fx.requests) == 2
        assert await fx.store.keys(collection=COLLECTION) == []

    async def test_empty_userinfo_scopes_are_not_cached(self) -> None:
        fx = _Fixture(userinfo=httpx.Response(200, json={"name": "no scopes"}))
        assert await fx.manager().get_scopes_from_user_info_async(access_token=_token()) == []
        assert await fx.store.keys(collection=COLLECTION) == []

    async def test_write_failure_is_swallowed(self) -> None:
        fx = _Fixture(store=_WriteFailingStore())
        assert await fx.manager().get_scopes_from_user_info_async(access_token=_token()) == [
            "access/*.*",
            "team/admins",
        ]

    async def test_read_failure_is_raised_for_the_caller_to_handle(self) -> None:
        fx = _Fixture(store=_ReadFailingStore())
        with pytest.raises(ConnectionError):
            await fx.manager().get_scopes_from_user_info_async(access_token=_token())

    async def test_unmatched_provider_never_calls_userinfo(self) -> None:
        fx = _Fixture()
        fx.reader.get_provider_for_client_id.return_value = None
        token = _token(
            claims={
                "sub": "u",
                "client_id": "client-x",
                "iss": "https://unknown.example.com",
            }
        )
        with pytest.raises(ValueError, match="No auth provider matches"):
            await fx.manager().get_scopes_from_user_info_async(access_token=token)
        assert fx.requests == []
