import os
import uuid
import pytest
import httpx
import respx
from unittest.mock import patch

from typing import Any, Dict, List, Optional, override

from oidcauthlib.auth.auth_manager import AuthManager
from oidcauthlib.auth.auth_helper import AuthHelper
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.exceptions.authorization_needed_exception import (
    AuthorizationNeededException,
)
from oidcauthlib.auth.cache.oauth_mongo_cache import OAuthMongoCache
from oidcauthlib.auth.cache.oauth_memory_cache import OAuthMemoryCache
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache_result import (
    WellKnownConfigurationCacheResult,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)
from oidcauthlib.auth.repository.repository_factory import RepositoryFactory
from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)


class FakeEnvironmentVariables(AbstractEnvironmentVariables):
    """Test helper providing environment values without external set_env calls."""

    def __init__(
        self,
        *,
        oauth_cache: str = "memory",
        auth_providers: Optional[List[str]] = None,
        redirect_uri: str = "https://example.com/callback",
        client_id: str = "client-id-1",
        client_secret: str = "client-secret-1",
        well_known_uri: str = "https://auth.example.com/.well-known/openid-configuration",
        audience: str = "audience-1",
        friendly_name: str = "Provider One",
        mongo_db_auth_cache_collection_name: Optional[str] = "auth_cache",
    ) -> None:
        super().__init__()  # ABC init (no-op) to satisfy linter
        self._oauth_cache = oauth_cache
        self._auth_providers = auth_providers or ["PROVIDER1"]
        self._mongo_db_auth_cache_collection_name = mongo_db_auth_cache_collection_name
        # Populate required process environment variables so AuthConfigReader works
        os.environ["AUTH_REDIRECT_URI"] = redirect_uri
        for provider in self._auth_providers:
            upper = provider.upper()
            os.environ[f"AUTH_CLIENT_ID_{upper}"] = client_id
            os.environ[f"AUTH_CLIENT_SECRET_{upper}"] = client_secret
            os.environ[f"AUTH_WELL_KNOWN_URI_{upper}"] = well_known_uri
            os.environ[f"AUTH_AUDIENCE_{upper}"] = audience
            os.environ[f"AUTH_FRIENDLY_NAME_{upper}"] = friendly_name

    @property
    @override
    def oauth_cache(self) -> str:
        return self._oauth_cache

    @property
    @override
    def mongo_uri(self) -> Optional[str]:
        return "mongodb://localhost:27017"

    @property
    @override
    def mongo_db_name(self) -> Optional[str]:
        return "testdb"

    @property
    @override
    def mongo_db_username(self) -> Optional[str]:
        return None

    @property
    @override
    def mongo_db_password(self) -> Optional[str]:
        return None

    @property
    @override
    def mongo_db_auth_cache_collection_name(self) -> Optional[str]:
        return self._mongo_db_auth_cache_collection_name

    @property
    @override
    def mongo_db_cache_disable_delete(self) -> Optional[bool]:
        return False

    @property
    @override
    def auth_providers(self) -> Optional[List[str]]:
        return self._auth_providers

    @property
    @override
    def oauth_referring_email(self) -> Optional[str]:
        return None

    @property
    @override
    def oauth_referring_subject(self) -> Optional[str]:
        return None

    @property
    @override
    def auth_redirect_uri(self) -> Optional[str]:
        return os.getenv("AUTH_REDIRECT_URI")


class DummyTokenReader(TokenReader):
    """Minimal subclass of TokenReader for type compatibility in tests."""

    # noinspection PyMissingConstructor
    def __init__(self) -> None:  # skip base init; tests do not use token_reader methods
        pass


class DummyWellKnownConfigurationManager(WellKnownConfigurationManager):
    """Simplified WellKnownConfigurationManager returning static metadata."""

    # noinspection PyMissingConstructor
    def __init__(
        self, *, auth_config_reader: AuthConfigReader, metadata: Dict[str, Any] | None
    ) -> None:
        # Bypass base init; only need auth configs and get_async behavior
        self._auth_configs = (
            auth_config_reader.get_auth_configs_for_all_auth_providers()
        )
        self._metadata = metadata

    @override
    async def get_async(
        self, auth_config: AuthConfig
    ) -> WellKnownConfigurationCacheResult | None:
        well_known_uri = auth_config.well_known_uri
        assert well_known_uri is not None
        return WellKnownConfigurationCacheResult(
            well_known_uri=well_known_uri,
            well_known_config=self._metadata,
            client_key_set=None,
        )


@pytest.fixture
def environment_memory() -> FakeEnvironmentVariables:
    return FakeEnvironmentVariables(oauth_cache="memory")


@pytest.fixture
def environment_mongo() -> FakeEnvironmentVariables:
    return FakeEnvironmentVariables(oauth_cache="mongo")


@pytest.fixture
def auth_config_reader(
    environment_memory: FakeEnvironmentVariables,
) -> AuthConfigReader:
    return AuthConfigReader(environment_variables=environment_memory)


@pytest.fixture
def auth_config_reader_mongo(
    environment_mongo: FakeEnvironmentVariables,
) -> AuthConfigReader:
    return AuthConfigReader(environment_variables=environment_mongo)


@pytest.fixture
def token_reader() -> DummyTokenReader:
    return DummyTokenReader()


@pytest.fixture
def well_known_manager(
    auth_config_reader: AuthConfigReader,
) -> DummyWellKnownConfigurationManager:
    return DummyWellKnownConfigurationManager(
        auth_config_reader=auth_config_reader,
        metadata={"issuer": "https://auth.example.com"},
    )


# ---------------- Tests -----------------
@pytest.mark.asyncio
async def test_init_memory_cache(
    environment_memory: FakeEnvironmentVariables,
    auth_config_reader: AuthConfigReader,
    token_reader: DummyTokenReader,
    well_known_manager: DummyWellKnownConfigurationManager,
) -> None:
    auth_manager = AuthManager(
        environment_variables=environment_memory,
        auth_config_reader=auth_config_reader,
        token_reader=token_reader,
        well_known_configuration_manager=well_known_manager,
    )
    assert isinstance(auth_manager.cache, OAuthMemoryCache)
    assert auth_manager.redirect_uri == "https://example.com/callback"


@pytest.mark.asyncio
async def test_init_mongo_cache(
    environment_mongo: FakeEnvironmentVariables,
    auth_config_reader_mongo: AuthConfigReader,
    token_reader: DummyTokenReader,
    well_known_manager: DummyWellKnownConfigurationManager,
) -> None:
    with patch.object(RepositoryFactory, "get_repository", return_value=FakeRepo()):
        auth_manager = AuthManager(
            environment_variables=environment_mongo,
            auth_config_reader=auth_config_reader_mongo,
            token_reader=token_reader,
            well_known_configuration_manager=well_known_manager,
        )
        assert isinstance(auth_manager.cache, OAuthMongoCache)


class FakeRepo:
    async def find_by_fields(self, *args: Any, **kwargs: Any) -> Any | None:
        return None

    async def insert_or_update(self, *args: Any, **kwargs: Any) -> Any | None:
        return None

    async def delete_by_id(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def update_by_id(self, *args: Any, **kwargs: Any) -> Any | None:
        return None

    async def insert(self, *args: Any, **kwargs: Any) -> uuid.UUID:
        return uuid.uuid4()


@pytest.mark.asyncio
async def test_ensure_initialized_and_create_client(
    environment_memory: FakeEnvironmentVariables,
    auth_config_reader: AuthConfigReader,
    token_reader: DummyTokenReader,
    well_known_manager: DummyWellKnownConfigurationManager,
) -> None:
    auth_manager = AuthManager(
        environment_variables=environment_memory,
        auth_config_reader=auth_config_reader,
        token_reader=token_reader,
        well_known_configuration_manager=well_known_manager,
    )
    client = await auth_manager.create_oauth_client(name="PROVIDER1")
    assert client is not None
    assert client.client_id == "client-id-1"


@pytest.mark.asyncio
@respx.mock
async def test_create_authorization_url(
    environment_memory: FakeEnvironmentVariables,
    auth_config_reader: AuthConfigReader,
    token_reader: DummyTokenReader,
    well_known_manager: DummyWellKnownConfigurationManager,
) -> None:
    # Mock the OIDC discovery document so the client doesn't perform real HTTP requests
    # Use the provider's well-known URI from env (same as FakeEnvironmentVariables sets)
    well_known_uri = "https://auth.example.com/.well-known/openid-configuration"
    respx.get(well_known_uri).respond(
        200,
        json={
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/oauth/authorize",
            "token_endpoint": "https://auth.example.com/oauth/token",
        },
    )
    with patch("uuid.uuid4", return_value=uuid.UUID(int=0)):
        auth_manager = AuthManager(
            environment_variables=environment_memory,
            auth_config_reader=auth_config_reader,
            token_reader=token_reader,
            well_known_configuration_manager=well_known_manager,
        )
        url = await auth_manager.create_authorization_url(
            auth_provider="PROVIDER1",
            redirect_uri="https://example.com/callback",
            url="https://tool.example.com",
            referring_email="user@example.com",
            referring_subject="sub-123",
        )
        assert "response_type" in url
        parsed = httpx.URL(url)
        state = parsed.params.get("state")
        assert state is not None
        decoded = AuthHelper.decode_state(state)
        assert decoded["auth_provider"] == "PROVIDER1"
        assert decoded["referring_email"] == "user@example.com"
        assert decoded["url"] == "https://tool.example.com"
        assert decoded["request_id"] == "00000000000000000000000000000000"


@pytest.mark.asyncio
async def test_get_auth_config_for_auth_provider_case_insensitive(
    environment_memory: FakeEnvironmentVariables,
    auth_config_reader: AuthConfigReader,
    token_reader: DummyTokenReader,
    well_known_manager: DummyWellKnownConfigurationManager,
) -> None:
    auth_manager = AuthManager(
        environment_variables=environment_memory,
        auth_config_reader=auth_config_reader,
        token_reader=token_reader,
        well_known_configuration_manager=well_known_manager,
    )
    cfg_upper = auth_manager.get_auth_config_for_auth_provider(
        auth_provider="PROVIDER1"
    )
    cfg_lower = auth_manager.get_auth_config_for_auth_provider(
        auth_provider="provider1"
    )
    assert cfg_upper is not None and cfg_lower is not None
    assert cfg_upper.client_id == cfg_lower.client_id == "client-id-1"


@pytest.mark.asyncio
async def test_get_auth_config_for_auth_provider_not_found(
    environment_memory: FakeEnvironmentVariables,
    auth_config_reader: AuthConfigReader,
    token_reader: DummyTokenReader,
    well_known_manager: DummyWellKnownConfigurationManager,
) -> None:
    auth_manager = AuthManager(
        environment_variables=environment_memory,
        auth_config_reader=auth_config_reader,
        token_reader=token_reader,
        well_known_configuration_manager=well_known_manager,
    )
    assert (
        auth_manager.get_auth_config_for_auth_provider(auth_provider="UNKNOWN") is None
    )


@pytest.mark.asyncio
@respx.mock
async def test_login_and_get_token_with_username_password_success_discovery() -> None:
    auth_config = AuthConfig(
        auth_provider="PROVIDER1",
        friendly_name="Provider One",
        audience="audience-1",
        issuer="https://issuer.example.com",
        client_id="client-id-1",
        client_secret="client-secret-1",
        well_known_uri="https://auth.example.com/.well-known/openid-configuration",
        scope="openid profile email",
    )
    respx.get(auth_config.well_known_uri).respond(
        200, json={"token_endpoint": "https://auth.example.com/oauth/token"}
    )
    respx.post("https://auth.example.com/oauth/token").respond(
        200, json={"access_token": "abc123"}
    )
    token = await AuthManager.login_and_get_token_with_username_password_async(
        auth_config=auth_config,
        username="user",
        password="pass",
    )
    assert token == "abc123"


@pytest.mark.asyncio
@respx.mock
async def test_login_and_get_token_with_username_password_success_issuer_fallback() -> (
    None
):
    auth_config = AuthConfig(
        auth_provider="PROVIDER1",
        friendly_name="Provider One",
        audience="audience-1",
        issuer="https://issuer.example.com/",
        client_id="client-id-1",
        client_secret="client-secret-1",
        well_known_uri=None,
        scope="openid profile email",
    )
    token_endpoint = "https://issuer.example.com/protocol/openid-connect/token"
    respx.post(token_endpoint).respond(200, json={"access_token": "xyz789"})
    token = await AuthManager.login_and_get_token_with_username_password_async(
        auth_config=auth_config,
        username="user",
        password="pass",
    )
    assert token == "xyz789"


@pytest.mark.asyncio
@respx.mock
async def test_login_and_get_token_missing_token_endpoint_raise() -> None:
    auth_config = AuthConfig(
        auth_provider="PROVIDER1",
        friendly_name="Provider One",
        audience="audience-1",
        issuer=None,
        client_id="client-id-1",
        client_secret="client-secret-1",
        well_known_uri="https://auth.example.com/.well-known/openid-configuration",
        scope="openid profile email",
    )
    respx.get(auth_config.well_known_uri).respond(200, json={})
    with pytest.raises(AuthorizationNeededException) as exc:
        await AuthManager.login_and_get_token_with_username_password_async(
            auth_config=auth_config,
            username="user",
            password="pass",
        )
    assert "No token endpoint" in str(exc.value)


@pytest.mark.asyncio
@respx.mock
async def test_login_and_get_token_request_failure() -> None:
    auth_config = AuthConfig(
        auth_provider="PROVIDER1",
        friendly_name="Provider One",
        audience="audience-1",
        issuer="https://issuer.example.com",
        client_id="client-id-1",
        client_secret="client-secret-1",
        well_known_uri=None,
        scope="openid profile email",
    )
    token_endpoint = "https://issuer.example.com/protocol/openid-connect/token"
    respx.post(token_endpoint).respond(400, json={"error": "invalid_grant"})
    with pytest.raises(AuthorizationNeededException) as exc:
        await AuthManager.login_and_get_token_with_username_password_async(
            auth_config=auth_config,
            username="user",
            password="pass",
        )
    assert "Token request failed" in str(exc.value)


@pytest.mark.asyncio
@respx.mock
async def test_login_and_get_token_missing_access_token_via_token_name_override() -> (
    None
):
    auth_config = AuthConfig(
        auth_provider="PROVIDER1",
        friendly_name="Provider One",
        audience="audience-1",
        issuer="https://issuer.example.com",
        client_id="client-id-1",
        client_secret="client-secret-1",
        well_known_uri=None,
        scope="openid profile email",
    )
    token_endpoint = "https://issuer.example.com/protocol/openid-connect/token"
    respx.post(token_endpoint).respond(200, json={"access_token": "abc123"})
    with pytest.raises(AuthorizationNeededException) as exc:
        await AuthManager.login_and_get_token_with_username_password_async(
            auth_config=auth_config,
            username="user",
            password="pass",
            token_name="non_existent",
        )
    assert "No access token" in str(exc.value)


@respx.mock
def test_wait_till_well_known_configuration_available_success() -> None:
    auth_config = AuthConfig(
        auth_provider="PROVIDER1",
        friendly_name="Provider One",
        audience="audience-1",
        issuer="https://issuer.example.com",
        client_id="client-id-1",
        client_secret="client-secret-1",
        well_known_uri="https://auth.example.com/.well-known/openid-configuration",
        scope="openid profile email",
    )
    statuses: List[int] = [503, 200]

    def handler(request: httpx.Request) -> httpx.Response:
        status = statuses.pop(0)
        return httpx.Response(status, json={"issuer": "x"})

    respx.get(auth_config.well_known_uri).mock(side_effect=handler)
    with patch("time.sleep", return_value=None):
        AuthManager.wait_till_well_known_configuration_available(
            auth_config=auth_config, timeout_seconds=3
        )


@respx.mock
def test_wait_till_well_known_configuration_available_timeout() -> None:
    auth_config = AuthConfig(
        auth_provider="PROVIDER1",
        friendly_name="Provider One",
        audience="audience-1",
        issuer="https://issuer.example.com",
        client_id="client-id-1",
        client_secret="client-secret-1",
        well_known_uri="https://auth.example.com/.well-known/openid-configuration",
        scope="openid profile email",
    )
    respx.get(auth_config.well_known_uri).respond(503)
    with patch("time.sleep", return_value=None):
        with pytest.raises(TimeoutError):
            AuthManager.wait_till_well_known_configuration_available(
                auth_config=auth_config, timeout_seconds=1
            )
