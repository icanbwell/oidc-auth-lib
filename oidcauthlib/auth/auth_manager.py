import logging
import os
import time
import uuid
from typing import Any, Dict, cast, List

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.starlette_client import OAuth, StarletteOAuth2App

from oidcauthlib.auth.auth_helper import AuthHelper
from oidcauthlib.auth.cache.oauth_cache import OAuthCache
from oidcauthlib.auth.cache.oauth_memory_cache import (
    OAuthMemoryCache,
)
from oidcauthlib.auth.cache.oauth_mongo_cache import OAuthMongoCache
from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import (
    AuthConfigReader,
)
from oidcauthlib.auth.exceptions.authorization_needed_exception import (
    AuthorizationNeededException,
)
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)
from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS
from oidcauthlib.utilities.logger.logging_transport import (
    LoggingTransport,
)

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class AuthManager:
    """
    AuthManager is responsible for managing authentication using OIDC PKCE.

    It initializes the OAuth client with the necessary configuration and provides methods
    to create authorization URLs and handle callback responses.
    """

    def __init__(
        self,
        *,
        environment_variables: AbstractEnvironmentVariables,
        auth_config_reader: AuthConfigReader,
        token_reader: TokenReader,
        well_known_configuration_manager: WellKnownConfigurationManager,
    ) -> None:
        """
        Initialize the AuthManager with the necessary configuration for OIDC PKCE.
        It sets up the OAuth cache, reads environment variables for the OIDC provider,
        and configures the OAuth client.
        The environment variables required are:
        - MONGO_URL: The connection string for the MongoDB database.
        - MONGO_DB_NAME: The name of the MongoDB database.
        - MONGO_DB_TOKEN_COLLECTION_NAME: The name of the MongoDB collection for tokens.
        It also initializes the OAuth cache based on the OAUTH_CACHE environment variable,
        which can be set to "memory" for in-memory caching or "mongo" for MongoDB caching.
        If the OAUTH_CACHE environment variable is not set, it defaults to "memory".

        Args:
            environment_variables (AbstractEnvironmentVariables): The environment variables for the application.
            auth_config_reader (AuthConfigReader): The reader for authentication configurations.
            token_reader (TokenReader): The reader for tokens.
        """
        self.environment_variables: AbstractEnvironmentVariables = environment_variables
        if self.environment_variables is None:
            raise ValueError("environment_variables must not be None")
        if not isinstance(self.environment_variables, AbstractEnvironmentVariables):
            raise TypeError(
                "environment_variables must be an instance of EnvironmentVariables"
            )

        self.auth_config_reader: AuthConfigReader = auth_config_reader
        if self.auth_config_reader is None:
            raise ValueError("auth_config_reader must not be None")
        if not isinstance(self.auth_config_reader, AuthConfigReader):
            raise TypeError(
                "auth_config_reader must be an instance of AuthConfigReader"
            )

        self.token_reader: TokenReader = token_reader
        if self.token_reader is None:
            raise ValueError("token_reader must not be None")
        if not isinstance(self.token_reader, TokenReader):
            raise TypeError("token_reader must be an instance of TokenReader")

        self.well_known_configuration_manager: WellKnownConfigurationManager = (
            well_known_configuration_manager
        )
        if self.well_known_configuration_manager is None:
            raise ValueError("well_known_configuration_manager must not be None")
        if not isinstance(
            self.well_known_configuration_manager, WellKnownConfigurationManager
        ):
            raise TypeError(
                "well_known_configuration_manager must be an instance of WellKnownConfigurationManager"
            )
        oauth_cache_type = environment_variables.oauth_cache
        self.cache: OAuthCache = (
            OAuthMemoryCache()
            if oauth_cache_type == "memory"
            else OAuthMongoCache(environment_variables=environment_variables)
        )

        logger.debug(
            f"Initializing AuthManager with cache type {type(self.cache)} cache id: {self.cache.id}"
        )
        # OIDC PKCE setup
        self.redirect_uri = os.getenv("AUTH_REDIRECT_URI")
        if self.redirect_uri is None:
            raise ValueError("AUTH_REDIRECT_URI environment variable must be set")
        # https://docs.authlib.org/en/latest/client/frameworks.html#frameworks-clients
        self._oauth: OAuth = OAuth(cache=self.cache)  # type: ignore[no-untyped-call]
        # read AUTH_PROVIDERS comma separated list from the environment variable and register the OIDC provider for each provider
        self.auth_configs: List[AuthConfig] = (
            self.auth_config_reader.get_auth_configs_for_all_auth_providers()
        )

    async def ensure_initialized_async(self) -> None:
        auth_config: AuthConfig
        for auth_config in self.auth_configs:
            server_metadata: (
                dict[str, Any] | None
            ) = await self.well_known_configuration_manager.get_async(
                auth_config=auth_config
            )
            logger.debug(
                f"Registering OAuth client for auth provider {auth_config.auth_provider}"
                + (
                    f" with well-known configuration: {server_metadata}"
                    if server_metadata is not None
                    else f" from {auth_config.well_known_uri}"
                )
            )
            self._oauth.register(
                name=auth_config.auth_provider.lower(),
                client_id=auth_config.client_id,
                client_secret=auth_config.client_secret,
                server_metadata_url=auth_config.well_known_uri,
                # server_metadata_url=auth_config.well_known_uri
                # if server_metadata is None
                # else None,
                # server_metadata=server_metadata,
                client_kwargs={
                    "scope": "openid email",
                    "code_challenge_method": "S256",
                    "transport": LoggingTransport(httpx.AsyncHTTPTransport()),
                },
            )

    async def create_authorization_url(
        self,
        *,
        auth_provider: str,
        client_id: str,
        redirect_uri: str,
        audience: str,
        issuer: str,
        url: str | None,
        referring_email: str | None,
        referring_subject: str | None,
    ) -> str:
        """
        Create the authorization URL for the OIDC provider.

        This method generates the authorization URL with the necessary parameters,
        including the redirect URI and state. The state is encoded to include the tool name,
        which is used to identify the tool that initiated the authentication process.
        Args:
            auth_provider (str): The name of the OIDC provider.
            client_id (str): The client ID of the OIDC provider.
            redirect_uri (str): The redirect URI to which the OIDC provider will send the user
                after authentication.
            audience (str): The audience we need to get a token for.
            issuer (str): The issuer of the OIDC provider, used to validate the token.
            url (str): The URL of the tool that has requested this.
            referring_email (str): The email of the user who initiated the request.
            referring_subject (str): The subject of the user who initiated the request.
        Returns:
            str: The authorization URL to redirect the user to for authentication.
        """
        # default to first audience
        client: StarletteOAuth2App = await self.create_oauth_client(name=auth_provider)
        if client is None:
            raise ValueError(f"Client for audience {audience} not found")
        state_content: Dict[str, str | None] = {
            "auth_provider": auth_provider,
            "referring_email": referring_email,
            "referring_subject": referring_subject,
            "url": url,  # the URL of the tool that has requested this
            # include a unique request ID so we don't get cache for another request
            # This will create a unique state for each request
            # the callback will use this state to find the correct token
            "request_id": uuid.uuid4().hex,
        }
        # convert state_content to a string
        state: str = AuthHelper.encode_state(state_content)

        logger.debug(
            f"Creating authorization URL for audience {audience} with state {state_content} and encoded state {state}"
        )

        rv: Dict[str, Any] = await client.create_authorization_url(  # type: ignore[no-untyped-call]
            redirect_uri=redirect_uri, state=state
        )
        logger.debug(f"Authorization URL created: {rv}")
        # request is only needed if we are using the session to store the state
        await client.save_authorize_data(request=None, redirect_uri=redirect_uri, **rv)  # type: ignore[no-untyped-call]
        return cast(str, rv["url"])

    async def create_oauth_client(self, *, name: str) -> StarletteOAuth2App:
        if not name:
            raise ValueError("name must not be empty")
        await self.ensure_initialized_async()
        return cast(StarletteOAuth2App, self._oauth.create_client(name=name.lower()))  # type: ignore[no-untyped-call]

    @staticmethod
    async def login_and_get_token_with_username_password_async(
        *,
        auth_config: AuthConfig,
        username: str,
        password: str,
        audience: str | None = None,
        token_name: str = "access_token",
    ) -> str:
        """
        Logs in a user with the provided username and password, and retrieves an access token.

        Args:
            auth_config (AuthConfig): The authentication configuration.
            username (str): The username of the user.
            password (str): The password of the user.
            audience (str | None): The intended audience for the token. Optional.
            token_name (str): The name of the token to retrieve. Defaults to "access_token".

        Returns:
            str: The access token if login is successful.

        Raises:
            Exception: If login fails or token retrieval is unsuccessful.
        """

        # Discover token endpoint
        token_url = None
        if auth_config.well_known_uri:
            try:
                async with httpx.AsyncClient(timeout=5) as async_client:
                    resp = await async_client.get(auth_config.well_known_uri)
                resp.raise_for_status()
                token_url = resp.json().get("token_endpoint")
            except Exception as e:
                raise AuthorizationNeededException(
                    message=f"Failed to discover token endpoint: {e}"
                )
        if not token_url and auth_config.issuer:
            token_url = (
                auth_config.issuer.rstrip("/") + "/protocol/openid-connect/token"
            )
        if not token_url:
            raise AuthorizationNeededException(
                message="No token endpoint found in AuthConfig."
            )

        # Prepare OAuth2 client
        client_id = auth_config.client_id
        client_secret = auth_config.client_secret
        audience = audience or auth_config.audience
        client = AsyncOAuth2Client(client_id, client_secret, timeout=10)

        # Request token
        try:
            # This DOES return a coroutine
            # noinspection PyUnresolvedReferences
            token: Dict[str, Any] = await client.fetch_token(
                url=token_url,
                grant_type="password",
                username=username,
                password=password,
                scope="openid",
                audience=audience,
            )
            if not isinstance(token, dict):
                raise TypeError(f"Expected token to be a dict, got {type(token)}")

        except Exception as e:
            raise AuthorizationNeededException(message=f"Token request failed: {e}")

        access_token: str | None = token.get(token_name)
        if not access_token:
            raise AuthorizationNeededException(message="No access token returned.")

        return access_token

    def get_auth_config_for_auth_provider(
        self, *, auth_provider: str
    ) -> AuthConfig | None:
        if not auth_provider:
            raise ValueError("auth_provider must not be empty")
        for auth_config in self.auth_configs:
            if auth_config.auth_provider.lower() == auth_provider.lower():
                return auth_config
        return None

    @staticmethod
    def wait_till_well_known_configuration_available(
        *, auth_config: AuthConfig, timeout_seconds: int = 30
    ) -> None:
        """
        Wait until the well-known configuration is available for the given AuthConfig.

        This method repeatedly attempts to fetch the well-known configuration from the
        specified URL until it succeeds or the timeout is reached.

        Args:
            auth_config (AuthConfig): The authentication configuration containing the
                well-known URL.
            timeout_seconds (int): The maximum time to wait in seconds. Defaults to 30 seconds.
        Raises:
            TimeoutError: If the well-known configuration is not available within the timeout period.
        """
        if not auth_config.well_known_uri:
            raise ValueError("AuthConfig must have a well-known URI to wait for.")

        start_time = time.time()
        while True:
            try:
                with httpx.Client(timeout=5) as client:
                    resp = client.get(auth_config.well_known_uri)
                resp.raise_for_status()
                # Successfully fetched the configuration
                logger.info(
                    f"Well-known configuration is now available at {auth_config.well_known_uri}"
                )
                return
            except Exception as e:
                elapsed_time = time.time() - start_time
                if elapsed_time >= timeout_seconds:
                    raise TimeoutError(
                        f"Timed out waiting for well-known configuration at {auth_config.well_known_uri}"
                    ) from e
                logger.debug(
                    f"Well-known configuration not yet available, retrying... ({elapsed_time:.1f}s elapsed)"
                )
                time.sleep(2)  # Wait before retrying
