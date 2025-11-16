import logging
import os
import threading

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["INITIALIZATION"])


class AuthConfigReader:
    """
    A class to read authentication configurations from environment variables.
    """

    def __init__(self, *, environment_variables: AbstractEnvironmentVariables) -> None:
        """
        Initialize the AuthConfigReader with an EnvironmentVariables instance.
        Args:
            environment_variables (AbstractEnvironmentVariables): An instance of EnvironmentVariables to read auth configurations.
        """
        logger.debug("Initializing AuthConfigReader")
        self.environment_variables: AbstractEnvironmentVariables = environment_variables
        if self.environment_variables is None:
            logger.error(
                "AuthConfigReader initialization failed: environment_variables is None"
            )
            raise ValueError(
                "AuthConfigReader requires an EnvironmentVariables instance."
            )
        if not isinstance(self.environment_variables, AbstractEnvironmentVariables):
            logger.error(
                f"AuthConfigReader initialization failed: environment_variables is not an instance of AbstractEnvironmentVariables, got {type(environment_variables)}"
            )
            raise TypeError(
                "environment_variables must be an instance of EnvironmentVariables"
            )
        self._auth_configs: list[AuthConfig] | None = None
        # lock to protect first-time initialization of _auth_configs across threads
        self._lock: threading.Lock = threading.Lock()
        logger.info("AuthConfigReader initialized successfully")

    def get_auth_configs_for_all_auth_providers(self) -> list[AuthConfig]:
        """
        Get authentication configurations for all audiences.

        Returns:
            list[AuthConfig]: A list of AuthConfig instances for each audience.
        """
        # Fast path without locking if already initialized
        existing: list[AuthConfig] | None = self._auth_configs
        if existing is not None:
            logger.debug(
                f"Returning cached auth configs for {len(existing)} provider(s)"
                + f" ({', '.join(ac.auth_provider for ac in existing)})"
            )
            return existing
        # Double-checked locking to ensure only one thread performs initialization
        logger.debug("Initializing auth configs for all providers")
        with self._lock:
            if self._auth_configs is not None:
                logger.debug("Auth configs already initialized by another thread")
                return self._auth_configs
            auth_providers: list[str] | None = self.environment_variables.auth_providers
            if auth_providers is None:
                logger.error("auth_providers environment variable is not set")
                raise ValueError("auth_providers environment variable must be set")
            logger.info(f"Loading auth configs for providers: {auth_providers}")
            auth_configs: list[AuthConfig] = []
            for auth_provider in auth_providers:
                logger.debug(f"Reading config for auth provider: {auth_provider}")
                auth_config: AuthConfig | None = self.read_config_for_auth_provider(
                    auth_provider=auth_provider,
                )
                if auth_config is not None:
                    auth_configs.append(auth_config)
                    logger.debug(
                        f"Successfully loaded config for provider: {auth_provider}"
                    )
                else:
                    logger.warning(f"No config found for provider: {auth_provider}")
            # Assign atomically while still under lock
            self._auth_configs = auth_configs
            logger.info(
                f"Loaded {len(auth_configs)} auth config(s) successfully"
                + f" ({', '.join(ac.auth_provider for ac in auth_configs)})"
            )
            return auth_configs

    def get_config_for_auth_provider(self, *, auth_provider: str) -> AuthConfig | None:
        """
        Get the authentication configuration for a specific audience.

        Args:
            auth_provider (str): The audience for which to retrieve the configuration.
        Returns:
            AuthConfig | None: The authentication configuration if found, otherwise None.
        """
        logger.debug(f"Getting config for auth provider: {auth_provider}")
        for auth_config in self.get_auth_configs_for_all_auth_providers():
            if auth_config.auth_provider.lower() == auth_provider.lower():
                logger.debug(f"Found config for auth provider: {auth_provider}")
                return auth_config
        logger.warning(f"No config found for auth provider: {auth_provider}")
        return None

    # noinspection PyMethodMayBeStatic
    def read_config_for_auth_provider(self, *, auth_provider: str) -> AuthConfig | None:
        """
        Get the authentication configuration for a specific audience.

        Args:
            auth_provider (str): The audience for which to retrieve the configuration.

        Returns:
            AuthConfig | None: The authentication configuration if found, otherwise None.
        """
        logger.debug(f"Reading config for auth provider: {auth_provider}")
        if auth_provider is None:
            logger.error("auth_provider must not be None")
            raise ValueError("auth_provider must not be None")
        # environment variables are case-insensitive, but we standardize to upper case
        auth_provider_upper: str = auth_provider.upper()
        logger.debug(f"Standardized auth provider name to: {auth_provider_upper}")
        # read client_id and client_secret from the environment variables
        auth_client_id: str | None = os.getenv(f"AUTH_CLIENT_ID_{auth_provider_upper}")
        if auth_client_id is None:
            logger.error(
                f"AUTH_CLIENT_ID_{auth_provider_upper} environment variable is not set"
            )
            raise ValueError(
                f"AUTH_CLIENT_ID_{auth_provider_upper} environment variable must be set"
            )
        auth_client_secret: str | None = os.getenv(
            f"AUTH_CLIENT_SECRET_{auth_provider_upper}"
        )
        if auth_client_secret:
            logger.debug(f"Found client secret for provider: {auth_provider_upper}")
        else:
            logger.debug(f"No client secret found for provider: {auth_provider_upper}")
        auth_well_known_uri: str | None = os.getenv(
            f"AUTH_WELL_KNOWN_URI_{auth_provider_upper}"
        )
        if auth_well_known_uri is None:
            logger.error(
                f"AUTH_WELL_KNOWN_URI_{auth_provider_upper} environment variable is not set"
            )
            raise ValueError(
                f"AUTH_WELL_KNOWN_URI_{auth_provider_upper} environment variable must be set"
            )
        issuer: str | None = os.getenv(f"AUTH_ISSUER_{auth_provider_upper}")
        logger.debug(
            f"Issuer for {auth_provider_upper}: {issuer if issuer else 'not set'}"
        )
        audience: str | None = os.getenv(f"AUTH_AUDIENCE_{auth_provider_upper}")
        if audience is None:
            logger.error(
                f"AUTH_AUDIENCE_{auth_provider_upper} environment variable is not set"
            )
            raise ValueError(
                f"AUTH_AUDIENCE_{auth_provider_upper} environment variable must be set"
            )
        friendly_name: str | None = os.getenv(
            f"AUTH_FRIENDLY_NAME_{auth_provider_upper}"
        )
        if not friendly_name:
            # if no friendly name is set, use the auth_provider as the friendly name
            friendly_name = auth_provider
            logger.debug(
                f"No friendly name set, using auth provider name: {friendly_name}"
            )
        else:
            logger.debug(f"Friendly name for {auth_provider}: {friendly_name}")

        logger.info(f"Successfully read config for auth provider: {auth_provider}")
        return AuthConfig(
            auth_provider=auth_provider,
            friendly_name=friendly_name,
            audience=audience,
            issuer=issuer,
            client_id=auth_client_id,
            client_secret=auth_client_secret,
            well_known_uri=auth_well_known_uri,
        )

    def get_audience_for_provider(self, *, auth_provider: str) -> str:
        """
        Get the audience for a specific auth provider.

        Args:
            auth_provider (str): The auth provider for which to retrieve the audience.

        Returns:
            str: The audience for the specified auth provider.
        """
        logger.debug(f"Getting audience for provider: {auth_provider}")
        auth_config: AuthConfig | None = self.get_config_for_auth_provider(
            auth_provider=auth_provider
        )
        if auth_config is None:
            logger.error(f"AuthConfig for provider {auth_provider} not found")
            raise ValueError(f"AuthConfig for audience {auth_provider} not found.")
        logger.debug(
            f"Found audience for provider {auth_provider}: {auth_config.audience}"
        )
        return auth_config.audience

    def get_provider_for_audience(self, *, audience: str) -> str | None:
        """
        Get the auth provider for a specific audience.

        Args:
            audience (str): The audience for which to retrieve the auth provider.

        Returns:
            str | None: The auth provider if found, otherwise None.
        """
        logger.debug(f"Getting provider for audience: {audience}")
        auth_configs: list[AuthConfig] = self.get_auth_configs_for_all_auth_providers()
        for auth_config in auth_configs:
            if auth_config.audience == audience:
                logger.debug(
                    f"Found provider for audience {audience}: {auth_config.auth_provider}"
                )
                return auth_config.auth_provider
        logger.warning(f"No provider found for audience: {audience}")
        return None

    def get_provider_for_client_id(self, *, client_id: str) -> str | None:
        """
        Get the auth provider for a specific audience.

        Args:
            client_id (str): The client id for which to retrieve the auth provider.

        Returns:
            str | None: The auth provider if found, otherwise None.
        """
        logger.debug(f"Getting provider for client_id: {client_id}")
        auth_configs: list[AuthConfig] = self.get_auth_configs_for_all_auth_providers()
        for auth_config in auth_configs:
            if auth_config.client_id == client_id:
                logger.debug(
                    f"Found provider for client_id {client_id}: {auth_config.auth_provider}"
                )
                return auth_config.auth_provider
        logger.warning(f"No provider found for client_id: {client_id}")
        return None

    def get_first_provider(self) -> str | None:
        """
        Get the first auth provider from the list of configured auth providers.

        Returns:
            str | None: The first auth provider if available, otherwise None.
        """
        logger.debug("Getting first provider")
        auth_providers: list[str] | None = self.environment_variables.auth_providers
        if auth_providers is None or len(auth_providers) == 0:
            logger.warning("No auth providers configured")
            return None
        logger.debug(f"First provider is: {auth_providers[0]}")
        return auth_providers[0]

    def get_config_for_first_auth_provider(
        self,
    ) -> AuthConfig | None:
        """
        Get the authentication configuration for the first configured auth provider.

        Returns:
            AuthConfig | None: The authentication configuration if found, otherwise None.
        """
        logger.debug("Getting config for first auth provider")
        # make sure we have loaded all configs
        self.get_auth_configs_for_all_auth_providers()
        first_provider: str | None = self.get_first_provider()
        if first_provider is None:
            logger.warning("No first provider available")
            return None
        return self.get_config_for_auth_provider(auth_provider=first_provider)
