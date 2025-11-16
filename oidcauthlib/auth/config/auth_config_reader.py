import os

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)


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
        self.environment_variables: AbstractEnvironmentVariables = environment_variables
        if self.environment_variables is None:
            raise ValueError(
                "AuthConfigReader requires an EnvironmentVariables instance."
            )
        if not isinstance(self.environment_variables, AbstractEnvironmentVariables):
            raise TypeError(
                "environment_variables must be an instance of EnvironmentVariables"
            )

    def get_auth_configs_for_all_auth_providers(self) -> list[AuthConfig]:
        """
        Get authentication configurations for all audiences.

        Returns:
            list[AuthConfig]: A list of AuthConfig instances for each audience.
        """
        auth_providers: list[str] | None = self.environment_variables.auth_providers
        if auth_providers is None:
            raise ValueError("auth_providers environment variable must be set")
        auth_configs: list[AuthConfig] = []
        for auth_provider in auth_providers:
            auth_config: AuthConfig | None = self.get_config_for_auth_provider(
                auth_provider=auth_provider,
            )
            if auth_config is not None:
                auth_configs.append(auth_config)
        return auth_configs

    # noinspection PyMethodMayBeStatic
    def get_config_for_auth_provider(self, *, auth_provider: str) -> AuthConfig | None:
        """
        Get the authentication configuration for a specific audience.

        Args:
            auth_provider (str): The audience for which to retrieve the configuration.

        Returns:
            AuthConfig | None: The authentication configuration if found, otherwise None.
        """
        if auth_provider is None:
            raise ValueError("auth_provider must not be None")
        # environment variables are case-insensitive, but we standardize to upper case
        auth_provider = auth_provider.upper()
        # read client_id and client_secret from the environment variables
        auth_client_id: str | None = os.getenv(f"AUTH_CLIENT_ID_{auth_provider}")
        if auth_client_id is None:
            raise ValueError(
                f"AUTH_CLIENT_ID_{auth_provider} environment variable must be set"
            )
        auth_client_secret: str | None = os.getenv(
            f"AUTH_CLIENT_SECRET_{auth_provider}"
        )
        auth_well_known_uri: str | None = os.getenv(
            f"AUTH_WELL_KNOWN_URI_{auth_provider}"
        )
        if auth_well_known_uri is None:
            raise ValueError(
                f"AUTH_WELL_KNOWN_URI_{auth_provider} environment variable must be set"
            )
        issuer: str | None = os.getenv(f"AUTH_ISSUER_{auth_provider}")
        audience: str | None = os.getenv(f"AUTH_AUDIENCE_{auth_provider}")
        if audience is None:
            raise ValueError(
                f"AUTH_AUDIENCE_{auth_provider} environment variable must be set"
            )
        return AuthConfig(
            auth_provider=auth_provider,
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
        auth_config: AuthConfig | None = self.get_config_for_auth_provider(
            auth_provider=auth_provider
        )
        if auth_config is None:
            raise ValueError(f"AuthConfig for audience {auth_provider} not found.")
        return auth_config.audience

    def get_provider_for_audience(self, *, audience: str) -> str | None:
        """
        Get the auth provider for a specific audience.

        Args:
            audience (str): The audience for which to retrieve the auth provider.

        Returns:
            str | None: The auth provider if found, otherwise None.
        """
        auth_configs: list[AuthConfig] = self.get_auth_configs_for_all_auth_providers()
        for auth_config in auth_configs:
            if auth_config.audience == audience:
                return auth_config.auth_provider
        return None

    def get_first_provider(self) -> str | None:
        """
        Get the first auth provider from the list of configured auth providers.

        Returns:
            str | None: The first auth provider if available, otherwise None.
        """
        auth_providers: list[str] | None = self.environment_variables.auth_providers
        if auth_providers is None or len(auth_providers) == 0:
            return None
        return auth_providers[0]

    def get_config_for_first_auth_provider(
        self,
    ) -> AuthConfig | None:
        """
        Get the authentication configuration for the first configured auth provider.

        Returns:
            AuthConfig | None: The authentication configuration if found, otherwise None.
        """
        first_provider: str | None = self.get_first_provider()
        if first_provider is None:
            return None
        return self.get_config_for_auth_provider(auth_provider=first_provider)
