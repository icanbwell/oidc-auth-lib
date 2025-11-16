import logging

from oidcauthlib.auth.auth_manager import AuthManager
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)
from oidcauthlib.auth.fastapi_auth_manager import FastAPIAuthManager
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.container.simple_container import SimpleContainer
from oidcauthlib.utilities.environment.environment_variables import EnvironmentVariables

logger = logging.getLogger(__name__)


class OidcAuthLibContainerFactory:
    @staticmethod
    def register_services_in_container(
        *, container: SimpleContainer
    ) -> SimpleContainer:
        """
        Register services in the DI container

        :param container:
        :return:
        """
        # register services here
        container.singleton(
            EnvironmentVariables,
            lambda c: EnvironmentVariables(),
        )

        container.singleton(
            AuthConfigReader,
            lambda c: AuthConfigReader(
                environment_variables=c.resolve(EnvironmentVariables)
            ),
        )

        container.singleton(
            WellKnownConfigurationCache, lambda c: WellKnownConfigurationCache()
        )

        container.singleton(
            WellKnownConfigurationManager,
            lambda c: WellKnownConfigurationManager(
                auth_config_reader=c.resolve(AuthConfigReader),
                cache=c.resolve(WellKnownConfigurationCache),
            ),
        )

        container.singleton(
            TokenReader,
            lambda c: TokenReader(
                auth_config_reader=c.resolve(AuthConfigReader),
                well_known_config_manager=c.resolve(WellKnownConfigurationManager),
            ),
        )
        container.singleton(
            FastAPIAuthManager,
            lambda c: FastAPIAuthManager(
                environment_variables=c.resolve(EnvironmentVariables),
                auth_config_reader=c.resolve(AuthConfigReader),
                token_reader=c.resolve(TokenReader),
                well_known_configuration_manager=c.resolve(
                    WellKnownConfigurationManager
                ),
            ),
        )

        container.singleton(
            AuthManager,
            lambda c: AuthManager(
                auth_config_reader=c.resolve(AuthConfigReader),
                token_reader=c.resolve(TokenReader),
                environment_variables=c.resolve(EnvironmentVariables),
                well_known_configuration_manager=c.resolve(
                    WellKnownConfigurationManager
                ),
            ),
        )

        logger.info("DI container initialized")
        return container
