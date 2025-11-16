import logging

from oidcauthlib.auth.auth_manager import AuthManager
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
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
            TokenReader,
            lambda c: TokenReader(
                auth_config_reader=c.resolve(AuthConfigReader),
            ),
        )
        container.register(
            FastAPIAuthManager,
            lambda c: FastAPIAuthManager(
                environment_variables=c.resolve(EnvironmentVariables),
                auth_config_reader=c.resolve(AuthConfigReader),
                token_reader=c.resolve(TokenReader),
            ),
        )

        container.register(
            AuthManager,
            lambda c: AuthManager(
                auth_config_reader=c.resolve(AuthConfigReader),
                token_reader=c.resolve(TokenReader),
                environment_variables=c.resolve(EnvironmentVariables),
            ),
        )

        logger.info("DI container initialized")
        return container
