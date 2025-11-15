import logging

from oidcauthlib.auth.auth_manager import AuthManager
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.fastapi_auth_manager import FastAPIAuthManager
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.container.simple_container import SimpleContainer
from oidcauthlib.utilities.environment.environment_variables import EnvironmentVariables

logger = logging.getLogger(__name__)


class ContainerFactory:
    # noinspection PyMethodMayBeStatic
    def create_container_only(self) -> SimpleContainer:
        """
        Initialize the DI container without registering services

        :return:
        """
        logger.info("Initializing DI container")

        container = SimpleContainer()

        return container

    def create_container(self) -> SimpleContainer:
        """
        Initialize the DI container and register services

        :return:
        """
        logger.info("Initializing DI container")

        container = SimpleContainer()

        return self.register_services_in_container(container=container)

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
        container.register(
            EnvironmentVariables,
            lambda c: EnvironmentVariables(),
        )

        container.register(
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
