import logging

from oidcauthlib.auth.auth_manager import AuthManager
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.fastapi_auth_manager import FastAPIAuthManager
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache import (
    WellKnownConfigurationCache,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)
from oidcauthlib.container.simple_container import SimpleContainer
from oidcauthlib.storage.cache_to_collection_mapper import CacheToCollectionMapper
from oidcauthlib.storage.storage_factory import StorageFactory
from oidcauthlib.storage.storage_factory_creator import StorageFactoryCreator
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)
from oidcauthlib.storage.memory_storage_factory import MemoryStorageFactory

logger = logging.getLogger(__name__)


class OidcAuthLibContainerFactory:
    @classmethod
    def create_container(cls) -> SimpleContainer:
        logger.info("Initializing DI container")

        container = SimpleContainer()

        container = OidcAuthLibContainerFactory().register_services_in_container(
            container=container
        )
        return container

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
            OidcEnvironmentVariables,
            lambda c: OidcEnvironmentVariables(),
        )

        container.singleton(
            AuthConfigReader,
            lambda c: AuthConfigReader(
                environment_variables=c.resolve(OidcEnvironmentVariables)
            ),
        )

        # Register the concrete MemoryStorageFactory instead of the StorageFactory Protocol
        container.singleton(MemoryStorageFactory, lambda c: MemoryStorageFactory())

        container.singleton(
            WellKnownConfigurationCache,
            lambda c: WellKnownConfigurationCache(
                well_known_store=c.resolve(MemoryStorageFactory).get_store(
                    namespace="well_known_configuration",
                )
            ),
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
                environment_variables=c.resolve(OidcEnvironmentVariables),
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
                environment_variables=c.resolve(OidcEnvironmentVariables),
                well_known_configuration_manager=c.resolve(
                    WellKnownConfigurationManager
                ),
            ),
        )

        container.singleton(
            CacheToCollectionMapper,
            lambda c: CacheToCollectionMapper(
                environment_variables=c.resolve(OidcEnvironmentVariables)
            ),
        )

        container.singleton(
            StorageFactoryCreator,
            lambda c: StorageFactoryCreator(
                environment_variables=c.resolve(OidcEnvironmentVariables),
                cache_to_collection_mapper=c.resolve(CacheToCollectionMapper),
            ),
        )
        # Register storage factory as singleton to manage connection pools
        # Implementation (MongoDB/Redis) selected based on CACHE_PROVIDER env var
        container.singleton(
            StorageFactory,
            lambda c: c.resolve(StorageFactoryCreator).create_storage_factory(),
        )

        logger.info("DI container initialized")
        return container
