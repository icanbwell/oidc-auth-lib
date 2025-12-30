"""Storage factory module with provider selection.

This module provides the entry point for creating storage factory instances
based on the CACHE_PROVIDER environment variable. It selects the appropriate
backend implementation (MongoDB, Redis, etc.) and returns a StorageFactory
instance.
"""

from oidcauthlib.storage.cache_to_collection_mapper import CacheToCollectionMapper
from oidcauthlib.storage.storage_factory import StorageFactory

from oidcauthlib.storage.mongo_storage_factory import MongoStoreFactory
from oidcauthlib.storage.memory_storage_factory import MemoryStorageFactory
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
    CacheProvider,
)


class StorageFactoryCreator:
    def __init__(
        self,
        *,
        environment_variables: OidcEnvironmentVariables,
        cache_to_collection_mapper: CacheToCollectionMapper,
    ) -> None:
        self.environment_variables = environment_variables
        if self.environment_variables is None:
            raise ValueError("Environment variables must be provided")
        if not isinstance(environment_variables, OidcEnvironmentVariables):
            raise TypeError(
                f"environment_variables must be an instance of OidcEnvironmentVariables: {type(environment_variables).__name__}"
            )
        self.cache_to_collection_mapper = cache_to_collection_mapper
        if self.cache_to_collection_mapper is None:
            raise ValueError("Cache to collection mapper must be provided")
        if not isinstance(cache_to_collection_mapper, CacheToCollectionMapper):
            raise TypeError(
                f"cache_to_collection_mapper must be an instance of CacheToCollectionMapper: {type(cache_to_collection_mapper).__name__}"
            )

    def create_storage_factory(
        self,
    ) -> StorageFactory:
        """
        Create storage factory based on CACHE_PROVIDER setting.

        Selects and instantiates the appropriate storage factory implementation
        based on the cache provider configured in environment variables.


        Returns:
            StorageFactory implementation (MongoDB or Redis)

        Raises:
            NotImplementedError: If Redis provider selected (not yet implemented)
            ValueError: If unknown provider specified

        Example:
            ```python
            from oidcauthlib.storage import create_storage_factory
            from oidcauthlib.storage.factory import CacheNamespace

            env = OidcEnvironmentVariables()
            factory = create_storage_factory(env)
            patient_cache = factory.get_cache(CacheNamespace.PERSON_PATIENT)
            ```
        """
        match self.environment_variables.cache_provider:
            case CacheProvider.MONGODB:
                return MongoStoreFactory(
                    environment_variables=self.environment_variables,
                    cache_to_collection_mapper=self.cache_to_collection_mapper,
                )
            case CacheProvider.REDIS:
                raise NotImplementedError(
                    "Redis provider not yet implemented. "
                    f"Use CACHE_PROVIDER={CacheProvider.MONGODB.value} (default)"
                )
            case CacheProvider.MEMORY:
                return MemoryStorageFactory()
            case _:
                raise ValueError(
                    f"Unknown cache provider: {self.environment_variables.cache_provider}"
                )
