"""MongoDB store factory for accessing different collections."""

import threading
from typing import Any
from typing import override

from pymongo import AsyncMongoClient

from oidcauthlib.storage.cache_to_collection_mapper import CacheToCollectionMapper
from oidcauthlib.storage.mongo_gridfs_db import MongoDBGridFSStore
from oidcauthlib.storage.storage_factory import StorageFactory
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)
from oidcauthlib.utilities.mongo_url_utils import MongoUrlHelpers

# MongoDB client connection configuration constants
DEFAULT_MAX_IDLE_TIME_MS = 45_000  # 45 seconds - close idle connections
DEFAULT_SERVER_SELECTION_TIMEOUT_MS = 5_000  # 5 seconds - server selection timeout


class MongoStoreFactory(StorageFactory):
    """Factory for creating and managing MongoDB store instances."""

    def __init__(
        self,
        *,
        environment_variables: OidcEnvironmentVariables,
        cache_to_collection_mapper: CacheToCollectionMapper,
    ) -> None:
        """Initialize the factory with environment configuration.

        Args:
            environment_variables: Environment configuration
        """
        self._environment_variables: OidcEnvironmentVariables = environment_variables
        if self._environment_variables is None:
            raise ValueError("Environment variables must be provided")
        if not isinstance(environment_variables, OidcEnvironmentVariables):
            raise TypeError(
                f"environment_variables must be an instance of OidcEnvironmentVariables: {type(environment_variables).__name__}"
            )
        self._stores: dict[str, MongoDBGridFSStore] = {}
        self._connection_string: str | None = None
        self._mongo_client: AsyncMongoClient[dict[str, Any]] | None = None
        self._client_lock = threading.Lock()
        # New lock to protect cache store creation and ensure thread-safe singletons
        self._stores_lock = threading.Lock()

        self._cache_to_collection_mapper = cache_to_collection_mapper
        if self._cache_to_collection_mapper is None:
            raise ValueError("Cache to collection mapper must be provided")
        if not isinstance(cache_to_collection_mapper, CacheToCollectionMapper):
            raise TypeError(
                f"cache_to_collection_mapper must be an instance of CacheToCollectionMapper: {type(cache_to_collection_mapper).__name__}"
            )

    def _get_connection_string(self) -> str:
        """Get the MongoDB connection string with credentials.

        Returns:
            MongoDB connection string
        """
        if self._connection_string is None:
            mongo_url = self._environment_variables.mongo_uri
            if not mongo_url:
                raise ValueError("mongo_uri is required in environment variables")

            self._connection_string = MongoUrlHelpers.add_credentials_to_mongo_url(
                mongo_url=mongo_url,
                username=self._environment_variables.mongo_db_username,
                password=self._environment_variables.mongo_db_password,
            )
        return self._connection_string

    def _get_mongo_client(self) -> AsyncMongoClient[dict[str, Any]]:
        """Get or create a shared AsyncMongoClient with thread-safe initialization.

        Uses double-checked locking to ensure only one client is created even
        under concurrent access.

        Returns:
            AsyncMongoClient instance with configurable pool size
        """
        if self._mongo_client is None:
            with self._client_lock:
                # Double-checked locking pattern to prevent race conditions
                if self._mongo_client is None:
                    max_pool_size = self._environment_variables.mongo_max_pool_size
                    min_pool_size = self._environment_variables.mongo_min_pool_size
                    self._mongo_client = AsyncMongoClient(
                        self._get_connection_string(),
                        maxPoolSize=max_pool_size,  # Configurable via MONGO_MAX_POOL_SIZE
                        minPoolSize=min_pool_size,  # Configurable via MONGO_MIN_POOL_SIZE
                        maxIdleTimeMS=DEFAULT_MAX_IDLE_TIME_MS,
                        serverSelectionTimeoutMS=DEFAULT_SERVER_SELECTION_TIMEOUT_MS,
                        appname="OidcAuthLib",
                    )
        return self._mongo_client

    def _create_store(self, collection_name: str) -> MongoDBGridFSStore:
        """Create a new MongoDB store for the specified collection.

        Args:
            collection_name: Name of the MongoDB collection

        Returns:
            Configured MongoDBStore instance

        Raises:
            ValueError: If required environment variables are missing
        """
        # Validate required MongoDB configuration
        db_name = self._environment_variables.mongo_db_name
        if not db_name:
            raise ValueError(
                "MONGO_DB_NAME environment variable is required but not set"
            )

        if not collection_name:
            raise ValueError("Collection name is required but not provided")

        return MongoDBGridFSStore(
            client=self._get_mongo_client(),
            db_name=db_name,
            coll_name=collection_name,
            default_collection=collection_name,
            gridfs_chunk_size_kb=self._environment_variables.gridfs_chunk_size_kb,
            max_inline_size_kb=self._environment_variables.max_mongo_inline_size_kb,
        )

    @override
    def get_store(self, namespace: str) -> MongoDBGridFSStore:
        """Get cache for namespace (implements StorageFactory Protocol).

        Uses dictionary-based dispatch for O(1) lookup and extensibility.
        New namespaces can be added to the mapping without modifying this method.

        Args:
            namespace: Cache namespace from CacheNamespace enum

        Returns:
            MongoDBStore instance for the specified namespace

        Raises:
            ValueError: If namespace is not supported or required environment
                       variable is not set
        """
        # Fast path: return if already created
        existing = self._stores.get(namespace)
        if existing is not None:
            return existing

        # Slow path: create under lock to ensure singletons under concurrency
        with self._stores_lock:
            # Double-check after acquiring the lock
            existing_locked = self._stores.get(namespace)
            if existing_locked is not None:
                return existing_locked

            collection_name: str | None = (
                self._cache_to_collection_mapper.get_collection_for_cache(
                    cache_name=namespace
                )
            )
            if collection_name is None:
                raise ValueError(
                    f"No collection mapping found for cache namespace: {namespace}"
                )

            # Validate required collection configuration
            if not collection_name:
                raise ValueError(
                    f"Collection configuration missing for namespace: {namespace}"
                )

            # Create and cache the store
            store = self._create_store(collection_name)
            self._stores[namespace] = store
            return store
