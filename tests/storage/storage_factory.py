from abc import abstractmethod, ABC

from key_value.aio.stores.base import BaseStore


class StorageFactory(ABC):
    """Protocol for storage factory implementations.

    This protocol defines the interface that all storage factory implementations
    must follow. It provides backend-agnostic access to cache stores for different
    namespaces via a single get_cache() method.

    Implementations:
        - MongoStorageFactory: MongoDB backend (current)
        - RedisStorageFactory: Redis backend (future)

    Usage:
        Factory instances are created via create_storage_factory() which selects
        the appropriate implementation based on CACHE_PROVIDER environment variable.

    """

    @abstractmethod
    def get_store(self, namespace: str) -> BaseStore:
        """Get or create cache store for the specified namespace.

        Returns a singleton cache instance for the given namespace. Multiple calls
        with the same namespace return the same store instance (singleton pattern).

        Args:
            namespace: Cache namespace from CacheNamespace enum

        Returns:
            BaseStore instance for the specified namespace

        Raises:
            ValueError: If namespace configuration is invalid
        """
        ...
