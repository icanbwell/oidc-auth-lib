from typing import override

from key_value.aio.stores.base import BaseDestroyCollectionStore
from key_value.aio.stores.memory import MemoryStore

from tests.storage.storage_factory import StorageFactory


class MemoryStorageFactory(StorageFactory):
    """Factory for creating and managing in-memory store instances."""

    def __init__(self) -> None:
        """Initialize the factory."""
        self._stores: dict[str, MemoryStore] = {}

    @override
    def get_store(self, namespace: str) -> BaseDestroyCollectionStore:
        """Get or create in-memory cache store for the specified namespace.

        Returns a singleton cache instance for the given namespace. Multiple calls
        with the same namespace return the same store instance (singleton pattern).

        Args:
            namespace: Cache namespace from CacheNamespace enum

        Returns:
            BaseStore instance for the specified namespace
        """
        if namespace not in self._stores:
            self._stores[namespace] = MemoryStore()
        return self._stores[namespace]

    @classmethod
    async def clear_all_stores(cls) -> None:
        """Clear all in-memory stores managed by this factory."""
        # This method assumes a single global instance of MemoryStorageFactory.
        # In a real application, you might want to manage instances differently.
        instance = cls()
        for store in instance._stores.values():
            await store.delete_many({})  # Clear all entries in each store
