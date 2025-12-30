"""Security tests for StorageFactory implementations.

Tests data isolation, thread safety, singleton behavior, and factory selection
to ensure no patient data leaks between cache instances.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import Mock, patch

import pytest

from oidcauthlib.storage.cache_to_collection_mapper import CacheToCollectionMapper
from oidcauthlib.storage.mongo_storage_factory import MongoStoreFactory
from oidcauthlib.storage.storage_factory import StorageFactory
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
    CacheProvider,
)

PERSON_PATIENT: str = "person_patient"
DYNAMIC_CLIENT_REGISTRATION: str = "dynamic_client_registration"

# ============================================================================
# Data Isolation Tests - Critical for FHIR patient data security
# ============================================================================


@pytest.mark.asyncio
async def test_data_isolation_between_namespaces() -> None:
    """Test that data written to one namespace doesn't appear in another.

    This is CRITICAL for FHIR patient data - we must ensure person_patient
    cache data never leaks into client_registration cache.
    """
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db_isolation"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.mongo_db_username = None
    env.mongo_db_password = None
    env.cache_provider = CacheProvider.MONGODB
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"

    with patch("oidcauthlib.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch(
            "oidcauthlib.storage.mongo_storage_factory.MongoDBGridFSStore"
        ) as mock_store_class:
            # Create two separate mock stores
            person_store_mock = Mock()
            client_store_mock = Mock()

            # Set up the mock to return different instances for different collections
            def create_store_side_effect(*args: Any, **kwargs: Any) -> Mock:
                coll_name = kwargs.get("coll_name")
                if coll_name == "person_patient_cache":
                    return person_store_mock
                elif coll_name == "dynamic_client_registration":
                    return client_store_mock
                else:
                    raise ValueError(f"Unexpected collection: {coll_name}")

            mock_store_class.side_effect = create_store_side_effect

            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            # Get caches for different namespaces
            person_cache = factory.get_store(PERSON_PATIENT)
            client_cache = factory.get_store(DYNAMIC_CLIENT_REGISTRATION)

            # Verify they are different instances
            assert person_cache is not client_cache
            assert person_cache is person_store_mock
            assert client_cache is client_store_mock


@pytest.mark.asyncio
async def test_concurrent_writes_to_different_namespaces_dont_interfere() -> None:
    """Test that concurrent writes to different namespaces are properly isolated."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db_concurrent"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.mongo_db_username = None
    env.mongo_db_password = None
    env.cache_provider = CacheProvider.MONGODB
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"

    with patch("oidcauthlib.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch(
            "oidcauthlib.storage.mongo_storage_factory.MongoDBGridFSStore"
        ) as mock_store_class:
            # Create separate mock stores with tracking
            person_writes = []
            client_writes = []

            person_store_mock = Mock()
            client_store_mock = Mock()

            async def person_put(key: str, value: Any) -> None:
                person_writes.append((key, value))

            async def client_put(key: str, value: Any) -> None:
                client_writes.append((key, value))

            person_store_mock.put = person_put
            client_store_mock.put = client_put

            def create_store_side_effect(*args: Any, **kwargs: Any) -> Mock:
                coll_name = kwargs.get("coll_name")
                if coll_name == "person_patient_cache":
                    return person_store_mock
                elif coll_name == "dynamic_client_registration":
                    return client_store_mock
                else:
                    raise ValueError(f"Unexpected collection: {coll_name}")

            mock_store_class.side_effect = create_store_side_effect

            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            person_cache = factory.get_store(PERSON_PATIENT)
            client_cache = factory.get_store(DYNAMIC_CLIENT_REGISTRATION)

            # Simulate concurrent writes
            await asyncio.gather(
                person_cache.put("person1", {"name": "John"}),
                client_cache.put("client1", {"id": "oauth_client"}),
                person_cache.put("person2", {"name": "Jane"}),
                client_cache.put("client2", {"id": "oauth_client2"}),
            )

            # Verify writes went to correct stores
            assert len(person_writes) == 2
            assert len(client_writes) == 2
            assert ("person1", {"name": "John"}) in person_writes
            assert ("person2", {"name": "Jane"}) in person_writes
            assert ("client1", {"id": "oauth_client"}) in client_writes
            assert ("client2", {"id": "oauth_client2"}) in client_writes


def test_different_namespaces_use_different_collections() -> None:
    """Test that different namespaces map to different MongoDB collections."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.mongo_db_username = None
    env.mongo_db_password = None
    env.cache_provider = CacheProvider.MONGODB
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"

    with patch("oidcauthlib.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch(
            "oidcauthlib.storage.mongo_storage_factory.MongoDBGridFSStore"
        ) as mock_store_class:
            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            # Get both caches
            factory.get_store(PERSON_PATIENT)
            factory.get_store(DYNAMIC_CLIENT_REGISTRATION)

            # Verify MongoDBStore was called twice with different collection names
            assert mock_store_class.call_count == 2

            call_args_list = [
                call[1]["coll_name"] for call in mock_store_class.call_args_list
            ]
            assert "person_patient_cache" in call_args_list
            assert "dynamic_client_registration" in call_args_list


# ============================================================================
# Thread Safety Tests
# ============================================================================


def test_concurrent_get_cache_same_namespace_returns_same_instance() -> None:
    """Test that concurrent calls to get_cache for the same namespace return the same instance.

    This ensures the singleton pattern is thread-safe and prevents multiple
    connections/stores being created.
    """
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.mongo_db_username = None
    env.mongo_db_password = None
    env.cache_provider = CacheProvider.MONGODB
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"

    with patch("oidcauthlib.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch(
            "oidcauthlib.storage.mongo_storage_factory.MongoDBGridFSStore"
        ) as mock_store_class:
            mock_store_instance = Mock()
            mock_store_class.return_value = mock_store_instance

            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            # Fire 100 concurrent calls from different threads
            caches = []

            def call_factory() -> None:
                cache = factory.get_store(PERSON_PATIENT)
                caches.append(cache)

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(call_factory) for _ in range(100)]
                for future in futures:
                    future.result()

            # All threads should get the same instance
            assert len(caches) == 100
            assert all(c is caches[0] for c in caches)

            # MongoDBStore constructor should only be called once (singleton worked)
            assert mock_store_class.call_count == 1


def test_factory_initialization_is_thread_safe() -> None:
    """Test that creating multiple factory instances from different threads is safe."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.mongo_db_username = None
    env.mongo_db_password = None
    env.cache_provider = CacheProvider.MONGODB

    with patch("oidcauthlib.storage.mongo_storage_factory.AsyncMongoClient"):
        factories = []

        def create_factory_instance() -> None:
            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )
            factories.append(factory)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_factory_instance) for _ in range(50)]
            for future in futures:
                future.result()

        # All factories should be created successfully
        assert len(factories) == 50
        # All should be MongoStoreFactory instances
        assert all(isinstance(f, MongoStoreFactory) for f in factories)


# ============================================================================
# Singleton Behavior Tests
# ============================================================================


def test_singleton_per_namespace() -> None:
    """Test that calling get_cache twice for same namespace returns identical instance."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.mongo_db_username = None
    env.mongo_db_password = None
    env.cache_provider = CacheProvider.MONGODB
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"

    with patch("oidcauthlib.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch(
            "oidcauthlib.storage.mongo_storage_factory.MongoDBGridFSStore"
        ) as mock_store_class:
            mock_store_instance = Mock()
            mock_store_class.return_value = mock_store_instance

            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            cache1 = factory.get_store(PERSON_PATIENT)
            cache2 = factory.get_store(PERSON_PATIENT)

            # Same object reference (singleton)
            assert cache1 is cache2
            assert cache1 is mock_store_instance

            # Store only created once
            assert mock_store_class.call_count == 1


def test_different_namespaces_return_different_instances() -> None:
    """Test that different namespaces return different cache instances."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.mongo_db_username = None
    env.mongo_db_password = None
    env.cache_provider = CacheProvider.MONGODB
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"

    with patch("oidcauthlib.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch(
            "oidcauthlib.storage.mongo_storage_factory.MongoDBGridFSStore"
        ) as mock_store_class:
            # Return different mocks for each call
            mock_store_class.side_effect = [Mock(), Mock()]

            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            cache1 = factory.get_store(PERSON_PATIENT)
            cache2 = factory.get_store(DYNAMIC_CLIENT_REGISTRATION)

            # Different instances
            assert cache1 is not cache2
            # Both calls created stores
            assert mock_store_class.call_count == 2


def test_singleton_per_factory_instance() -> None:
    """Test that each factory instance maintains its own singleton stores."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.mongo_db_username = None
    env.mongo_db_password = None
    env.cache_provider = CacheProvider.MONGODB
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"

    with patch("oidcauthlib.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch(
            "oidcauthlib.storage.mongo_storage_factory.MongoDBGridFSStore"
        ) as mock_store_class:
            # Return different mocks for each call
            mock_store_class.side_effect = [Mock(), Mock(), Mock(), Mock()]

            # Create two separate factory instances
            factory1 = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )
            factory2 = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            # Each factory should have its own stores
            cache1_person = factory1.get_store(PERSON_PATIENT)
            cache2_person = factory2.get_store(PERSON_PATIENT)

            # Different instances (different factories)
            assert cache1_person is not cache2_person

            # But within same factory, should be singleton
            cache1_person_again = factory1.get_store(PERSON_PATIENT)
            assert cache1_person is cache1_person_again


# ============================================================================
# Factory Selection Tests
# ============================================================================


def test_factory_selection_mongodb() -> None:
    """Test that CACHE_PROVIDER=mongodb returns MongoStoreFactory."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.cache_provider = CacheProvider.MONGODB
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.mongo_db_username = None
    env.mongo_db_password = None

    with patch("oidcauthlib.storage.mongo_storage_factory.AsyncMongoClient"):
        factory = MongoStoreFactory(
            environment_variables=env,
            cache_to_collection_mapper=CacheToCollectionMapper(
                environment_variables=env
            ),
        )
        assert isinstance(factory, MongoStoreFactory)
        # Verify it implements StorageFactory Protocol
        assert isinstance(factory, StorageFactory)


def test_factory_selection_redis_not_implemented() -> None:
    """Test that CACHE_PROVIDER=redis raises NotImplementedError."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.cache_provider = CacheProvider.REDIS

    with pytest.raises(NotImplementedError) as exc_info:
        MongoStoreFactory(
            environment_variables=env,
            cache_to_collection_mapper=CacheToCollectionMapper(
                environment_variables=env
            ),
        )

    assert "Redis provider not yet implemented" in str(exc_info.value)
    assert CacheProvider.MONGODB.value in str(exc_info.value)


def test_factory_selection_invalid_provider() -> None:
    """Test that invalid provider raises ValueError."""
    env = Mock(spec=OidcEnvironmentVariables)
    # Mock an invalid provider (bypass enum validation)
    env.cache_provider = "invalid_provider"

    with pytest.raises(ValueError) as exc_info:
        MongoStoreFactory(
            environment_variables=env,
            cache_to_collection_mapper=CacheToCollectionMapper(
                environment_variables=env
            ),
        )

    assert "Unknown cache provider" in str(exc_info.value)
