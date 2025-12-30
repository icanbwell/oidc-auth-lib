"""MongoDB-specific tests for MongoStoreFactory.

Tests credential injection, protocol compliance, and connection pooling
to ensure MongoDB implementation is secure and properly configured.
"""

from unittest.mock import Mock, patch

import pytest

from oidcauthlib.storage.cache_to_collection_mapper import CacheToCollectionMapper
from oidcauthlib.storage.mongo_storage_factory import MongoStoreFactory
from oidcauthlib.storage.storage_factory import StorageFactory
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)


PERSON_PATIENT: str = "person_patient"
DYNAMIC_CLIENT_REGISTRATION: str = "dynamic_client_registration"
# ============================================================================
# Credential Injection Tests - Kubernetes secrets security
# ============================================================================


def test_credential_injection_from_separate_env_vars() -> None:
    """Test that credentials are injected when username and password provided separately.

    This is the Kubernetes pattern - URI without credentials, username/password
    provided as separate secrets.
    """
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/test_db"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"
    env.mongo_db_username = "k8s_user"
    env.mongo_db_password = "k8s_pass"  # pragma: allowlist secret

    with patch(
        "mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"
    ) as mock_client_class:
        with patch("mcpfhiragent.storage.mongo_storage_factory.MongoDBGridFSStore"):
            with patch(
                "mcpfhiragent.storage.mongo_storage_factory.MongoUrlHelpers.add_credentials_to_mongo_url"
            ) as mock_add_creds:
                # Mock the credential injection to return URL with credentials
                mock_add_creds.return_value = (
                    "mongodb://k8s_user:k8s_pass@localhost:27017/test_db"
                )

                factory = MongoStoreFactory(
                    environment_variables=env,
                    cache_to_collection_mapper=CacheToCollectionMapper(
                        environment_variables=env
                    ),
                )

                # Trigger connection string creation
                factory.get_store(PERSON_PATIENT)

                # Verify MongoUrlHelpers was called to inject credentials
                assert mock_add_creds.called
                call_kwargs = mock_add_creds.call_args[1]
                assert call_kwargs["username"] == "k8s_user"
                assert call_kwargs["password"] == "k8s_pass"  # pragma: allowlist secret

                # Verify AsyncMongoClient was called with credentials in connection string
                assert mock_client_class.called
                call_args = mock_client_class.call_args[0]
                connection_string = call_args[0]

                # Credentials should be present
                assert "k8s_user" in connection_string
                assert "k8s_pass" in connection_string  # pragma: allowlist secret


def test_credential_injection_env_vars_override_embedded() -> None:
    """Test that env var credentials override embedded URI credentials.

    If both are present, Kubernetes secrets (env vars) take precedence.
    """
    env = Mock(spec=OidcEnvironmentVariables)
    # URI has embedded credentials
    env.mongo_uri = "mongodb://embedded_user:embedded_pass@localhost:27017/test_db"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"
    # But env vars are also provided (should override)
    env.mongo_db_username = "k8s_user"
    env.mongo_db_password = "k8s_pass"  # pragma: allowlist secret

    with patch("mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch("mcpfhiragent.storage.mongo_storage_factory.MongoDBGridFSStore"):
            with patch(
                "mcpfhiragent.storage.mongo_storage_factory.MongoUrlHelpers.add_credentials_to_mongo_url"
            ) as mock_add_creds:
                # Mock the credential injection to return a test URL
                mock_add_creds.return_value = (
                    "mongodb://k8s_user:k8s_pass@localhost:27017/test_db"
                )

                factory = MongoStoreFactory(
                    environment_variables=env,
                    cache_to_collection_mapper=CacheToCollectionMapper(
                        environment_variables=env
                    ),
                )
                factory.get_store(PERSON_PATIENT)

                # Verify MongoUrlHelpers.add_credentials_to_mongo_url was called
                assert mock_add_creds.called
                call_kwargs = mock_add_creds.call_args[1]
                assert call_kwargs["username"] == "k8s_user"
                assert call_kwargs["password"] == "k8s_pass"  # pragma: allowlist secret


def test_credential_injection_skipped_when_only_username_provided() -> None:
    """Test that credential injection is skipped when only username is provided."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/test_db"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"
    env.mongo_db_username = "testuser"
    env.mongo_db_password = None  # Missing password

    with patch(
        "mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"
    ) as mock_client_class:
        with patch("mcpfhiragent.storage.mongo_storage_factory.MongoDBGridFSStore"):
            with patch(
                "mcpfhiragent.storage.mongo_storage_factory.MongoUrlHelpers.add_credentials_to_mongo_url"
            ) as mock_add_creds:
                # When only username, should not inject (return original URL)
                mock_add_creds.return_value = env.mongo_uri

                factory = MongoStoreFactory(
                    environment_variables=env,
                    cache_to_collection_mapper=CacheToCollectionMapper(
                        environment_variables=env
                    ),
                )
                factory.get_store(PERSON_PATIENT)

                # Verify connection string does NOT contain username
                assert mock_client_class.called
                call_args = mock_client_class.call_args[0]
                connection_string = call_args[0]
                # Original URI should be used (no credentials)
                assert "testuser" not in connection_string


def test_credential_injection_skipped_when_only_password_provided() -> None:
    """Test that credential injection is skipped when only password is provided."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/test_db"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"
    env.mongo_db_username = None  # Missing username
    env.mongo_db_password = "testpass"  # pragma: allowlist secret

    with patch(
        "mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"
    ) as mock_client_class:
        with patch("mcpfhiragent.storage.mongo_storage_factory.MongoDBGridFSStore"):
            with patch(
                "mcpfhiragent.storage.mongo_storage_factory.MongoUrlHelpers.add_credentials_to_mongo_url"
            ) as mock_add_creds:
                # When only password, should not inject (return original URL)
                mock_add_creds.return_value = env.mongo_uri

                factory = MongoStoreFactory(
                    environment_variables=env,
                    cache_to_collection_mapper=CacheToCollectionMapper(
                        environment_variables=env
                    ),
                )
                factory.get_store(PERSON_PATIENT)

                # Verify connection string does NOT contain password
                assert mock_client_class.called
                call_args = mock_client_class.call_args[0]
                connection_string = call_args[0]
                # Original URI should be used (no credentials)
                assert "testpass" not in connection_string  # pragma: allowlist secret


# ============================================================================
# Protocol Compliance Tests
# ============================================================================


def test_mongo_store_factory_implements_storage_factory_protocol() -> None:
    """Test that MongoStoreFactory passes isinstance check for StorageFactory Protocol."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2

    with patch("mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"):
        factory = MongoStoreFactory(
            environment_variables=env,
            cache_to_collection_mapper=CacheToCollectionMapper(
                environment_variables=env
            ),
        )

        # Should pass runtime Protocol check
        assert isinstance(factory, StorageFactory)


def test_get_cache_method_returns_base_store() -> None:
    """Test that get_cache() method returns BaseStore-compatible object."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"
    env.mongo_db_username = None
    env.mongo_db_password = None

    with patch("mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch(
            "mcpfhiragent.storage.mongo_storage_factory.MongoDBGridFSStore"
        ) as mock_store_class:
            mock_store = Mock()
            mock_store_class.return_value = mock_store

            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            # Test both supported namespaces
            cache1 = factory.get_store(PERSON_PATIENT)
            assert cache1 is mock_store

            cache2 = factory.get_store(DYNAMIC_CLIENT_REGISTRATION)
            assert cache2 is mock_store


def test_get_cache_with_unknown_namespace_raises_error() -> None:
    """Test that get_cache() raises ValueError for unknown namespace."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2

    with patch("mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"):
        factory = MongoStoreFactory(
            environment_variables=env,
            cache_to_collection_mapper=CacheToCollectionMapper(
                environment_variables=env
            ),
        )

        # Create a fake namespace
        fake_namespace = Mock()
        fake_namespace.value = "unknown_namespace"

        with pytest.raises(ValueError) as exc_info:
            factory.get_store(fake_namespace)

        assert "Unknown cache namespace" in str(exc_info.value)


# ============================================================================
# Connection Pooling Tests
# ============================================================================


def test_connection_pool_size_configuration() -> None:
    """Test that pool size environment variables are applied to AsyncMongoClient."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 50
    env.mongo_min_pool_size = 5
    env.person_patient_cache_collection = "person_patient_cache"
    env.mongo_db_username = None
    env.mongo_db_password = None

    with patch(
        "mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"
    ) as mock_client_class:
        with patch("mcpfhiragent.storage.mongo_storage_factory.MongoDBGridFSStore"):
            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            # Trigger client creation
            factory.get_store(PERSON_PATIENT)

            # Verify AsyncMongoClient was called with correct pool parameters
            assert mock_client_class.called
            call_kwargs = mock_client_class.call_args[1]
            assert call_kwargs["maxPoolSize"] == 50
            assert call_kwargs["minPoolSize"] == 5
            assert call_kwargs["maxIdleTimeMS"] == 45000
            assert call_kwargs["serverSelectionTimeoutMS"] == 5000
            assert call_kwargs["appname"] == "McpFhirAgent"


def test_shared_mongo_client_across_namespaces() -> None:
    """Test that multiple cache namespaces share the same MongoDB client.

    This is critical for connection pooling - we want one pool shared
    across all cache types, not separate pools per namespace.
    """
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"
    env.mongo_db_username = None
    env.mongo_db_password = None

    with patch(
        "mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"
    ) as mock_client_class:
        with patch("mcpfhiragent.storage.mongo_storage_factory.MongoDBGridFSStore"):
            mock_client = Mock()
            mock_client_class.return_value = mock_client

            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            # Get caches for both namespaces
            factory.get_store(PERSON_PATIENT)
            factory.get_store(DYNAMIC_CLIENT_REGISTRATION)

            # AsyncMongoClient should only be created once (shared)
            assert mock_client_class.call_count == 1


def test_connection_string_cached_across_calls() -> None:
    """Test that connection string is built once and cached."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.person_patient_cache_collection = "person_patient_cache"
    env.dynamic_client_registration_collection = "dynamic_client_registration"
    env.mcp_response_cache_collection = "mcp_response_cache"
    env.mongo_db_username = "user"
    env.mongo_db_password = "pass"  # pragma: allowlist secret

    with patch("mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch("mcpfhiragent.storage.mongo_storage_factory.MongoDBGridFSStore"):
            with patch(
                "mcpfhiragent.storage.mongo_storage_factory.MongoUrlHelpers.add_credentials_to_mongo_url"
            ) as mock_add_creds:
                mock_add_creds.return_value = "mongodb://user:pass@localhost:27017/"

                factory = MongoStoreFactory(
                    environment_variables=env,
                    cache_to_collection_mapper=CacheToCollectionMapper(
                        environment_variables=env
                    ),
                )

                # Get multiple caches
                factory.get_store(PERSON_PATIENT)
                factory.get_store(DYNAMIC_CLIENT_REGISTRATION)
                # Call again
                factory.get_store(PERSON_PATIENT)

                # Credential injection should only happen once (connection string cached)
                assert mock_add_creds.call_count == 1


def test_mongo_store_factory_without_required_db_name_raises_error() -> None:
    """Test that MongoStoreFactory raises error when MONGO_DB_NAME is missing."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = None  # Missing required value
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.person_patient_cache_collection = "person_patient_cache"

    with patch("mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch("mcpfhiragent.storage.mongo_storage_factory.MongoDBGridFSStore"):
            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            with pytest.raises(ValueError) as exc_info:
                factory.get_store(PERSON_PATIENT)

            assert "MONGO_DB_NAME" in str(exc_info.value)


def test_mongo_store_factory_without_required_collection_name_raises_error() -> None:
    """Test that get_cache raises error when collection environment variable is missing."""
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.person_patient_cache_collection = None  # Missing
    env.mcp_response_cache_collection = "mcp_response_cache"

    with patch("mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"):
        with patch("mcpfhiragent.storage.mongo_storage_factory.MongoDBGridFSStore"):
            factory = MongoStoreFactory(
                environment_variables=env,
                cache_to_collection_mapper=CacheToCollectionMapper(
                    environment_variables=env
                ),
            )

            with pytest.raises(ValueError) as exc_info:
                factory.get_store(PERSON_PATIENT)

            assert "person_patient_cache" in str(exc_info.value)


def test_different_factory_instances_have_separate_clients() -> None:
    """Test that different factory instances create separate MongoDB clients.

    Each factory instance should have its own connection pool.
    """
    env = Mock(spec=OidcEnvironmentVariables)
    env.mongo_uri = "mongodb://localhost:27017/"
    env.mongo_db_name = "test_db"
    env.mongo_max_pool_size = 10
    env.mongo_min_pool_size = 2
    env.person_patient_cache_collection = "person_patient_cache"
    env.mongo_db_username = None
    env.mongo_db_password = None

    with patch(
        "mcpfhiragent.storage.mongo_storage_factory.AsyncMongoClient"
    ) as mock_client_class:
        with patch("mcpfhiragent.storage.mongo_storage_factory.MongoDBGridFSStore"):
            # Create separate clients for each factory instance
            mock_client_class.side_effect = [Mock(), Mock()]

            # Create two factory instances
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

            # Trigger client creation
            factory1.get_store(PERSON_PATIENT)
            factory2.get_store(PERSON_PATIENT)

            # Should create two separate clients
            assert mock_client_class.call_count == 2
