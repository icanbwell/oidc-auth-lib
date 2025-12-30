import os
from enum import Enum
from typing import Optional, override

from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)


class CacheProvider(str, Enum):
    """Cache provider types - a single source of truth for cache implementations."""

    MONGODB = "mongodb"
    REDIS = "redis"
    MEMORY = "memory"


class OidcEnvironmentVariables(AbstractEnvironmentVariables):
    @staticmethod
    @override
    def str2bool(v: str | None) -> bool:
        return v is not None and str(v).lower() in ("yes", "true", "t", "1", "y")

    @property
    @override
    def oauth_cache(self) -> str:
        return os.environ.get("OAUTH_CACHE", "memory")

    @property
    @override
    def mongo_uri(self) -> Optional[str]:
        return os.environ.get("MONGO_URL")

    @property
    @override
    def mongo_db_name(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_NAME")

    @property
    @override
    def mongo_db_username(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_USERNAME")

    @property
    @override
    def mongo_db_password(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_PASSWORD")

    @property
    @override
    def mongo_db_auth_cache_collection_name(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_AUTH_CACHE_COLLECTION_NAME")

    @property
    @override
    def mongo_db_cache_disable_delete(self) -> Optional[bool]:
        return self.str2bool(os.environ.get("MONGO_DB_AUTH_CACHE_DISABLE_DELETE"))

    @property
    @override
    def auth_providers(self) -> Optional[list[str]]:
        auth_providers: str | None = os.environ.get("AUTH_PROVIDERS")
        return (
            [p.strip() for p in auth_providers.split(",")] if auth_providers else None
        )

    @property
    @override
    def oauth_referring_email(self) -> Optional[str]:
        return os.environ.get("OAUTH_REFERRING_EMAIL")

    @property
    @override
    def oauth_referring_subject(self) -> Optional[str]:
        return os.environ.get("OAUTH_REFERRING_SUBJECT")

    @property
    @override
    def auth_redirect_uri(self) -> Optional[str]:
        return os.environ.get("AUTH_REDIRECT_URI")

    @property
    def cache_provider(self) -> CacheProvider:
        """
        Cache provider type.

        Determines which provider to use for cache implementations.
        See the CacheProvider enum for valid values.

        Set via CACHE_PROVIDER environment variable.
        Defaults to mongodb.

        Returns:
            CacheProvider enum value

        Raises:
            ValueError: If an invalid provider type specified
        """
        provider_str = os.environ.get(
            "CACHE_PROVIDER", CacheProvider.MONGODB.value
        ).lower()

        try:
            return CacheProvider(provider_str)
        except ValueError:
            valid_values = [p.value for p in CacheProvider]
            raise ValueError(
                f"CACHE_PROVIDER must be one of {valid_values}, got '{provider_str}'"
            )

    @property
    def mongo_max_pool_size(self) -> int:
        """
        Maximum MongoDB connection pool size per store.

        Controls the maximum number of concurrent connections each MongoDB store
        can maintain. Higher values allow more concurrent operations but consume
        more resources. Defaults to 10 connections.
        """
        size = int(os.environ.get("MONGO_MAX_POOL_SIZE", "10"))
        if size < 1:
            raise ValueError(f"MONGO_MAX_POOL_SIZE must be >= 1, got {size}")
        if size > 100:
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(
                f"MONGO_MAX_POOL_SIZE={size} is very high, consider reducing to avoid resource exhaustion"
            )
        return size

    @property
    def mongo_min_pool_size(self) -> int:
        """
        Minimum MongoDB connection pool size per store.

        Controls the number of connections to keep alive. Higher values reduce
         the latency for cold starts but consume more resources. Defaults to 2.
        """
        size = int(os.environ.get("MONGO_MIN_POOL_SIZE", "2"))
        if size < 0:
            raise ValueError(f"MONGO_MIN_POOL_SIZE must be >= 0, got {size}")
        if size > self.mongo_max_pool_size:
            raise ValueError(
                f"MONGO_MIN_POOL_SIZE ({size}) cannot exceed MONGO_MAX_POOL_SIZE ({self.mongo_max_pool_size})"
            )
        return size

    @property
    def well_known_configuration_collection_name(self) -> str:
        """
        MongoDB collection name for well-known configuration cache.

        Set via MONGO_DB_WELL_KNOWN_CONFIGURATION_COLLECTION_NAME environment variable.
        Defaults to 'well_known_configuration_cache'.
        """
        return os.environ.get(
            "MONGO_DB_WELL_KNOWN_CONFIGURATION_COLLECTION_NAME",
            "well_known_configuration_cache",
        )

    @property
    def gridfs_chunk_size_kb(self) -> int:
        """GridFS chunk size in KB for storing large files in MongoDB.

        Controls the size of each chunk when storing files in GridFS.
        Larger chunk sizes can improve performance for large files
        but consume more memory during read/write operations.

        Set via GRIDFS_CHUNK_SIZE_KB environment variable.
        Defaults to 255KB.

        Returns:
            Chunk size in KB

        Raises:
            ValueError: If chunk size is not a positive integer
        """
        try:
            chunk_size = int(os.environ.get("GRIDFS_CHUNK_SIZE_KB", str(255)))
            return chunk_size
        except ValueError:
            raise ValueError(
                "GRIDFS_CHUNK_SIZE_KB must be a positive integer representing bytes"
            )

    @property
    def max_mongo_inline_size_kb(self) -> int:
        """Maximum size in KB for inline storage in MongoDB.

        Controls the maximum size of documents to store inline
        versus using GridFS.

        Set via MAX_MONGO_INLINE_SIZE_KB environment variable.
        Defaults to 14MB.

        Returns:
            Maximum inline size in KB

        Raises:
            ValueError: If size is not a positive integer
        """
        try:
            max_size = int(os.environ.get("MAX_MONGO_INLINE_SIZE_KB", str(14 * 1024)))
            return max_size
        except ValueError:
            raise ValueError(
                "MAX_MONGO_INLINE_SIZE_KB must be a positive integer representing bytes"
            )
