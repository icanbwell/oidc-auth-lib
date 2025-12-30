"""
MongoDBGridFSStore: GridFS-Backed Key-Value Store for Large Documents

This module extends the base MongoDBStore to add support for storing large values in MongoDB using GridFS.

Key Features:
- Subclasses MongoDBStore, preserving all base functionality for metadata and small values.
- Stores large values (that may exceed MongoDB's 16MB document limit) in GridFS, while keeping metadata (key, collection, timestamps, etc.) in a regular MongoDB collection.
- Each logical collection gets its own GridFS bucket (named <collection>_fs) for isolation and organization.
- All CRUD operations (_get_managed_entry, _put_managed_entry, _delete_managed_entry, etc.) are overridden to use GridFS for value storage and retrieval.
- Metadata and GridFS file references are kept in sync; orphaned files are cleaned up on update/delete.
- Bulk operations and statistics are supported for efficient management and monitoring.
- The implementation is fully async and compatible with pymongo's async GridFS API (pymongo 4.0+).

How it works:
- When storing a value, the value is serialized and uploaded to GridFS. The resulting file_id is stored in the metadata collection.
- When retrieving a value, the file_id is fetched from metadata, and the value is streamed from GridFS and deserialized.
- When deleting, both the metadata and the GridFS file are removed.
- Bulk operations and collection deletion handle all associated GridFS files and metadata.

**Data Model and Linking:**
- The main (metadata) collection stores one document per key. Each document contains:
    - `key`: The unique key for the entry.
    - `collection`: The logical collection name.
    - `created_at`, `expires_at`, `ttl`: Timestamps and TTL metadata.
    - `gridfs_file_id`: The ObjectId reference to the actual value stored in GridFS.
- The actual value is stored as a file in the GridFS bucket for that collection, with the file's ObjectId referenced by `gridfs_file_id` in the metadata document.
- To retrieve a value, the code looks up the metadata document by `key`, reads the `gridfs_file_id`, and fetches the value from GridFS.
- This design allows efficient metadata queries and supports values larger than MongoDB’s document size limit.

This approach allows seamless use of MongoDB for both small and very large values, with minimal changes to the base key-value store interface.

See class and method docstrings for further details.
"""

import json
from datetime import datetime
from typing import Any, Sequence, override

from bson import ObjectId
from gridfs import AsyncGridFSBucket
from key_value.aio.stores.mongodb import MongoDBStore
from key_value.shared.errors import DeserializationError
from key_value.shared.utils.managed_entry import ManagedEntry
from key_value.shared.utils.sanitization import SanitizationStrategy
from pydantic import BaseModel, Field
from pymongo import AsyncMongoClient, UpdateOne
from pymongo.asynchronous.collection import AsyncCollection
from pymongo.asynchronous.command_cursor import AsyncCommandCursor
from pymongo.errors import PyMongoError
from pymongo.results import DeleteResult


# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.trace import Tracer

from oidcauthlib.open_telemetry.attribute_names import OidcOpenTelemetryAttributeNames
from oidcauthlib.open_telemetry.span_names import OidcOpenTelemetrySpanNames
from oidcauthlib.storage.mongo_gridfs_exception import MongoGridFSException


class GridFSFileMetadata(BaseModel):
    # Metadata stored alongside each GridFS file to help with monitoring and debugging
    key: str = Field(description="The key for the stored value.")
    collection: str = Field(description="The collection name.")
    size_bytes: int = Field(description="The size of the stored value in bytes.")
    created_at: datetime | None = Field(
        description="The creation timestamp of the entry."
    )
    expires_at: datetime | None = Field(description="The expiration timestamp, if any.")
    ttl: float | None = Field(description="Time to live in seconds, if any.")


class MongoDBGridFSStore(MongoDBStore):
    """MongoDB-based key-value store using GridFS for large document storage.

    This subclass extends MongoDBStore to store large documents in GridFS instead of
    directly in MongoDB collections. This is useful when documents exceed MongoDB's
    16MB document size limit or when you want to optimize storage for large values.

    Uses pymongo's native async GridFS support (pymongo 4.0+).

    Architecture:
    - Metadata (key, collection, created_at, expires_at, etc.) is stored in regular collections
    - Actual document values are stored in GridFS
    - Each collection gets its own GridFS bucket (e.g., "collection_name_fs")

    Example:
        ```python
        store = MongoDBGridFSStore(
            url="mongodb://localhost:27017",
            db_name="my_database",
            default_collection="large_docs"
        )

        async with store:
            # Store a large document
            await store.put("key1", large_document, collection="large_docs")

            # Retrieve it
            value = await store.get("key1", collection="large_docs")
        ```
    """

    def __init__(
        self,
        *,
        client: AsyncMongoClient[dict[str, Any]] | None = None,
        url: str | None = None,
        db_name: str | None = None,
        coll_name: str | None = None,
        default_collection: str | None = None,
        collection_sanitization_strategy: SanitizationStrategy | None = None,
        gridfs_chunk_size_kb: int = 255,  # 255KB default chunk size
        max_inline_size_kb: int = 16
        * 1024,  # Max size in KB for inline storage: 16MB is mongo limit
    ) -> None:
        """Initialize the MongoDB GridFS store.

        Args:
            client: The MongoDB client to use (mutually exclusive with url). If provided,
                the store will not manage the client's lifecycle.
            url: The url of the MongoDB cluster (mutually exclusive with client).
            db_name: The name of the MongoDB database.
            coll_name: The name of the MongoDB collection.
            default_collection: The default collection to use if no collection is provided.
            collection_sanitization_strategy: The sanitization strategy to use for collections.
            gridfs_chunk_size_kb: Size of GridFS chunks in bytes. Default is 255KB.
                Larger chunks may improve performance for very large files.
            max_inline_size_kb: Maximum size in KB for storing values inline in metadata collection.
        """
        # Validate mutually exclusive client/url inputs and initialize base store
        if client is None and url is None:
            raise ValueError("Either 'client' or 'url' must be provided.")

        if client is not None:
            # Use an externally-managed client
            super().__init__(
                client=client,
                db_name=db_name,
                coll_name=coll_name,
                default_collection=default_collection,
                collection_sanitization_strategy=collection_sanitization_strategy,
            )
        else:
            # Create a client from the URL
            if url is None:
                raise ValueError("'url' must be provided if 'client' is not.")
            super().__init__(
                url=url,
                db_name=db_name,
                coll_name=coll_name,
                default_collection=default_collection,
                collection_sanitization_strategy=collection_sanitization_strategy,
            )
        # Per-collection GridFS bucket cache
        self._gridfs_buckets: dict[str, AsyncGridFSBucket] = {}
        # Configurable chunk size used by GridFS
        self._gridfs_chunk_size_kb: int = gridfs_chunk_size_kb
        # Threshold (bytes) for deciding inline vs GridFS storage
        self.max_inline_size_kb: int = max_inline_size_kb  # in KB
        # Initialize tracer for OpenTelemetry to instrument operations
        self._tracer: Tracer = trace.get_tracer("oidcauthlib.storage.mongo_gridfs_db")

    @override
    async def setup_collection(self, *, collection: str) -> None:
        """Set up both metadata collection and GridFS bucket for a collection."""
        # Sanitize the user-supplied name to ensure valid MongoDB identifiers
        sanitized_collection = self._sanitize_collection(collection=collection)

        # Determine whether the metadata collection already exists
        collection_filter: dict[str, str] = {"name": sanitized_collection}
        matching_collections: list[str] = await self._db.list_collection_names(
            filter=collection_filter
        )

        if matching_collections:
            # Reuse existing collection handle
            self._collections_by_name[collection] = self._db[sanitized_collection]
        else:
            # Create new metadata collection and required indexes
            new_collection: AsyncCollection[
                dict[str, Any]
            ] = await self._db.create_collection(name=sanitized_collection)

            # Unique index on key prevents duplicates and speeds lookups
            _ = await new_collection.create_index(keys="key", unique=True)

            # TTL index expires metadata docs; GridFS file cleanup handled separately
            _ = await new_collection.create_index(
                keys="expires_at", expireAfterSeconds=0
            )

            # Index on GridFS file id enables efficient maintenance operations
            _ = await new_collection.create_index(keys="gridfs_file_id")

            self._collections_by_name[collection] = new_collection

        # Initialize a dedicated GridFS bucket per logical collection
        gridfs_bucket_name = f"{sanitized_collection}_fs"
        self._gridfs_buckets[collection] = AsyncGridFSBucket(
            self._db,
            bucket_name=gridfs_bucket_name,
            chunk_size_bytes=self._gridfs_chunk_size_kb * 1024,
        )

    def _reconstruct_managed_entry_from_metadata(
        self,
        *,
        key: str,
        collection: str,
        metadata_doc: dict[str, Any],
    ) -> ManagedEntry | None:
        """Helper to reconstruct a ManagedEntry from metadata, handling inline/GridFS.

        If the value is stored inline in the metadata document (below size threshold),
        rebuild the ManagedEntry directly. Otherwise return None so the caller can
        load from GridFS using the stored file id.
        """
        # Minimize span noise: no span for this lightweight helper
        if "inline_value" in metadata_doc:
            # Inline storage path: value is embedded in the metadata document
            stored_value = metadata_doc["inline_value"]
            # Do NOT unwrap here; adapter expects a wrapper with 'object'
            full_doc: dict[str, Any] = {
                "key": key,
                "collection": collection,
                "value": stored_value,
            }
            created_at = metadata_doc.get("created_at")
            if created_at is not None:
                full_doc["created_at"] = created_at
            expires_at = metadata_doc.get("expires_at")
            if expires_at is not None:
                full_doc["expires_at"] = expires_at
            ttl = metadata_doc.get("ttl")
            if ttl is not None:
                full_doc["ttl"] = ttl
            try:
                return self._adapter.load_dict(data=full_doc)
            except Exception as e:
                raise e
        # Not inline; caller will continue with GridFS lookup
        return None  # GridFS case handled by caller

    async def _get_gridfs_value(
        self,
        *,
        key: str,
        collection: str,
        gridfs_file_id: ObjectId,
        metadata_doc: dict[str, Any],
    ) -> ManagedEntry | None:
        """Stream and deserialize value bytes from GridFS for a given file id."""
        # Open a download stream from GridFS and read all bytes
        gridfs_bucket: AsyncGridFSBucket = self._gridfs_buckets[collection]
        grid_out = await gridfs_bucket.open_download_stream(gridfs_file_id)
        value_bytes = await grid_out.read()
        # BSON GridFS stores raw bytes; decode and parse JSON payload
        value_str = value_bytes.decode("utf-8")
        parsed: Any = json.loads(value_str)
        full_doc: dict[str, Any] = {
            "key": key,
            "collection": collection,
            "value": parsed,
        }
        created_at = metadata_doc.get("created_at")
        if created_at is not None:
            full_doc["created_at"] = created_at
        expires_at = metadata_doc.get("expires_at")
        if expires_at is not None:
            full_doc["expires_at"] = expires_at
        ttl = metadata_doc.get("ttl")
        if ttl is not None:
            full_doc["ttl"] = ttl
        return self._adapter.load_dict(data=full_doc)

    async def _serialize_and_store_entry(
        self,
        *,
        key: str,
        collection: str,
        managed_entry: ManagedEntry,
        gridfs_bucket: AsyncGridFSBucket,
        existing_metadata: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Serialize the entry and choose inline vs GridFS storage.

        - Serialize value to JSON bytes for consistent storage format.
        - If below threshold, embed in metadata as `inline_value`.
        - If above threshold, upload to GridFS and reference the file id in metadata.
        - Clean up any previously stored GridFS file when updating entries.
        """
        value_to_store: dict[str, Any] = {"object": managed_entry.value}
        value_json = json.dumps(value_to_store)
        value_bytes = value_json.encode("utf-8")
        value_size = len(value_bytes)
        value_to_store["size"] = value_size
        mongo_doc = self._adapter.dump_dict(
            entry=managed_entry, key=key, collection=collection
        )
        mongo_doc.pop("value", None)
        # Decide storage location based on configured threshold
        if value_size < self.max_inline_size_kb * 1024:
            # Inline storage: embed value and remove GridFS reference
            mongo_doc["inline_value"] = value_to_store
            mongo_doc.pop("gridfs_file_id", None)
            # Remove old GridFS file if present
            if existing_metadata and "gridfs_file_id" in existing_metadata:
                old_file_id: ObjectId = existing_metadata["gridfs_file_id"]
                try:
                    await gridfs_bucket.delete(old_file_id)
                except Exception as e:
                    raise MongoGridFSException(
                        f"Failed to delete old GridFS file with id {old_file_id}"
                    ) from e
        else:
            # GridFS storage: upload bytes and store file id reference
            gridfs_file_id: ObjectId = await gridfs_bucket.upload_from_stream(
                filename=f"{collection}:{key}",
                source=value_bytes,
                metadata=GridFSFileMetadata(
                    key=key,
                    collection=collection,
                    size_bytes=value_size,
                    created_at=managed_entry.created_at,
                    expires_at=managed_entry.expires_at,
                    ttl=managed_entry.ttl,
                ).model_dump(),
            )
            mongo_doc["gridfs_file_id"] = gridfs_file_id
            mongo_doc["size"] = value_size
            mongo_doc.pop("inline_value", None)
            # Remove old GridFS file if present and different
            if existing_metadata and "gridfs_file_id" in existing_metadata:
                old_file_id1: ObjectId = existing_metadata["gridfs_file_id"]
                if old_file_id1 != gridfs_file_id:
                    try:
                        await gridfs_bucket.delete(old_file_id1)
                    except Exception as e:
                        raise MongoGridFSException(
                            f"Failed to delete old GridFS file with id {old_file_id1}"
                        ) from e
        return mongo_doc

    @override
    async def _get_managed_entry(
        self, *, key: str, collection: str
    ) -> ManagedEntry | None:
        """Retrieve a single ManagedEntry, preferring inline and falling back to GridFS."""
        with self._tracer.start_as_current_span(
            OidcOpenTelemetrySpanNames.MONGO_GRIDFS_GET_MANAGED_ENTRY
        ) as span:
            span.set_attribute(
                OidcOpenTelemetryAttributeNames.DB_COLLECTION, collection
            )
            span.set_attribute(OidcOpenTelemetryAttributeNames.STORAGE_KEY, key)
            # Lookup metadata by key; contains either inline value or GridFS file id
            metadata_doc = await self._collections_by_name[collection].find_one(
                filter={"key": key}
            )
            if not metadata_doc:
                span.set_attribute(OidcOpenTelemetryAttributeNames.STORAGE_HIT, False)
                return None
            try:
                # First try the inline path (fastest)
                entry = self._reconstruct_managed_entry_from_metadata(
                    key=key, collection=collection, metadata_doc=metadata_doc
                )
                if entry is not None:
                    span.set_attribute(
                        OidcOpenTelemetryAttributeNames.STORAGE_HIT, True
                    )
                    return entry
                # Otherwise use the GridFS file id if present
                gridfs_file_id: ObjectId | None = metadata_doc.get("gridfs_file_id")
                if not gridfs_file_id:
                    # Metadata exists but lacks value; treat as missing
                    span.set_attribute(
                        OidcOpenTelemetryAttributeNames.STORAGE_MODE, "missing"
                    )
                    return None
                span.set_attribute(
                    OidcOpenTelemetryAttributeNames.STORAGE_MODE, "gridfs"
                )
                return await self._get_gridfs_value(
                    key=key,
                    collection=collection,
                    gridfs_file_id=gridfs_file_id,
                    metadata_doc=metadata_doc,
                )
            except (
                DeserializationError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as e:
                # Decode or deserialization issues indicate corrupted payloads
                raise MongoGridFSException(
                    f"Failed to deserialize entry for key '{key}' in collection '{collection}'"
                ) from e
            except Exception as e:
                # Catch-all for unexpected database / IO errors
                raise MongoGridFSException(
                    f"Failed to retrieve entry for key '{key}' in collection '{collection}'"
                ) from e

    @override
    async def _get_managed_entries(
        self, *, collection: str, keys: Sequence[str]
    ) -> list[ManagedEntry | None]:
        """Batch retrieval for multiple keys, mixing inline and GridFS paths.

        Maintains result order aligned with the input keys and returns None for
        any missing entries.
        """
        if not keys:
            return []
        # Query all candidate metadata docs in one cursor
        cursor = self._collections_by_name[collection].find(
            filter={"key": {"$in": list(keys)}}
        )
        managed_entries_by_key: dict[str, ManagedEntry | None] = dict.fromkeys(keys)
        async for metadata_doc in cursor:
            key = metadata_doc.get("key")
            if not key:
                continue
            try:
                # Prefer inline value when available
                entry = self._reconstruct_managed_entry_from_metadata(
                    key=key, collection=collection, metadata_doc=metadata_doc
                )
                if entry is not None:
                    managed_entries_by_key[key] = entry
                    continue
                # Fallback to GridFS
                gridfs_file_id: ObjectId | None = metadata_doc.get("gridfs_file_id")
                if not gridfs_file_id:
                    managed_entries_by_key[key] = None
                    continue
                managed_entries_by_key[key] = await self._get_gridfs_value(
                    key=key,
                    collection=collection,
                    gridfs_file_id=gridfs_file_id,
                    metadata_doc=metadata_doc,
                )
            except (
                DeserializationError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as e:
                raise MongoGridFSException(
                    f"Failed to deserialize entry for key '{key}' in collection '{collection}'"
                ) from e
            except Exception as e:
                raise MongoGridFSException(
                    f"Unexpected error retrieving entry for key '{key}' in collection '{collection}'"
                ) from e
        # Preserve input key order
        return [managed_entries_by_key[key] for key in keys]

    @override
    async def _put_managed_entry(
        self,
        *,
        key: str,
        collection: str,
        managed_entry: ManagedEntry,
    ) -> None:
        """Upsert a single entry, cleaning up any prior GridFS file when needed."""
        with self._tracer.start_as_current_span(
            OidcOpenTelemetrySpanNames.MONGO_GRIDFS_PUT_MANAGED_ENTRY
        ) as span:
            span.set_attribute(
                OidcOpenTelemetryAttributeNames.DB_COLLECTION, collection
            )
            span.set_attribute(OidcOpenTelemetryAttributeNames.STORAGE_KEY, key)
            gridfs_bucket = self._gridfs_buckets[collection]
            # Check existing metadata so we can remove any old GridFS file if updated
            existing_metadata = await self._collections_by_name[collection].find_one(
                filter={"key": key}
            )
            try:
                mongo_doc = await self._serialize_and_store_entry(
                    key=key,
                    collection=collection,
                    managed_entry=managed_entry,
                    gridfs_bucket=gridfs_bucket,
                    existing_metadata=existing_metadata,
                )
                # Upsert ensures idempotent create/update behavior
                unset_fields: dict[str, str] = {}
                if "inline_value" in mongo_doc:
                    unset_fields = {"gridfs_file_id": "", "size": ""}
                else:
                    unset_fields = {"inline_value": ""}
                update_doc: dict[str, Any] = {"$set": mongo_doc}
                if unset_fields:
                    update_doc["$unset"] = unset_fields
                await self._collections_by_name[collection].update_one(
                    filter={"key": key},
                    update=update_doc,
                    upsert=True,
                )
            except PyMongoError as e:
                # Provide a clear message for MongoDB-specific failures
                msg = f"Failed to update MongoDB document: {e}"
                raise MongoGridFSException(msg) from e
            except Exception as e:
                # Catch-all for unexpected errors during serialization or upload
                msg = f"Failed to store entry: {e}"
                raise MongoGridFSException(msg) from e

    @override
    async def _put_managed_entries(
        self,
        *,
        collection: str,
        keys: Sequence[str],
        managed_entries: Sequence[ManagedEntry],
        ttl: float | None,
        created_at: datetime,
        expires_at: datetime | None,
    ) -> None:
        """Bulk upsert multiple entries, mixing inline and GridFS storage as needed."""
        if not keys:
            return
        if created_at is None:
            raise MongoGridFSException(
                "created_at must be provided when storing managed entries."
            )
        if not collection:
            raise MongoGridFSException(
                "collection must be provided when storing managed entries."
            )
        gridfs_bucket = self._gridfs_buckets[collection]
        # Read existing docs once to enable old GridFS cleanup during updates
        existing_docs: dict[str, dict[str, Any]] = {}
        cursor = self._collections_by_name[collection].find(
            filter={"key": {"$in": list(keys)}}
        )
        async for doc in cursor:
            if key := doc.get("key"):
                existing_docs[key] = doc
        operations: list[UpdateOne] = []
        for key, managed_entry in zip(keys, managed_entries, strict=True):
            try:
                mongo_doc = await self._serialize_and_store_entry(
                    key=key,
                    collection=collection,
                    managed_entry=managed_entry,
                    gridfs_bucket=gridfs_bucket,
                    existing_metadata=existing_docs.get(key),
                )
                # Ensure bulk operations set consistent timestamps/ttl
                mongo_doc["created_at"] = created_at
                mongo_doc["expires_at"] = expires_at or managed_entry.expires_at
                mongo_doc["ttl"] = ttl or managed_entry.ttl
                unset_fields: dict[str, str] = {}
                if "inline_value" in mongo_doc:
                    unset_fields = {"gridfs_file_id": "", "size": ""}
                else:
                    unset_fields = {"inline_value": ""}
                update_doc: dict[str, Any] = {"$set": mongo_doc}
                if unset_fields:
                    update_doc["$unset"] = unset_fields
                operations.append(UpdateOne({"key": key}, update_doc, upsert=True))
            except Exception as e:
                raise MongoGridFSException(
                    f"Failed to store entry for key '{key}' in collection '{collection}'"
                ) from e
        if operations:
            await self._collections_by_name[collection].bulk_write(operations)

    @override
    async def _delete_managed_entry(self, *, key: str, collection: str) -> bool:
        """Delete a managed entry from both metadata collection and GridFS.

        Args:
            key: The key to delete.
            collection: The collection containing the key.

        Returns:
            True if the entry was deleted, False if it didn't exist.
        """
        metadata_doc = await self._collections_by_name[collection].find_one(
            filter={"key": key}
        )

        if not metadata_doc:
            return False

        # Delete from GridFS if file exists
        if gridfs_file_id := metadata_doc.get("gridfs_file_id"):
            try:
                await self._gridfs_buckets[collection].delete(gridfs_file_id)
            except Exception as e:
                raise MongoGridFSException(
                    f"Failed to delete GridFS file with id {gridfs_file_id}"
                ) from e

        # Delete metadata
        result: DeleteResult = await self._collections_by_name[collection].delete_one(
            filter={"key": key}
        )

        return bool(result.deleted_count)

    @override
    async def _delete_managed_entries(
        self, *, keys: Sequence[str], collection: str
    ) -> int:
        """Delete multiple managed entries efficiently.

        Args:
            keys: Sequence of keys to delete.
            collection: The collection to delete from.

        Returns:
            Number of entries deleted.
        """
        if not keys:
            return 0

        # Get all metadata documents to find GridFS file IDs
        cursor = self._collections_by_name[collection].find(
            filter={"key": {"$in": list(keys)}}
        )

        gridfs_bucket = self._gridfs_buckets[collection]
        deleted_count = 0

        # Delete all GridFS files
        async for metadata_doc in cursor:
            if gridfs_file_id := metadata_doc.get("gridfs_file_id"):
                try:
                    await gridfs_bucket.delete(gridfs_file_id)
                    deleted_count += 1
                except Exception:
                    # Continue even if deletion fails; record for observability
                    pass

        # Delete all metadata documents in one operation
        result: DeleteResult = await self._collections_by_name[collection].delete_many(
            filter={"key": {"$in": list(keys)}}
        )

        return result.deleted_count

    @override
    async def _delete_collection(self, *, collection: str) -> bool:
        """Delete both metadata collection and all associated GridFS files.

        This is a destructive operation that removes:
        - The metadata collection
        - All GridFS files for this collection
        - The GridFS bucket collections (fs.files and fs.chunks)

        Args:
            collection: The collection to delete.

        Returns:
            True if the collection was deleted successfully.
        """
        collection_name = self._collections_by_name[collection].name
        gridfs_bucket = self._gridfs_buckets[collection]

        # Get all metadata documents to find GridFS file IDs
        cursor = self._collections_by_name[collection].find({})
        async for metadata_doc in cursor:
            if gridfs_file_id := metadata_doc.get("gridfs_file_id"):
                try:
                    await gridfs_bucket.delete(gridfs_file_id)
                except Exception:
                    pass

        # Drop the metadata collection
        _ = await self._db.drop_collection(name_or_collection=collection_name)

        # Drop the GridFS collections (bucket_name.files and bucket_name.chunks)
        sanitized_collection = self._sanitize_collection(collection=collection)
        gridfs_bucket_name = f"{sanitized_collection}_fs"

        try:
            await self._db.drop_collection(f"{gridfs_bucket_name}.files")
            await self._db.drop_collection(f"{gridfs_bucket_name}.chunks")
        except Exception:
            pass

        # Clean up internal references so future operations fail fast
        self._collections_by_name.pop(collection, None)
        self._gridfs_buckets.pop(collection, None)

        return True

    async def get_gridfs_stats(self, *, collection: str) -> dict[str, Any]:
        """Get statistics about GridFS storage for a collection.

        Useful for monitoring storage usage and performance.

        Args:
            collection: The collection to get stats for.

        Returns:
            Dictionary containing:
            - total_files: Number of files stored
            - total_size_bytes: Total size of all files
            - avg_file_size_bytes: Average file size
            - chunk_size_bytes: Configured chunk size
        """
        sanitized_collection = self._sanitize_collection(collection=collection)
        gridfs_bucket_name = f"{sanitized_collection}_fs"
        files_collection = self._db[f"{gridfs_bucket_name}.files"]
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total_files": {"$sum": 1},
                    "total_size_bytes": {"$sum": "$length"},
                    "avg_file_size_bytes": {"$avg": "$length"},
                }
            }
        ]
        cursor: AsyncCommandCursor[Any] = await files_collection.aggregate(pipeline)
        result = await cursor.to_list(length=1)
        if result:
            stats = result[0]
            if not isinstance(stats, dict):
                return {
                    "total_files": 0,
                    "total_size_bytes": 0,
                    "avg_file_size_bytes": 0,
                    "chunk_size_bytes": self._gridfs_chunk_size_kb * 1024,
                }
            stats.pop("_id", None)
            stats["chunk_size_bytes"] = self._gridfs_chunk_size_kb * 1024
            return stats
        return {
            "total_files": 0,
            "total_size_bytes": 0,
            "avg_file_size_bytes": 0,
            "chunk_size_bytes": self._gridfs_chunk_size_kb * 1024,
        }
