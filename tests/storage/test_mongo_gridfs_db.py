from datetime import datetime, UTC
from typing import cast, override, Mapping

import pytest
from bson import ObjectId
from key_value.shared.utils.managed_entry import ManagedEntry
from oidcauthlib.container.interfaces import IContainer
from oidcauthlib.storage.cache_to_collection_mapper import CacheToCollectionMapper
from oidcauthlib.storage.storage_factory import StorageFactory

from oidcauthlib.storage.mongo_gridfs_db import MongoDBGridFSStore
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)

TEST_CACHE = "test_cache"


class TestCacheToCollectionMapper(CacheToCollectionMapper):
    def __init__(
        self,
        *,
        environment_variables: OidcEnvironmentVariables,
        mapping: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(environment_variables=environment_variables)
        if mapping is None:
            mapping = {
                TEST_CACHE: "test_collection",
            }
        self.mapping = mapping

    @override
    def get_collection_for_cache(self, *, cache_name: str) -> str | None:
        return self.mapping.get(cache_name)


@pytest.mark.asyncio
async def test_inline_store_and_get_roundtrip(test_container: IContainer) -> None:
    """
    Validate inline storage roundtrip:
    - Use small payload so value is stored inline in metadata (not GridFS)
    - Put entry, then get it, and assert ManagedEntry.value matches original object
    """
    test_container.singleton(
        CacheToCollectionMapper,
        lambda c: TestCacheToCollectionMapper(
            environment_variables=c.resolve(OidcEnvironmentVariables)
        ),
    )
    storage_factory: StorageFactory = test_container.resolve(StorageFactory)
    store = cast(MongoDBGridFSStore, storage_factory.get_store(TEST_CACHE))
    await store.setup_collection(collection="gridfs_inline_test")

    entry = ManagedEntry(
        value={"hello": "world"}, created_at=datetime.now(UTC), expires_at=None
    )
    await store._put_managed_entry(
        key="k_inline", collection="gridfs_inline_test", managed_entry=entry
    )
    got = await store._get_managed_entry(
        key="k_inline", collection="gridfs_inline_test"
    )
    assert got is not None
    assert isinstance(got.value, dict)
    assert got.value == {"hello": "world"}


@pytest.mark.asyncio
async def test_gridfs_store_and_get_roundtrip(test_container: IContainer) -> None:
    """
    Validate GridFS storage roundtrip:
    - Force GridFS by lowering inline threshold
    - Store a large payload, then retrieve it, verifying value integrity
    """
    test_container.singleton(
        CacheToCollectionMapper,
        lambda c: TestCacheToCollectionMapper(
            environment_variables=c.resolve(OidcEnvironmentVariables)
        ),
    )
    storage_factory: StorageFactory = test_container.resolve(StorageFactory)
    store = cast(MongoDBGridFSStore, storage_factory.get_store(TEST_CACHE))
    await store.setup_collection(collection="gridfs_big_test")

    # Force GridFS by using a tiny inline threshold
    store.max_inline_size_kb = 1  # 1KB
    large_obj = {"data": "x" * 5000}
    entry = ManagedEntry(value=large_obj, created_at=datetime.now(UTC), expires_at=None)

    await store._put_managed_entry(
        key="k_big", collection="gridfs_big_test", managed_entry=entry
    )
    got = await store._get_managed_entry(key="k_big", collection="gridfs_big_test")
    assert got is not None
    assert got.value == large_obj


@pytest.mark.asyncio
async def test_update_cleanup_old_gridfs_file(test_container: IContainer) -> None:
    """
    Validate cleanup when switching from GridFS to inline:
    - Write a large (GridFS) entry, then update same key with small (inline) entry
    - Assert metadata has inline_value and old gridfs_file_id is removed
    - Verify retrieved value is the new small object
    """
    test_container.singleton(
        CacheToCollectionMapper,
        lambda c: TestCacheToCollectionMapper(
            environment_variables=c.resolve(OidcEnvironmentVariables)
        ),
    )
    storage_factory: StorageFactory = test_container.resolve(StorageFactory)
    store = cast(MongoDBGridFSStore, storage_factory.get_store(TEST_CACHE))
    await store.setup_collection(collection="gridfs_update_test")

    store.max_inline_size_kb = 1  # force gridfs for large
    # first write large
    large_obj = {"data": "y" * 6000}
    entry1 = ManagedEntry(
        value=large_obj, created_at=datetime.now(UTC), expires_at=None
    )
    await store._put_managed_entry(
        key="k_update", collection="gridfs_update_test", managed_entry=entry1
    )

    # capture existing file id from metadata
    metadata_doc = await store._collections_by_name["gridfs_update_test"].find_one(
        filter={"key": "k_update"}
    )
    assert metadata_doc is not None
    old_id_val = metadata_doc.get("gridfs_file_id")
    assert isinstance(old_id_val, ObjectId)

    # now update with small inline value
    small_obj = {"ok": True}
    entry2 = ManagedEntry(
        value=small_obj, created_at=datetime.now(UTC), expires_at=None
    )
    await store._put_managed_entry(
        key="k_update", collection="gridfs_update_test", managed_entry=entry2
    )

    # metadata should now have inline_value and old gridfs id removed
    metadata_doc2 = await store._collections_by_name["gridfs_update_test"].find_one(
        filter={"key": "k_update"}
    )
    assert metadata_doc2 is not None
    assert "inline_value" in metadata_doc2
    assert (
        "gridfs_file_id" not in metadata_doc2
        or metadata_doc2.get("gridfs_file_id") is None
    )

    got2 = await store._get_managed_entry(
        key="k_update", collection="gridfs_update_test"
    )
    assert got2 is not None
    assert got2.value == small_obj


@pytest.mark.asyncio
async def test_batch_get_mixed_inline_and_gridfs(test_container: IContainer) -> None:
    """
    Validate batch get across mixed storage modes:
    - Store one inline and one GridFS entry; request both plus a missing key
    - Assert order preservation and None for missing entry
    """
    test_container.singleton(
        CacheToCollectionMapper,
        lambda c: TestCacheToCollectionMapper(
            environment_variables=c.resolve(OidcEnvironmentVariables)
        ),
    )
    storage_factory: StorageFactory = test_container.resolve(StorageFactory)
    store = cast(MongoDBGridFSStore, storage_factory.get_store(TEST_CACHE))
    await store.setup_collection(collection="gridfs_batch_test")

    # Configure threshold to force GridFS for larger doc
    store.max_inline_size_kb = 1

    # Prepare entries: one small inline, one large gridfs, one missing
    small = ManagedEntry(value={"s": 1}, created_at=datetime.now(UTC), expires_at=None)
    large = ManagedEntry(
        value={"l": "z" * 5000}, created_at=datetime.now(UTC), expires_at=None
    )

    await store._put_managed_entry(
        key="k_small", collection="gridfs_batch_test", managed_entry=small
    )
    await store._put_managed_entry(
        key="k_large", collection="gridfs_batch_test", managed_entry=large
    )

    # Batch get
    results = await store._get_managed_entries(
        collection="gridfs_batch_test", keys=["k_small", "k_large", "k_missing"]
    )
    assert len(results) == 3
    assert results[0] is not None and results[0].value == {"s": 1}
    assert results[1] is not None and results[1].value == {"l": "z" * 5000}
    assert results[2] is None


@pytest.mark.asyncio
async def test_batch_get_all_missing_returns_nones(test_container: IContainer) -> None:
    """
    Validate batch get behavior when all keys are missing:
    - Request multiple missing keys and assert the result list contains only None values
    """
    test_container.singleton(
        CacheToCollectionMapper,
        lambda c: TestCacheToCollectionMapper(
            environment_variables=c.resolve(OidcEnvironmentVariables)
        ),
    )
    storage_factory: StorageFactory = test_container.resolve(StorageFactory)
    store = cast(MongoDBGridFSStore, storage_factory.get_store(TEST_CACHE))
    await store.setup_collection(collection="gridfs_all_missing_test")

    keys = ["na1", "na2", "na3"]
    results = await store._get_managed_entries(
        collection="gridfs_all_missing_test", keys=keys
    )
    assert len(results) == 3
    assert all(r is None for r in results)


@pytest.mark.asyncio
async def test_delete_managed_entries_bulk(test_container: IContainer) -> None:
    """
    Validate bulk deletion path:
    - Store three entries (mix inline/GridFS), delete two keys via bulk delete
    - Assert deleted keys return None and remaining key returns its value
    """
    test_container.singleton(
        CacheToCollectionMapper,
        lambda c: TestCacheToCollectionMapper(
            environment_variables=c.resolve(OidcEnvironmentVariables)
        ),
    )
    storage_factory: StorageFactory = test_container.resolve(StorageFactory)
    store = cast(MongoDBGridFSStore, storage_factory.get_store(TEST_CACHE))
    await store.setup_collection(collection="gridfs_delete_bulk")

    store.max_inline_size_kb = 1
    e1 = ManagedEntry(value={"a": 1}, created_at=datetime.now(UTC), expires_at=None)
    e2 = ManagedEntry(
        value={"b": "q" * 5000}, created_at=datetime.now(UTC), expires_at=None
    )
    e3 = ManagedEntry(value={"c": 3}, created_at=datetime.now(UTC), expires_at=None)

    await store._put_managed_entry(
        key="a", collection="gridfs_delete_bulk", managed_entry=e1
    )
    await store._put_managed_entry(
        key="b", collection="gridfs_delete_bulk", managed_entry=e2
    )
    await store._put_managed_entry(
        key="c", collection="gridfs_delete_bulk", managed_entry=e3
    )

    # Delete two keys
    deleted = await store._delete_managed_entries(
        keys=["a", "b"], collection="gridfs_delete_bulk"
    )
    assert deleted >= 2

    # Verify remaining
    r_a = await store._get_managed_entry(key="a", collection="gridfs_delete_bulk")
    r_b = await store._get_managed_entry(key="b", collection="gridfs_delete_bulk")
    r_c = await store._get_managed_entry(key="c", collection="gridfs_delete_bulk")
    assert r_a is None and r_b is None and r_c is not None and r_c.value == {"c": 3}


@pytest.mark.asyncio
async def test_delete_managed_entry_single_path(test_container: IContainer) -> None:
    """
    Validate single-key deletion path:
    - Store one entry, delete it via _delete_managed_entry, verify it's gone
    - Deleting a non-existent key should return False
    """
    test_container.singleton(
        CacheToCollectionMapper,
        lambda c: TestCacheToCollectionMapper(
            environment_variables=c.resolve(OidcEnvironmentVariables)
        ),
    )
    storage_factory: StorageFactory = test_container.resolve(StorageFactory)
    store = cast(MongoDBGridFSStore, storage_factory.get_store(TEST_CACHE))
    await store.setup_collection(collection="gridfs_delete_single")

    store.max_inline_size_kb = 1
    e = ManagedEntry(
        value={"one": "value"}, created_at=datetime.now(UTC), expires_at=None
    )
    await store._put_managed_entry(
        key="one", collection="gridfs_delete_single", managed_entry=e
    )

    # Ensure exists
    assert (
        await store._get_managed_entry(key="one", collection="gridfs_delete_single")
        is not None
    )

    # Delete single
    ok = await store._delete_managed_entry(key="one", collection="gridfs_delete_single")
    assert ok is True
    # Verify gone
    assert (
        await store._get_managed_entry(key="one", collection="gridfs_delete_single")
        is None
    )

    # Delete non-existent
    ok2 = await store._delete_managed_entry(
        key="missing", collection="gridfs_delete_single"
    )
    assert ok2 is False


@pytest.mark.asyncio
async def test_gridfs_stats_and_delete_collection(test_container: IContainer) -> None:
    """
    Validate stats aggregation and collection deletion:
    - Write two GridFS entries and assert stats fields/values
    - Delete the collection; internal references should be removed
    - Re-setup the collection and assert subsequent gets return None
    """
    test_container.singleton(
        CacheToCollectionMapper,
        lambda c: TestCacheToCollectionMapper(
            environment_variables=c.resolve(OidcEnvironmentVariables)
        ),
    )
    storage_factory: StorageFactory = test_container.resolve(StorageFactory)
    store = cast(MongoDBGridFSStore, storage_factory.get_store(TEST_CACHE))
    await store.setup_collection(collection="gridfs_stats_test")

    # Write a couple of gridfs entries
    store.max_inline_size_kb = 1
    e1 = ManagedEntry(
        value={"x": "m" * 3000}, created_at=datetime.now(UTC), expires_at=None
    )
    e2 = ManagedEntry(
        value={"y": "n" * 4000}, created_at=datetime.now(UTC), expires_at=None
    )
    await store._put_managed_entry(
        key="x", collection="gridfs_stats_test", managed_entry=e1
    )
    await store._put_managed_entry(
        key="y", collection="gridfs_stats_test", managed_entry=e2
    )

    # Stats should report non-zero files and sizes
    stats = await store.get_gridfs_stats(collection="gridfs_stats_test")
    assert "total_files" in stats and stats["total_files"] >= 1
    assert "total_size_bytes" in stats and stats["total_size_bytes"] > 0
    assert "avg_file_size_bytes" in stats and stats["avg_file_size_bytes"] > 0
    assert (
        "chunk_size_bytes" in stats
        and stats["chunk_size_bytes"] == store._gridfs_chunk_size_kb * 1024
    )

    # Delete collection and ensure subsequent gets return None
    deleted_ok = await store._delete_collection(collection="gridfs_stats_test")
    assert deleted_ok is True
    # Internal references should be removed
    assert "gridfs_stats_test" not in store._collections_by_name
    # Recreate collection to allow get() call; it should be empty
    await store.setup_collection(collection="gridfs_stats_test")
    assert (
        await store._get_managed_entry(key="x", collection="gridfs_stats_test") is None
    )
    assert (
        await store._get_managed_entry(key="y", collection="gridfs_stats_test") is None
    )
