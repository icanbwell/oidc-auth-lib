import asyncio
from typing import cast, override

import pytest

from oidcauthlib.container.interfaces import IContainer
from oidcauthlib.storage.storage_factory import StorageFactory
from oidcauthlib.storage.mongo_gridfs_db import MongoDBGridFSStore
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)
from oidcauthlib.storage.cache_to_collection_mapper import CacheToCollectionMapper

TEST_CACHE = "race_cache"


class TestCacheToCollectionMapper(CacheToCollectionMapper):
    def __init__(self, *, environment_variables: OidcEnvironmentVariables) -> None:
        super().__init__(environment_variables=environment_variables)
        self.mapping = {TEST_CACHE: "race_collection"}

    @override
    def get_collection_for_cache(self, *, cache_name: str) -> str | None:
        return self.mapping.get(cache_name)


@pytest.mark.asyncio
async def test_concurrent_setup_collection_is_race_safe(
    test_container: IContainer,
) -> None:
    """
    Ensure that calling setup_collection concurrently does not raise and results in a
    single usable collection and GridFS bucket.
    """
    # Wire mapping for the test cache
    test_container.singleton(
        CacheToCollectionMapper,
        lambda c: TestCacheToCollectionMapper(
            environment_variables=c.resolve(OidcEnvironmentVariables)
        ),
    )
    storage_factory: StorageFactory = test_container.resolve(StorageFactory)
    store = cast(MongoDBGridFSStore, storage_factory.get_store(TEST_CACHE))

    # Run two setup_collection calls concurrently for the same logical name
    await asyncio.gather(
        store.setup_collection(collection="race_collection"),
        store.setup_collection(collection="race_collection"),
    )

    # After setup, collection handle and bucket should exist
    assert "race_collection" in store._collections_by_name
    assert "race_collection" in store._gridfs_buckets

    # Basic smoke: perform a trivial put/get to verify collection is usable
    from datetime import datetime, UTC
    from key_value.aio._utils.managed_entry import ManagedEntry

    entry = ManagedEntry(
        value={"ok": True}, created_at=datetime.now(UTC), expires_at=None
    )
    await store._put_managed_entry(
        key="smoke",
        collection="race_collection",
        managed_entry=entry,
    )

    got = await store._get_managed_entry(key="smoke", collection="race_collection")
    assert got is not None
    assert got.value == {"ok": True}
