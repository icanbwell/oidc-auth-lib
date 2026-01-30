from datetime import datetime, UTC

import pytest
from bson import ObjectId
from oidcauthlib.auth.repository.memory.memory_repository import AsyncMemoryRepository
from oidcauthlib.auth.models.cache_item import CacheItem


@pytest.mark.asyncio
async def test_insert_and_find_by_id() -> None:
    repo: AsyncMemoryRepository[CacheItem] = AsyncMemoryRepository()
    item: CacheItem = CacheItem(key="foo", value="bar", created=datetime.now(UTC))
    inserted_id: ObjectId = await repo.insert("cache", item)
    assert isinstance(inserted_id, ObjectId)
    found: CacheItem | None = await repo.find_by_id("cache", CacheItem, inserted_id)
    assert found is item
    assert found.key == "foo"
    assert found.value == "bar"


@pytest.mark.asyncio
async def test_find_by_id_not_found() -> None:
    repo: AsyncMemoryRepository[CacheItem] = AsyncMemoryRepository()
    result: CacheItem | None = await repo.find_by_id("cache", CacheItem, ObjectId())
    assert result is None


@pytest.mark.asyncio
async def test_insert_or_replace_many_insert_and_replace() -> None:
    repo: AsyncMemoryRepository[CacheItem] = AsyncMemoryRepository()
    collection = "cache"
    # Insert two new items
    items = [
        CacheItem(key="alice", value="initial_value_alice", created=datetime.now(UTC)),
        CacheItem(key="bob", value="initial_value_bob", created=datetime.now(UTC)),
    ]
    result = await repo.insert_or_replace_many(
        collection_name=collection,
        items=items,
        key_fields=["key"],
    )
    assert isinstance(result, list)
    assert len(result) == 2
    # Query by key field
    found_alice = await repo.find_by_fields(collection, CacheItem, {"key": "alice"})
    found_bob = await repo.find_by_fields(collection, CacheItem, {"key": "bob"})
    assert found_alice is not None
    assert found_bob is not None
    assert found_alice.key == "alice"
    assert found_bob.key == "bob"
    assert found_alice.value == "initial_value_alice"
    assert found_bob.value == "initial_value_bob"

    # Replace Alice's document entirely
    updated_alice = CacheItem(
        key="alice", value="replaced_value_alice", created=datetime.now(UTC)
    )
    result2 = await repo.insert_or_replace_many(
        collection_name=collection,
        items=[updated_alice],
        key_fields=["key"],
    )
    assert isinstance(result2, list)
    assert len(result2) == 1
    found_alice_updated = await repo.find_by_fields(
        collection, CacheItem, {"key": "alice"}
    )
    assert found_alice_updated is not None
    assert found_alice_updated.key == "alice"
    assert found_alice_updated.value == "replaced_value_alice"


@pytest.mark.asyncio
async def test_insert_or_update_many_insert_and_update() -> None:
    repo: AsyncMemoryRepository[CacheItem] = AsyncMemoryRepository()
    collection = "cache"
    # Insert two new items
    items = [
        CacheItem(key="alice", value="initial_value_alice", created=datetime.now(UTC)),
        CacheItem(key="bob", value="initial_value_bob", created=datetime.now(UTC)),
    ]
    result = await repo.insert_or_update_many(
        collection_name=collection,
        items=items,
        key_fields=["key"],
    )
    assert isinstance(result, list)
    assert len(result) == 2
    # Query by key field
    found_alice = await repo.find_by_fields(collection, CacheItem, {"key": "alice"})
    found_bob = await repo.find_by_fields(collection, CacheItem, {"key": "bob"})
    assert found_alice is not None
    assert found_bob is not None
    assert found_alice.key == "alice"
    assert found_bob.key == "bob"
    assert found_alice.value == "initial_value_alice"
    assert found_bob.value == "initial_value_bob"

    # Update Alice's document (partial update - value changes, created should be preserved)
    # Create a new item with only the fields we want to update (key for matching + value to update)
    new_created_time = datetime.now(UTC)
    updated_alice = CacheItem(
        key="alice", value="updated_value_alice", created=new_created_time
    )
    result2 = await repo.insert_or_update_many(
        collection_name=collection,
        items=[updated_alice],
        key_fields=["key"],
    )
    assert isinstance(result2, list)
    assert len(result2) == 1
    found_alice_updated = await repo.find_by_fields(
        collection, CacheItem, {"key": "alice"}
    )
    assert found_alice_updated is not None
    assert found_alice_updated.key == "alice"
    assert found_alice_updated.value == "updated_value_alice"
    # The created field should be updated since it's provided in the update
    assert found_alice_updated.created == new_created_time
