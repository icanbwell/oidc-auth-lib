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
