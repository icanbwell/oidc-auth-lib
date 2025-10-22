from typing import Any
from oidcauthlib.auth.models.cache_item import CacheItem
from datetime import datetime


def test_cache_item_creation() -> None:
    now: datetime = datetime.utcnow()
    item: CacheItem = CacheItem(key="foo", value="bar", created=now)
    assert item.key == "foo"
    assert item.value == "bar"
    assert item.created == now
    assert item.deleted is None
    # Test serialization
    data: dict[str, Any] = item.model_dump()
    assert data["key"] == "foo"
    assert data["value"] == "bar"
    assert data["created"] == now
