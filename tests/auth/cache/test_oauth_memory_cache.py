import pytest
from oidcauthlib.auth.cache.oauth_memory_cache import OAuthMemoryCache


@pytest.mark.asyncio
async def test_set_and_get() -> None:
    cache = OAuthMemoryCache()
    await cache.set("foo", "bar")
    value = await cache.get("foo")
    assert value == "bar"


@pytest.mark.asyncio
async def test_get_default() -> None:
    cache = OAuthMemoryCache()
    value = await cache.get("missing", default="baz")
    assert value == "baz"


@pytest.mark.asyncio
async def test_delete() -> None:
    cache = OAuthMemoryCache()
    await cache.set("foo", "bar")
    await cache.delete("foo")
    value = await cache.get("foo")
    assert value is None
