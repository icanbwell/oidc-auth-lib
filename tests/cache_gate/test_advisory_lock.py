import asyncio
from typing import Any

import pytest
from key_value.aio.stores.memory import MemoryStore

from oidcauthlib.cache_gate.advisory_lock import LOCK_COLLECTION, AdvisoryLock


class _FailDeleteStore:
    """Wraps a real store; delete() always raises, simulating a transient
    KV-store error on release. Everything else delegates straight through."""

    def __init__(self, inner: MemoryStore) -> None:
        self._inner = inner

    async def get(self, key: str, *, collection: str | None = None) -> dict[str, Any] | None:
        result: dict[str, Any] | None = await self._inner.get(key, collection=collection)
        return result

    async def ttl(self, key: str, *, collection: str | None = None) -> tuple[dict[str, Any] | None, float | None]:
        ttl_result: tuple[dict[str, Any] | None, float | None] = await self._inner.ttl(key, collection=collection)
        return ttl_result

    async def put(self, key: str, value: Any, *, collection: str | None = None, ttl: Any = None) -> None:
        await self._inner.put(key, value, collection=collection, ttl=ttl)

    async def delete(self, key: str, *, collection: str | None = None) -> bool:
        raise RuntimeError("store unavailable")

    async def get_many(self, keys: Any, *, collection: str | None = None) -> list[dict[str, Any] | None]:
        many: list[dict[str, Any] | None] = await self._inner.get_many(keys, collection=collection)
        return many

    async def ttl_many(self, keys: Any, *, collection: str | None = None) -> Any:
        return await self._inner.ttl_many(keys, collection=collection)

    async def put_many(self, keys: Any, values: Any, *, collection: str | None = None, ttl: Any = None) -> None:
        await self._inner.put_many(keys, values, collection=collection, ttl=ttl)

    async def delete_many(self, keys: Any, *, collection: str | None = None) -> int:
        deleted_count: int = await self._inner.delete_many(keys, collection=collection)
        return deleted_count


@pytest.mark.asyncio
async def test_acquires_when_unheld() -> None:
    store = MemoryStore()

    async with AdvisoryLock(store, "skill_sync") as acquired:
        assert acquired is True


@pytest.mark.asyncio
async def test_second_pod_skips_while_held() -> None:
    store = MemoryStore()

    async with AdvisoryLock(store, "skill_sync") as first_acquired:
        assert first_acquired is True

        async with AdvisoryLock(store, "skill_sync") as second_acquired:
            assert second_acquired is False


@pytest.mark.asyncio
async def test_lock_released_on_exit_allows_next_acquire() -> None:
    store = MemoryStore()

    async with AdvisoryLock(store, "skill_sync") as first_acquired:
        assert first_acquired is True

    async with AdvisoryLock(store, "skill_sync") as second_acquired:
        assert second_acquired is True


@pytest.mark.asyncio
async def test_lock_not_released_if_never_acquired() -> None:
    store = MemoryStore()

    async with AdvisoryLock(store, "skill_sync") as first_acquired:
        assert first_acquired is True

        async with AdvisoryLock(store, "skill_sync") as second_acquired:
            assert second_acquired is False

    # First holder released on exit; a fresh acquire attempt succeeds.
    async with AdvisoryLock(store, "skill_sync") as third_acquired:
        assert third_acquired is True


@pytest.mark.asyncio
async def test_stale_lock_expires_via_ttl() -> None:
    store = MemoryStore()
    # Simulate a crashed holder that never released: write the lock entry
    # directly rather than through AdvisoryLock, with a short TTL.
    await store.put("skill_sync", {"holder": "crashed-pod"}, collection=LOCK_COLLECTION, ttl=0.05)

    async with AdvisoryLock(store, "skill_sync") as before_expiry:
        assert before_expiry is False

    await asyncio.sleep(0.1)

    async with AdvisoryLock(store, "skill_sync") as after_expiry:
        assert after_expiry is True


@pytest.mark.asyncio
async def test_heartbeat_keeps_lock_alive_past_original_ttl() -> None:
    store = MemoryStore()

    async with AdvisoryLock(store, "skill_sync", ttl_seconds=1, heartbeat_interval_seconds=0.3) as acquired:
        assert acquired is True

        # Outlive the original TTL entirely. Without a heartbeat refreshing
        # it, this window would let a second pod acquire the same lock while
        # we're still holding it -- the exact bug this test guards against.
        await asyncio.sleep(1.5)

        async with AdvisoryLock(store, "skill_sync") as second_acquired:
            assert second_acquired is False

    # Released (and heartbeat stopped) on exit -- a fresh acquire succeeds.
    async with AdvisoryLock(store, "skill_sync") as third_acquired:
        assert third_acquired is True


@pytest.mark.asyncio
async def test_failed_release_does_not_mask_exception_from_critical_section() -> None:
    store = _FailDeleteStore(MemoryStore())

    with pytest.raises(ValueError, match="critical section failed"):
        async with AdvisoryLock(store, "skill_sync") as acquired:
            assert acquired is True
            raise ValueError("critical section failed")


@pytest.mark.asyncio
async def test_failed_release_does_not_raise_when_critical_section_succeeds() -> None:
    store = _FailDeleteStore(MemoryStore())

    async with AdvisoryLock(store, "skill_sync") as acquired:
        assert acquired is True
    # No exception propagates even though delete() raised internally.
