from collections.abc import Mapping, Sequence
from typing import Any, SupportsFloat

import pytest
from key_value.aio.stores.memory import MemoryStore

from oidcauthlib.cache_gate.version_gate import VersionGate


class _RaceStore:
    """Wraps a real store; the first `get()` for `key` reports "no marker",
    every subsequent `get()` reports `current_version` — simulating another
    pod writing the marker in the gap between our pre-lock check and our
    post-lock re-check. Implements the full AsyncKeyValueProtocol surface
    by delegating everything but `get()` straight to the wrapped store.
    """

    def __init__(self, inner: MemoryStore, *, key: str, current_version: str) -> None:
        self._inner = inner
        self._key = key
        self._current_version = current_version
        self._get_calls = 0

    async def get(self, key: str, *, collection: str | None = None) -> dict[str, Any] | None:
        if key == self._key:
            self._get_calls += 1
            if self._get_calls >= 2:
                return {"version": self._current_version}
            return None
        result: dict[str, Any] | None = await self._inner.get(key, collection=collection)
        return result

    async def ttl(self, key: str, *, collection: str | None = None) -> tuple[dict[str, Any] | None, float | None]:
        ttl_result: tuple[dict[str, Any] | None, float | None] = await self._inner.ttl(key, collection=collection)
        return ttl_result

    async def put(
        self, key: str, value: Mapping[str, Any], *, collection: str | None = None, ttl: SupportsFloat | None = None
    ) -> None:
        await self._inner.put(key, value, collection=collection, ttl=ttl)

    async def delete(self, key: str, *, collection: str | None = None) -> bool:
        deleted: bool = await self._inner.delete(key, collection=collection)
        return deleted

    async def get_many(self, keys: Sequence[str], *, collection: str | None = None) -> list[dict[str, Any] | None]:
        many: list[dict[str, Any] | None] = await self._inner.get_many(keys, collection=collection)
        return many

    async def ttl_many(
        self, keys: Sequence[str], *, collection: str | None = None
    ) -> list[tuple[dict[str, Any] | None, float | None]]:
        many_ttls: list[tuple[dict[str, Any] | None, float | None]] = await self._inner.ttl_many(
            keys, collection=collection
        )
        return many_ttls

    async def put_many(
        self,
        keys: Sequence[str],
        values: Sequence[Mapping[str, Any]],
        *,
        collection: str | None = None,
        ttl: SupportsFloat | None = None,
    ) -> None:
        await self._inner.put_many(keys, values, collection=collection, ttl=ttl)

    async def delete_many(self, keys: Sequence[str], *, collection: str | None = None) -> int:
        deleted_count: int = await self._inner.delete_many(keys, collection=collection)
        return deleted_count


@pytest.mark.asyncio
async def test_runs_action_on_first_call() -> None:
    store = MemoryStore()
    gate = VersionGate(store=store, key="marketplace_ref")
    calls: list[str] = []

    async def action() -> None:
        calls.append("v1")

    ran = await gate.run_if_changed_async(current_version="v1", action=action)

    assert ran is True
    assert calls == ["v1"]


@pytest.mark.asyncio
async def test_skips_when_version_unchanged() -> None:
    store = MemoryStore()
    gate = VersionGate(store=store, key="marketplace_ref")
    calls: list[str] = []

    async def action() -> None:
        calls.append("ran")

    await gate.run_if_changed_async(current_version="v1", action=action)
    ran_again = await gate.run_if_changed_async(current_version="v1", action=action)

    assert ran_again is False
    assert calls == ["ran"]


@pytest.mark.asyncio
async def test_reruns_when_version_changes() -> None:
    store = MemoryStore()
    gate = VersionGate(store=store, key="marketplace_ref")
    calls: list[str] = []

    async def action() -> None:
        calls.append("ran")

    await gate.run_if_changed_async(current_version="v1", action=action)
    ran = await gate.run_if_changed_async(current_version="v2", action=action)

    assert ran is True
    assert calls == ["ran", "ran"]


@pytest.mark.asyncio
async def test_marker_not_written_if_action_raises() -> None:
    store = MemoryStore()
    gate = VersionGate(store=store, key="marketplace_ref")

    async def failing_action() -> None:
        raise RuntimeError("sync failed")

    with pytest.raises(RuntimeError):
        await gate.run_if_changed_async(current_version="v1", action=failing_action)

    calls: list[str] = []

    async def succeeding_action() -> None:
        calls.append("ran")

    ran = await gate.run_if_changed_async(current_version="v1", action=succeeding_action)

    assert ran is True
    assert calls == ["ran"]


@pytest.mark.asyncio
async def test_second_pod_skips_while_lock_held() -> None:
    store = MemoryStore()
    gate = VersionGate(store=store, key="marketplace_ref", lock_name="skill_sync")

    calls: list[str] = []

    async def other_action() -> None:
        calls.append("other")

    async def slow_action() -> None:
        # Simulate a second pod checking in mid-action, before the marker is written.
        other_gate = VersionGate(store=store, key="marketplace_ref", lock_name="skill_sync")
        other_ran = await other_gate.run_if_changed_async(current_version="v1", action=other_action)
        assert other_ran is False
        calls.append("primary")

    ran = await gate.run_if_changed_async(current_version="v1", action=slow_action)

    assert ran is True
    assert calls == ["primary"]


@pytest.mark.asyncio
async def test_skips_if_marker_already_updated_between_precheck_and_lock() -> None:
    store = _RaceStore(MemoryStore(), key="marketplace_ref", current_version="v1")
    gate = VersionGate(store=store, key="marketplace_ref", lock_name="skill_sync")
    calls: list[str] = []

    async def action() -> None:
        calls.append("ran")

    ran = await gate.run_if_changed_async(current_version="v1", action=action)

    assert ran is False
    assert calls == []
