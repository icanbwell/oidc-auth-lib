import pytest
from key_value.aio.stores.memory import MemoryStore

from oidcauthlib.cache_gate.advisory_lock import AdvisoryLock


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
