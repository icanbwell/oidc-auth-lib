import pytest
from key_value.aio.stores.memory import MemoryStore

from oidcauthlib.cache_gate.version_gate import VersionGate


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
