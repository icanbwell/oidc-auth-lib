"""Staged here pending extraction into a standalone shared-infra package —
this module has no OIDC-specific logic and doesn't belong in oidc-auth-lib
long-term; it's here because this is the one package both current consumers
(baileyai, baileyai-skills-service) already depend on.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from key_value.aio.protocols.key_value import AsyncKeyValueProtocol

from oidcauthlib.cache_gate.advisory_lock import AdvisoryLock

logger = logging.getLogger(__name__)

VERSION_GATE_COLLECTION = "version_gate"


class VersionGate:
    """Runs an action at most once per distinct version, across a pod fleet.

    Compares `current_version` against a marker persisted in `store`. If it
    differs, runs `action` and — only once `action` completes without raising
    — persists the new marker. The marker is written *after* the action
    succeeds, never before: writing it first would let a crashed/incomplete
    action look "done" to every other pod, forever, until the version next
    changes.

    Pass `lock_name` when `action` is not safe to run concurrently from
    multiple pods (e.g. a multi-step load with partial-write visibility).
    Omit it when `action` is idempotent under concurrent execution (e.g. a
    pure cache clear followed by lazy repopulation) — redundant concurrent
    runs are then harmless and a lock only adds latency/contention.
    """

    def __init__(
        self,
        *,
        store: AsyncKeyValueProtocol,
        key: str,
        collection: str = VERSION_GATE_COLLECTION,
        lock_name: str | None = None,
        lock_ttl_seconds: int = 300,
        lock_heartbeat_interval_seconds: float | None = None,
    ) -> None:
        self._store = store
        self._key = key
        self._collection = collection
        self._lock_name = lock_name
        self._lock_ttl_seconds = lock_ttl_seconds
        self._lock_heartbeat_interval_seconds = lock_heartbeat_interval_seconds

    async def run_if_changed_async(
        self,
        *,
        current_version: str,
        action: Callable[[], Awaitable[None]],
    ) -> bool:
        """Runs `action` and records `current_version` iff it differs from the
        stored marker. Returns True iff `action` ran.
        """
        if await self._is_current(current_version):
            return False

        if self._lock_name is None:
            await action()
            await self._mark(current_version)
            return True

        async with AdvisoryLock(
            self._store,
            self._lock_name,
            ttl_seconds=self._lock_ttl_seconds,
            heartbeat_interval_seconds=self._lock_heartbeat_interval_seconds,
        ) as acquired:
            if not acquired:
                logger.info(
                    "VersionGate: lock '%s' held by another pod — skipping.",
                    self._lock_name,
                )
                return False

            # Re-check: whoever held the lock before us may have already
            # handled this version change while we were waiting to acquire.
            if await self._is_current(current_version):
                return False

            await action()
            await self._mark(current_version)
            return True

    async def _is_current(self, current_version: str) -> bool:
        stored = await self._store.get(self._key, collection=self._collection)
        return stored is not None and stored.get("version") == current_version

    async def _mark(self, current_version: str) -> None:
        await self._store.put(
            self._key,
            {"version": current_version},
            collection=self._collection,
        )
