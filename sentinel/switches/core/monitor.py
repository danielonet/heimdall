"""SwitchMonitor: polls every enabled switch, isolated from the router poll and from each other.

One APScheduler job calls poll_due() every few seconds; each target is polled when its own interval is up. A switch
that fails is retried with back-off (a login the switch rejected is not hammered: the driver's own cool-down applies),
and one failing or slow switch never delays another switch or the router poll. Configuration changes (host, user,
password, type) are picked up on the next cycle by comparing a fingerprint, so no cross-thread reload call is needed.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sentinel.config import _read_secret_file, settings, switch_secret_path
from sentinel.switches.catalog import get_spec
from sentinel.switches.core.attribution import Attribution, attribute
from sentinel.switches.core.counters import CounterTracker
from sentinel.switches.models import SwitchSnapshot
from sentinel.switches.registry import build_source
from sentinel.switches.source import SwitchAuthError, SwitchError, SwitchSource

logger = logging.getLogger(__name__)

POLL_TIMEOUT_S = 45.0

PersistFn = Callable[[int, str, Attribution, datetime], Awaitable[list[str]]]


@dataclass
class _Runtime:
    """The live driver for one switch, with its counter state and when it is next due."""

    fingerprint: str
    source: SwitchSource
    tracker: CounterTracker = field(default_factory=CounterTracker)
    next_due: float = 0.0
    failures: int = 0


class SwitchMonitor:
    """Owns one driver instance per configured switch. All collaborators are injectable for tests."""

    def __init__(
        self,
        repo: Any = None,
        persist: PersistFn | None = None,
        read_password: Callable[[int], str] | None = None,
        build: Callable[..., SwitchSource] = build_source,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if repo is None:
            from sentinel.db.repositories import SwitchTargetRepository
            repo = SwitchTargetRepository()
        if persist is None:
            from sentinel.switches.store import persist_poll
            persist = persist_poll
        self._repo = repo
        self._persist = persist
        self._read_password = read_password or (lambda target_id: _read_secret_file(switch_secret_path(target_id)))
        self._build = build
        self._clock = clock
        self._runtime: dict[int, _Runtime] = {}

    async def poll_due(self) -> None:
        """Poll every enabled switch whose interval is up. Never raises: a failure is recorded on the switch."""
        targets = await self._repo.list_enabled()
        wanted = {t.id for t in targets}
        for gone in set(self._runtime) - wanted:
            await self._drop(gone)
        now = self._clock()
        due = [t for t in targets if t.id not in self._runtime or now >= self._runtime[t.id].next_due]
        await asyncio.gather(*(self._poll_target(t) for t in due), return_exceptions=True)

    async def aclose(self) -> None:
        """Close every driver (shutdown)."""
        for target_id in list(self._runtime):
            await self._drop(target_id)

    async def _drop(self, target_id: int) -> None:
        runtime = self._runtime.pop(target_id, None)
        if runtime is not None:
            await runtime.source.aclose()

    def _interval(self, target: Any) -> float:
        return float(max(int(target.poll_interval_s or 0), settings.SWITCH_MIN_POLL_SECONDS))

    def _backoff(self, target: Any, failures: int) -> float:
        """Interval after one failure (could be transient), then doubling from the reconnect base to its cap."""
        if failures <= 1:
            return self._interval(target)
        step = settings.SWITCH_RECONNECT_BASE_SECONDS * 2 ** (failures - 2)
        return max(self._interval(target), float(min(step, settings.SWITCH_RECONNECT_MAX_SECONDS)))

    async def _runtime_for(self, target: Any, password: str) -> _Runtime | None:
        spec = get_spec(target.spec_id)
        if spec is None or not spec.implemented:
            return None
        digest = hashlib.sha256(password.encode()).hexdigest()
        fingerprint = f'{target.spec_id}|{target.host}|{target.username}|{digest}'
        current = self._runtime.get(target.id)
        if current is not None and current.fingerprint == fingerprint:
            return current
        if current is not None:
            await self._drop(target.id)
        runtime = _Runtime(
            fingerprint=fingerprint, source=self._build(spec, target.host, target.username, password),
        )
        self._runtime[target.id] = runtime
        return runtime

    async def _poll_target(self, target: Any) -> None:
        try:
            await self._poll_target_inner(target)
        except Exception:  # noqa: BLE001 — nothing a switch does may take the monitor (or the scheduler) down
            logger.exception('Switch %s: unexpected error while polling', target.name)

    async def _poll_target_inner(self, target: Any) -> None:
        password = self._read_password(target.id)
        if not password:
            await self._fail(target, 'no password is saved for this switch')
            return
        runtime = await self._runtime_for(target, password)
        if runtime is None:
            await self._fail(target, f'unknown or unsupported switch type {target.spec_id!r}')
            return
        try:
            snapshot: SwitchSnapshot = await asyncio.wait_for(runtime.source.poll(), timeout=POLL_TIMEOUT_S)
            attribution = attribute(snapshot, runtime.tracker, self._clock(), str(target.id))
            await self._persist(target.id, target.name, attribution, snapshot.taken_at)
        except asyncio.TimeoutError:
            await self._fail(target, f'no answer within {POLL_TIMEOUT_S:.0f} seconds', runtime=runtime)
            return
        except SwitchAuthError as exc:
            await self._fail(target, str(exc), runtime=runtime)
            return
        except SwitchError as exc:
            await self._fail(target, str(exc) or exc.__class__.__name__, runtime=runtime)
            return
        except ValueError as exc:     # HostNotAllowed and bad configuration
            await self._fail(target, str(exc), runtime=runtime)
            return
        if runtime.failures:
            logger.info('Switch %s is reporting again after %d failed poll(s)', target.name, runtime.failures)
        runtime.failures = 0
        runtime.next_due = self._clock() + self._interval(target)
        await self._repo.record_ok(
            target.id, model=snapshot.identity.model, firmware=snapshot.identity.firmware, now=datetime.now(timezone.utc),
        )
        for warning in snapshot.warnings:
            logger.warning('Switch %s: %s', target.name, warning)

    async def _fail(self, target: Any, message: str, *, runtime: _Runtime | None = None) -> None:
        failures = (runtime.failures + 1) if runtime is not None else 1
        if runtime is not None:
            runtime.failures = failures
            runtime.next_due = self._clock() + self._backoff(target, failures)
        else:
            # Nothing to retry until the admin fixes the configuration: look again at the normal interval.
            self._runtime_placeholder(target)
        if failures == 1 or failures % 20 == 0:
            logger.warning('Switch %s: %s', target.name, message)
        await self._repo.record_failure(target.id, message)

    def _runtime_placeholder(self, target: Any) -> None:
        """A switch with no usable configuration still needs a next-due time, or it would be retried every cycle."""
        existing = self._runtime.get(target.id)
        if existing is not None:
            existing.next_due = self._clock() + self._interval(target)
            return
        self._runtime[target.id] = _Runtime(fingerprint='', source=_NullSource(), next_due=self._clock() + self._interval(target))


class _NullSource:
    """Stands in for a driver that could not be built (no password saved, unknown type)."""

    async def poll(self) -> SwitchSnapshot:
        """Always fails: there is nothing to poll."""
        raise SwitchError('this switch is not configured')

    async def aclose(self) -> None:
        """Nothing to close."""
        return None
