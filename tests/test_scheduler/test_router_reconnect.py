"""SentinelScheduler._maybe_reconnect_router: rebuild the router adapter after a lost connection, but only
for network failures, only with a saved password, and with a growing delay between attempts."""
from __future__ import annotations

import asyncio

import httpx
import pytest

from sentinel.config import settings
from sentinel.scheduler import scheduler as scheduler_module
from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio

_LOST = httpx.ConnectError('All connection attempts failed')


class _FakeAdapter:
    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class _FakeSettingsRepository:
    async def get_active_router(self) -> str:
        return 'sagemcom'


@pytest.fixture
def sched(monkeypatch):
    s = object.__new__(SentinelScheduler)
    s._adapter = _FakeAdapter()
    s._adapter_lock = asyncio.Lock()
    s._rule_engine = object()
    monkeypatch.setattr(scheduler_module, 'SettingsRepository', _FakeSettingsRepository)
    monkeypatch.setattr(scheduler_module, 'router_password_saved', lambda router: True)
    monkeypatch.setattr(settings, 'ROUTER_RECONNECT_AFTER_FAILURES', 3)
    monkeypatch.setattr(settings, 'ROUTER_RECONNECT_BASE_SECONDS', 60)
    monkeypatch.setattr(settings, 'ROUTER_RECONNECT_MAX_SECONDS', 240)
    return s


async def _fail(sched, times: int, exc: BaseException = _LOST) -> None:
    for _ in range(times):
        await sched._maybe_reconnect_router(exc)


async def test_adapter_is_rebuilt_after_enough_connection_failures(sched):
    old = sched._adapter
    await _fail(sched, 2)
    assert sched._adapter is old  # below the threshold

    await _fail(sched, 1)
    assert sched._adapter is None
    assert sched._rule_engine is None
    assert old.closed
    assert sched._last_reconnect_at is not None


async def test_other_failures_never_reconnect(sched):
    old = sched._adapter
    await _fail(sched, 10, RuntimeError('XMO login rejected: wrong password'))
    await _fail(sched, 10, TimeoutError())
    assert sched._adapter is old


async def test_no_saved_password_means_no_reconnect(sched, monkeypatch):
    monkeypatch.setattr(scheduler_module, 'router_password_saved', lambda router: False)
    old = sched._adapter
    await _fail(sched, 10)
    assert sched._adapter is old
    assert sched._last_reconnect_at is None


async def test_attempts_back_off_and_are_capped(sched, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(scheduler_module.time, 'monotonic', lambda: clock[0])
    waits = []
    for _ in range(5):
        sched._adapter = _FakeAdapter()
        await _fail(sched, 3)
        assert sched._adapter is None
        waits.append(sched._next_reconnect_at - clock[0])
        # Still inside the delay: another failure must not rebuild again.
        sched._adapter = _FakeAdapter()
        await _fail(sched, 1)
        assert sched._adapter is not None
        clock[0] = sched._next_reconnect_at
    assert waits == [60, 120, 240, 240, 240]


async def test_successful_poll_resets_the_counters(sched, monkeypatch):
    async def ok_poll_cycle(*args, **kwargs) -> None:
        return None

    async def noop(*args, **kwargs) -> None:
        return None

    async def ensure_adapter():
        return sched._adapter

    monkeypatch.setattr(scheduler_module, 'poll_cycle', ok_poll_cycle)
    sched._ensure_adapter = ensure_adapter
    sched._reconcile_arp_table = noop
    sched._reconcile_block_enforcement = noop
    for name in ('_redis_client', '_pipeline', '_anomaly_engine', '_wan_bandwidth_detector', '_notifier'):
        setattr(sched, name, None)
    sched._connection_failures = 7
    sched._reconnect_attempts = 3

    await sched._poll_job()

    assert sched._connection_failures == 0
    assert sched._reconnect_attempts == 0
    assert sched._last_poll_error is None
