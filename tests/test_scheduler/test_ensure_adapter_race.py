"""Regression tests for a concurrency bug in SentinelScheduler._ensure_adapter()
/_ensure_secondary_adapter() found while diagnosing a live XMO_LOGIN_RETRY_ERR
lockout: both were a bare check-then-create ("if self._adapter is None:
self._adapter = await create_router_adapter()") with no lock. At boot,
_startup_job and the first _poll_job tick both call _ensure_adapter() around
the same moment; create_router_adapter() awaits a DB call
(SettingsRepository.get_active_router()) and yields control before either
caller's assignment lands, so both callers observe self._adapter as still
None and each builds its own independent adapter/XmoClient.

Confirmed live: on a single restart this produced two real XMO login HTTP
requests ~50ms apart, each independently hitting the router's
XMO_LOGIN_RETRY_ERR brute-force lockout and arming its own (then-discarded)
cooldown — exactly doubling the real hits to the router at the moment
xmo_client.py's lockout-cooldown fix was trying hardest to be gentle with it.

Fixed with double-checked locking via self._adapter_lock/_secondary_adapter_lock.
"""
import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio


async def _yielding_adapter_factory(*_args, **_kwargs) -> Mock:
    """Stands in for create_router_adapter()/create_secondary_router_adapter():
    a real await (not an instantly-resolved AsyncMock) so a second concurrent
    caller genuinely gets a chance to run before this one finishes — the
    exact shape of the race that made this bug possible in the first place."""
    await asyncio.sleep(0)
    return Mock(name='router-adapter')


class TestEnsureAdapterRace:
    async def test_concurrent_calls_build_the_adapter_only_once(self, monkeypatch):
        scheduler = object.__new__(SentinelScheduler)
        scheduler._adapter = None
        scheduler._adapter_lock = asyncio.Lock()

        factory = AsyncMock(side_effect=_yielding_adapter_factory)
        monkeypatch.setattr('sentinel.scheduler.scheduler.create_router_adapter', factory)

        first, second = await asyncio.gather(
            scheduler._ensure_adapter(), scheduler._ensure_adapter(),
        )

        assert factory.await_count == 1
        assert first is second
        assert scheduler._adapter is first

    async def test_already_built_adapter_short_circuits_without_the_lock(self, monkeypatch):
        """Once built, _ensure_adapter() must not pay for lock acquisition
        (or call the factory again) on the hot path."""
        scheduler = object.__new__(SentinelScheduler)
        existing = Mock(name='existing-adapter')
        scheduler._adapter = existing
        scheduler._adapter_lock = asyncio.Lock()

        factory = AsyncMock(side_effect=_yielding_adapter_factory)
        monkeypatch.setattr('sentinel.scheduler.scheduler.create_router_adapter', factory)

        result = await scheduler._ensure_adapter()

        assert result is existing
        factory.assert_not_awaited()


class TestEnsureSecondaryAdapterRace:
    async def test_concurrent_calls_build_the_secondary_adapter_only_once(self, monkeypatch):
        scheduler = object.__new__(SentinelScheduler)
        scheduler._secondary_adapter = None
        scheduler._secondary_adapter_lock = asyncio.Lock()

        settings_repo = Mock()
        settings_repo.get_active_router = AsyncMock(return_value='sagemcom')
        monkeypatch.setattr(
            'sentinel.scheduler.scheduler.SettingsRepository', Mock(return_value=settings_repo),
        )
        factory = AsyncMock(side_effect=_yielding_adapter_factory)
        monkeypatch.setattr('sentinel.scheduler.scheduler.create_secondary_router_adapter', factory)

        first, second = await asyncio.gather(
            scheduler._ensure_secondary_adapter(), scheduler._ensure_secondary_adapter(),
        )

        assert factory.await_count == 1
        assert first is second
        assert scheduler._secondary_adapter is first
