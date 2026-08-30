"""Tests for SentinelScheduler._reconcile_block_enforcement /
_correct_block_drift — the safeguard against devices.is_blocked drifting
out of sync with what the router is actually enforcing.

Confirmed live 2026-08-30 that this drift is real, not theoretical: a
blocked device's MAC rotates (see _identity_link_job/DeviceIdentityLinker),
gets recognized as the same physical device, and the new MAC ends up with
a completely fresh, unblocked Host entry at the router while Heimdall's
dashboard keeps showing the old MAC as blocked. _propagate_block_after_link
(tested in test_identity_link_job.py) closes that one specific path; this
job is the general-purpose net underneath it — any other cause of the same
kind of drift (a Host record that lost its schedule, a block applied or
cleared by hand at the router's own admin UI) gets caught here too.

_correct_block_drift always defers to the router (both directions just
update Heimdall's own record, never block_device()/unblock_device()) —
changed from an earlier, asymmetric version that re-issued the block when
Heimdall's own record said "blocked" and the router disagreed. Also
confirmed live 2026-08-30: an admin had unblocked a device directly via the
router's own admin UI (Heimdall's own unblock wasn't working at the time),
and the old behavior would have silently re-blocked it right back on the
next reconciliation cycle — fighting a deliberate, out-of-band admin
action.

Mirrors tests/test_scheduler/test_threat_auto_block.py's
object.__new__(SentinelScheduler) pattern — these methods only ever touch
self._adapter, self._last_block_reconcile_at, and the DB.
"""
import os
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select

from sentinel.adapter.models import DeviceSnapshot
from sentinel.api.extensions import socketio
from sentinel.db.models import Alert, Device
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio

_MAC = 'ee:22:00:00:00:01'
_MAC_2 = 'ee:22:00:00:00:02'
_ALL_MACS = [_MAC, _MAC_2]


@pytest.fixture(autouse=True, scope='module')
def _init_socketio_once():
    """_correct_block_drift broadcasts BLOCK_ENFORCEMENT_DRIFT over the socket."""
    socketio.init_app(Flask(__name__))


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Alert).where(Alert.device_mac.in_(_ALL_MACS)))
        await session.execute(delete(Device).where(Device.mac_address.in_(_ALL_MACS)))
    await get_engine().dispose()


async def _seed_device(mac: str, **overrides) -> None:
    defaults = dict(is_online=True, ip_address='10.0.0.9', hostname='test-device')
    defaults.update(overrides)
    async with get_session() as session:
        session.add(Device(mac_address=mac, **defaults))


async def _get_device(mac: str) -> Device | None:
    async with get_session() as session:
        return await session.get(Device, mac)


async def _drift_alert(mac: str) -> Alert | None:
    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.device_mac == mac, Alert.alert_type == 'BLOCK_ENFORCEMENT_DRIFT')
        )
        return result.scalars().first()


def _scheduler_with_adapter(devices: list[DeviceSnapshot]) -> SentinelScheduler:
    scheduler = object.__new__(SentinelScheduler)
    scheduler._last_block_reconcile_at = None
    adapter = AsyncMock()
    adapter.get_connected_devices = AsyncMock(return_value=devices)
    adapter.block_device = AsyncMock(return_value=True)
    scheduler._adapter = adapter
    return scheduler


def _snapshot(mac: str, blacklisted: bool) -> DeviceSnapshot:
    return DeviceSnapshot(
        mac_address=mac, ip_address='10.0.0.9', hostname='test-device',
        is_blacklisted_at_router=blacklisted,
    )


class TestReconcileBlockEnforcement:
    async def test_db_blocked_router_not_blacklisted_triggers_correction(self):
        await _seed_device(_MAC, is_blocked=True)
        scheduler = _scheduler_with_adapter([_snapshot(_MAC, blacklisted=False)])

        await scheduler._reconcile_block_enforcement(scheduler._adapter)

        scheduler._adapter.block_device.assert_not_awaited()  # never re-assert Heimdall's belief onto the router
        device = await _get_device(_MAC)
        assert device.is_blocked is False
        alert = await _drift_alert(_MAC)
        assert alert is not None
        assert alert.severity == 'WARNING'
        assert 'updated' in alert.description.lower()

    async def test_db_not_blocked_router_blacklisted_triggers_correction(self):
        await _seed_device(_MAC, is_blocked=False)
        scheduler = _scheduler_with_adapter([_snapshot(_MAC, blacklisted=True)])

        await scheduler._reconcile_block_enforcement(scheduler._adapter)

        scheduler._adapter.block_device.assert_not_awaited()  # never force-unblock the router's own state
        device = await _get_device(_MAC)
        assert device.is_blocked is True
        alert = await _drift_alert(_MAC)
        assert alert.severity == 'INFO'
        assert "router's own admin UI" in alert.description

    async def test_agreement_raises_no_alert(self):
        await _seed_device(_MAC, is_blocked=True)
        scheduler = _scheduler_with_adapter([_snapshot(_MAC, blacklisted=True)])

        await scheduler._reconcile_block_enforcement(scheduler._adapter)

        scheduler._adapter.block_device.assert_not_awaited()
        assert await _drift_alert(_MAC) is None

    async def test_mac_absent_from_router_state_is_skipped(self):
        """No live Host entry at all this cycle (e.g. long gone) — not
        confirmed either way, so no action, unlike an explicit
        blacklisted=False which is a real live signal."""
        await _seed_device(_MAC, is_blocked=True)
        scheduler = _scheduler_with_adapter([])  # router reports no hosts at all

        await scheduler._reconcile_block_enforcement(scheduler._adapter)

        scheduler._adapter.block_device.assert_not_awaited()
        assert await _drift_alert(_MAC) is None

    async def test_device_list_fetch_failure_does_not_raise(self):
        scheduler = _scheduler_with_adapter([])
        scheduler._adapter.get_connected_devices = AsyncMock(side_effect=RuntimeError('router unreachable'))

        await scheduler._reconcile_block_enforcement(scheduler._adapter)  # must not raise

    async def test_checks_every_device_not_just_one(self):
        await _seed_device(_MAC, is_blocked=True)
        await _seed_device(_MAC_2, is_blocked=False)
        scheduler = _scheduler_with_adapter([
            _snapshot(_MAC, blacklisted=False),
            _snapshot(_MAC_2, blacklisted=True),
        ])

        await scheduler._reconcile_block_enforcement(scheduler._adapter)

        assert await _drift_alert(_MAC) is not None
        assert await _drift_alert(_MAC_2) is not None


class TestReconcileBlockEnforcementCadence:
    async def test_second_call_within_the_interval_is_a_no_op(self):
        await _seed_device(_MAC, is_blocked=True)
        scheduler = _scheduler_with_adapter([_snapshot(_MAC, blacklisted=False)])

        await scheduler._reconcile_block_enforcement(scheduler._adapter)
        await scheduler._reconcile_block_enforcement(scheduler._adapter)

        scheduler._adapter.get_connected_devices.assert_awaited_once()

    async def test_call_after_the_interval_has_elapsed_reconciles_again(self):
        await _seed_device(_MAC, is_blocked=True)
        scheduler = _scheduler_with_adapter([_snapshot(_MAC, blacklisted=False)])

        await scheduler._reconcile_block_enforcement(scheduler._adapter)
        scheduler._last_block_reconcile_at -= 301
        await scheduler._reconcile_block_enforcement(scheduler._adapter)

        assert scheduler._adapter.get_connected_devices.await_count == 2


class TestCorrectBlockDrift:
    async def test_db_blocked_router_not_updates_the_record_and_never_touches_the_adapter(self):
        """The exact incident this method was changed for: an admin
        unblocked a device directly via the router's own admin UI. The
        router's live state must win outright, not get re-asserted over."""
        await _seed_device(_MAC, is_blocked=True)
        scheduler = object.__new__(SentinelScheduler)
        scheduler._adapter = AsyncMock()
        scheduler._adapter.block_device = AsyncMock(return_value=True)
        scheduler._adapter.unblock_device = AsyncMock(return_value=True)

        await scheduler._correct_block_drift(_MAC, db_blocked=True, router_blocked=False)

        scheduler._adapter.block_device.assert_not_awaited()
        scheduler._adapter.unblock_device.assert_not_awaited()
        device = await _get_device(_MAC)
        assert device.is_blocked is False
        alert = await _drift_alert(_MAC)
        assert alert.severity == 'WARNING'
        assert 'updated' in alert.description.lower()

    async def test_db_not_blocked_router_blocked_updates_the_record_and_never_touches_the_adapter(self):
        await _seed_device(_MAC, is_blocked=False)
        scheduler = object.__new__(SentinelScheduler)
        scheduler._adapter = AsyncMock()
        scheduler._adapter.block_device = AsyncMock(return_value=True)

        await scheduler._correct_block_drift(_MAC, db_blocked=False, router_blocked=True)

        scheduler._adapter.block_device.assert_not_awaited()
        device = await _get_device(_MAC)
        assert device.is_blocked is True
        alert = await _drift_alert(_MAC)
        assert alert.severity == 'INFO'

    async def test_disable_auto_block_is_irrelevant_here_since_nothing_is_auto_blocked(self, monkeypatch):
        """This method never calls block_device()/unblock_device() at all
        any more — DISABLE_AUTO_BLOCK has nothing to gate here."""
        from sentinel.config import settings
        monkeypatch.setattr(settings, 'DISABLE_AUTO_BLOCK', True)
        await _seed_device(_MAC, is_blocked=True)
        scheduler = object.__new__(SentinelScheduler)
        scheduler._adapter = AsyncMock()

        await scheduler._correct_block_drift(_MAC, db_blocked=True, router_blocked=False)

        device = await _get_device(_MAC)
        assert device.is_blocked is False
        alert = await _drift_alert(_MAC)
        assert 'AUTO-BLOCK DISABLED' not in alert.description

    async def test_repeated_drift_touches_one_alert_row_instead_of_spamming(self):
        await _seed_device(_MAC, is_blocked=True)
        scheduler = object.__new__(SentinelScheduler)
        scheduler._adapter = AsyncMock()

        await scheduler._correct_block_drift(_MAC, db_blocked=True, router_blocked=False)
        await scheduler._correct_block_drift(_MAC, db_blocked=True, router_blocked=False)

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.device_mac == _MAC, Alert.alert_type == 'BLOCK_ENFORCEMENT_DRIFT')
            )
            rows = result.scalars().all()
        assert len(rows) == 1
