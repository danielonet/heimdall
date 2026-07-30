"""Tests for SentinelScheduler._block_expiry_job — the #13 auto-block expiry
sweep (see sentinel/scheduler/scheduler.py's docstring on that method).

Same object.__new__(SentinelScheduler) pattern as test_threat_auto_block.py:
this job only ever touches self._adapter, self._notifier, and the DB.
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select

from sentinel.adapter.mock.mock_adapter import MockSagemcomAdapter
from sentinel.api.extensions import socketio
from sentinel.db.models import Alert, Device
from sentinel.db.repositories import SettingsRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:f0'
_IP = '10.0.0.51'


class _RecordingNotifier:
    def __init__(self):
        self.calls = []

    async def notify(self, title, message, severity='WARNING'):
        self.calls.append({'title': title, 'message': message, 'severity': severity})


@pytest.fixture(autouse=True, scope='module')
def _init_socketio_once():
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
        await session.execute(delete(Alert).where(Alert.device_mac == _MAC))
        await session.execute(delete(Device).where(Device.mac_address == _MAC))
    await get_engine().dispose()


@pytest.fixture
def scheduler():
    sched = object.__new__(SentinelScheduler)
    sched._adapter = MockSagemcomAdapter()
    sched._notifier = _RecordingNotifier()
    return sched


async def _seed_device(**overrides) -> None:
    async with get_session() as session:
        session.add(Device(mac_address=_MAC, ip_address=_IP, hostname='test-device', **overrides))


async def _get_device() -> Device | None:
    async with get_session() as session:
        return await session.get(Device, _MAC)


async def _latest_alert() -> Alert | None:
    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.device_mac == _MAC).order_by(Alert.created_at.desc())
        )
        return result.scalars().first()


class TestBlockExpiryJob:
    async def test_expires_an_overdue_block(self, scheduler):
        now = datetime.now(timezone.utc)
        await _seed_device(is_blocked=True, blocked_at=now - timedelta(hours=25), blocked_until=now - timedelta(hours=1))
        await SettingsRepository().set_auto_block_expiry_hours(24)

        await scheduler._block_expiry_job()

        device = await _get_device()
        assert device.is_blocked is False
        assert device.blocked_at is None
        assert device.blocked_until is None
        alert = await _latest_alert()
        assert alert.alert_type == 'AUTO_BLOCK_EXPIRED'
        assert alert.severity == 'INFO'
        assert len(scheduler._notifier.calls) == 1
        assert scheduler._notifier.calls[0]['title'] == 'Auto-block expired'

    async def test_leaves_a_not_yet_due_block_alone(self, scheduler):
        now = datetime.now(timezone.utc)
        await _seed_device(is_blocked=True, blocked_at=now - timedelta(hours=1), blocked_until=now + timedelta(hours=23))

        await scheduler._block_expiry_job()

        device = await _get_device()
        assert device.is_blocked is True
        assert device.blocked_until is not None
        assert await _latest_alert() is None
        assert scheduler._notifier.calls == []

    async def test_ignores_manual_blocks_with_null_blocked_until(self, scheduler):
        await _seed_device(is_blocked=True, blocked_at=None, blocked_until=None)

        await scheduler._block_expiry_job()

        device = await _get_device()
        assert device.is_blocked is True
        assert await _latest_alert() is None
        assert scheduler._notifier.calls == []

    async def test_ignores_already_unblocked_devices_even_with_a_past_blocked_until(self, scheduler):
        """A stale blocked_until surviving on an already-unblocked device
        (shouldn't normally happen, but is_blocked is the source of truth)
        must not trigger a spurious unblock/notify."""
        now = datetime.now(timezone.utc)
        await _seed_device(is_blocked=False, blocked_at=now - timedelta(hours=25), blocked_until=now - timedelta(hours=1))

        await scheduler._block_expiry_job()

        assert await _latest_alert() is None
        assert scheduler._notifier.calls == []

    async def test_router_rejecting_unblock_leaves_device_blocked_and_does_not_notify(self, scheduler, monkeypatch):
        now = datetime.now(timezone.utc)
        await _seed_device(is_blocked=True, blocked_at=now - timedelta(hours=25), blocked_until=now - timedelta(hours=1))

        async def _fake_unblock_device(mac):
            return False

        monkeypatch.setattr(scheduler._adapter, 'unblock_device', _fake_unblock_device)
        await scheduler._block_expiry_job()

        device = await _get_device()
        assert device.is_blocked is True
        assert await _latest_alert() is None
        assert scheduler._notifier.calls == []
