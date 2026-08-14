"""Tests for SentinelScheduler._alert_auto_resolve_job — the sweep that
closes open alerts with no natural "this stopped" signal of their own past
AppSettings.alert_auto_resolve_hours. Mirrors test_block_expiry.py's shape:
this job only ever touches SettingsRepository/AlertRepository (the DB).
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.db.models import Alert
from sentinel.db.repositories import AlertRepository, SettingsRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:f0'
_ALERT_TYPE = '__TEST_AUTO_RESOLVE__'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Alert).where(Alert.alert_type == _ALERT_TYPE))
    await get_engine().dispose()


@pytest.fixture
def scheduler():
    return object.__new__(SentinelScheduler)


async def _seed_open_alert(hours_since_last_seen: float) -> Alert:
    alert, _ = await AlertRepository().upsert(
        device_mac=_MAC, alert_type=_ALERT_TYPE, severity='CRITICAL', description='seed',
    )
    async with get_session() as session:
        row = await session.get(Alert, alert.id)
        row.last_seen = datetime.now(timezone.utc) - timedelta(hours=hours_since_last_seen)
    return alert


class TestAlertAutoResolveJob:
    async def test_closes_an_open_alert_past_the_configured_hours(self, scheduler):
        alert = await _seed_open_alert(hours_since_last_seen=100)
        await SettingsRepository().set_alert_auto_resolve_hours(72)

        await scheduler._alert_auto_resolve_job()

        async with get_session() as session:
            refreshed = await session.get(Alert, alert.id)
        assert refreshed.resolved is True
        assert refreshed.resolved_at is not None

    async def test_leaves_a_recently_active_alert_open(self, scheduler):
        alert = await _seed_open_alert(hours_since_last_seen=1)
        await SettingsRepository().set_alert_auto_resolve_hours(72)

        await scheduler._alert_auto_resolve_job()

        async with get_session() as session:
            refreshed = await session.get(Alert, alert.id)
        assert refreshed.resolved is False

    async def test_an_already_resolved_alert_is_never_touched_twice(self, scheduler):
        alert = await _seed_open_alert(hours_since_last_seen=100)
        await SettingsRepository().set_alert_auto_resolve_hours(72)
        await AlertRepository().resolve(device_mac=_MAC, alert_type=_ALERT_TYPE)
        async with get_session() as session:
            row = await session.get(Alert, alert.id)
            first_resolved_at = row.resolved_at

        await scheduler._alert_auto_resolve_job()

        async with get_session() as session:
            refreshed = await session.get(Alert, alert.id)
        assert refreshed.resolved_at == first_resolved_at

    async def test_reads_the_configured_hours_dynamically(self, scheduler):
        """No admin override yet -> falls back to the env default (72h) —
        a 100h-old alert is closed without ever calling set_alert_auto_resolve_hours."""
        alert = await _seed_open_alert(hours_since_last_seen=100)

        await scheduler._alert_auto_resolve_job()

        async with get_session() as session:
            refreshed = await session.get(Alert, alert.id)
        assert refreshed.resolved is True

    async def test_a_failed_sweep_does_not_raise(self, scheduler, monkeypatch):
        async def _boom(*args, **kwargs):
            raise RuntimeError('DB hiccup')

        monkeypatch.setattr(AlertRepository, 'resolve_stale_open', _boom)
        await scheduler._alert_auto_resolve_job()  # must not raise
