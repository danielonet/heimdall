"""Tests for SentinelScheduler._security_digest_job (#16) — see its
docstring in sentinel/scheduler/scheduler.py. Same object.__new__ pattern
as test_threat_auto_block.py/test_block_expiry.py; this job only touches
SettingsRepository, the DB, and self._notifier.
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.db.models import Alert
from sentinel.db.repositories import SettingsRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:f3'


class _RecordingNotifier:
    def __init__(self):
        self.calls = []

    async def notify(self, title, message, severity='WARNING'):
        self.calls.append({'title': title, 'message': message, 'severity': severity})


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
    await SettingsRepository().set_last_digest_sent_at(None)
    await get_engine().dispose()


@pytest.fixture
def scheduler():
    sched = object.__new__(SentinelScheduler)
    sched._notifier = _RecordingNotifier()
    return sched


async def _add_alert(alert_type: str, severity: str, created_at: datetime) -> None:
    async with get_session() as session:
        session.add(Alert(device_mac=_MAC, alert_type=alert_type, severity=severity, created_at=created_at))


class TestSecurityDigestJob:
    async def test_sends_all_clear_when_no_alerts_since_cutoff(self, scheduler):
        await SettingsRepository().set_last_digest_sent_at(datetime.now(timezone.utc) - timedelta(hours=1))

        await scheduler._security_digest_job()

        assert len(scheduler._notifier.calls) == 1
        call = scheduler._notifier.calls[0]
        assert call['title'] == 'Heimdall security digest'
        assert 'all clear' in call['message']
        assert call['severity'] == 'INFO'

    async def test_summarizes_alerts_since_cutoff_with_severity_breakdown(self, scheduler):
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=6))
        await _add_alert('ARP_SPOOF', 'CRITICAL', now - timedelta(hours=3))
        await _add_alert('HIGH_UPLOAD', 'WARNING', now - timedelta(hours=2))
        await _add_alert('NEW_DEVICE', 'INFO', now - timedelta(hours=1))

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert '3 alert(s)' in call['message']
        assert 'CRITICAL' in call['message']
        assert 'ARP_SPOOF' in call['message']
        assert call['severity'] == 'CRITICAL'  # worst severity present wins

    async def test_severity_picks_warning_when_no_critical_present(self, scheduler):
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=6))
        await _add_alert('HIGH_UPLOAD', 'WARNING', now - timedelta(hours=2))
        await _add_alert('NEW_DEVICE', 'INFO', now - timedelta(hours=1))

        await scheduler._security_digest_job()

        assert scheduler._notifier.calls[0]['severity'] == 'WARNING'

    async def test_alerts_before_cutoff_are_excluded(self, scheduler):
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=1))
        await _add_alert('ARP_SPOOF', 'CRITICAL', now - timedelta(hours=5))  # before cutoff

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert 'all clear' in call['message']

    async def test_no_last_sent_defaults_to_a_24h_lookback(self, scheduler):
        await SettingsRepository().set_last_digest_sent_at(None)
        now = datetime.now(timezone.utc)
        await _add_alert('ARP_SPOOF', 'CRITICAL', now - timedelta(hours=23))
        await _add_alert('ARP_SPOOF', 'CRITICAL', now - timedelta(hours=25))  # just outside 24h

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert '1 alert(s)' in call['message']

    async def test_advances_last_digest_sent_at(self, scheduler):
        before = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(before - timedelta(hours=1))

        await scheduler._security_digest_job()

        last_sent = await SettingsRepository().get_last_digest_sent_at()
        assert last_sent >= before

    async def test_top_five_alert_types_limits_the_type_list(self, scheduler):
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=6))
        types = ['ARP_SPOOF', 'HIGH_UPLOAD', 'NEW_DEVICE', 'SIGNAL_ANOMALY', 'VENDOR_MISMATCH', 'ROGUE_DHCP_SERVER']
        for i, t in enumerate(types):
            await _add_alert(t, 'WARNING', now - timedelta(minutes=i))

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert '6 alert(s)' in call['message']
        listed_types = [t for t in types if t in call['message'].split('Top types:')[1]]
        assert len(listed_types) == 5
