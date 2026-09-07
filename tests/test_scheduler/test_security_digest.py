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

    async def notify(self, title, message, severity='WARNING', html_message=None):
        self.calls.append({
            'title': title, 'message': message, 'severity': severity, 'html_message': html_message,
        })


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
        """Inherently dependent on the shared dev DB genuinely having no
        alerts at all in the last hour — a live household network rarely
        holds still that long, so this (and test_alerts_before_cutoff_are_
        excluded below, same shape) is expected to occasionally fail for
        that reason alone, not a real bug. Same category of pre-existing
        shared-DB flakiness as test_data_retention.py etc."""
        await SettingsRepository().set_last_digest_sent_at(datetime.now(timezone.utc) - timedelta(hours=1))

        await scheduler._security_digest_job()

        assert len(scheduler._notifier.calls) == 1
        call = scheduler._notifier.calls[0]
        assert call['title'] == 'Security Digest'
        assert 'all clear' in call['message']
        assert call['severity'] == 'INFO'

    async def test_summarizes_alerts_since_cutoff_with_severity_breakdown(self, scheduler):
        """Counts/totals aren't asserted exactly — this runs against the
        shared dev DB, which may have its own real alerts in the same
        window (see e.g. test_data_retention.py's module docstring for the
        same caveat elsewhere in this suite). Only this test's own MAC-
        scoped content is checked."""
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=6))
        await _add_alert('ARP_SPOOF', 'CRITICAL', now - timedelta(hours=3))
        await _add_alert('HIGH_UPLOAD', 'WARNING', now - timedelta(hours=2))
        await _add_alert('NEW_DEVICE', 'INFO', now - timedelta(hours=1))

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert f'[CRITICAL] {_MAC} — ARP_SPOOF' in call['message']
        assert f'[WARNING] {_MAC} — HIGH_UPLOAD' in call['message']
        assert f'[INFO] {_MAC} — NEW_DEVICE' in call['message']
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
        """Counts aren't asserted exactly — see test_summarizes_alerts_
        since_cutoff_with_severity_breakdown's docstring. What matters here
        is the 23h-old alert makes it into the digest and the 25h-old one
        (just outside the 24h fallback window) doesn't — MAX_ALERT_ROWS is
        well above 1, so both would appear individually if the cutoff
        logic were wrong."""
        await SettingsRepository().set_last_digest_sent_at(None)
        now = datetime.now(timezone.utc)
        await _add_alert('ARP_SPOOF', 'CRITICAL', now - timedelta(hours=23))
        await _add_alert('SIGNAL_ANOMALY', 'WARNING', now - timedelta(hours=25))  # just outside 24h

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert f'[CRITICAL] {_MAC} — ARP_SPOOF' in call['message']
        assert f'{_MAC} — SIGNAL_ANOMALY' not in call['message']

    async def test_advances_last_digest_sent_at(self, scheduler):
        before = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(before - timedelta(hours=1))

        await scheduler._security_digest_job()

        last_sent = await SettingsRepository().get_last_digest_sent_at()
        assert last_sent >= before

    async def test_more_than_max_alert_rows_gets_truncated_with_a_pointer_to_the_alerts_tab(self, scheduler):
        """Replaces the old "top 5 types" cap (aggregate-counts era) — the
        digest now lists individual alerts (see DigestAlertRow), capped at
        MAX_ALERT_ROWS with a '...and N more' pointer, not a top-5-types
        summary line. Seeding well more than MAX_ALERT_ROWS of this test's
        own alerts guarantees truncation regardless of whatever else is in
        the shared dev DB's own window."""
        from sentinel.notifications.digest import MAX_ALERT_ROWS

        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=6))
        extra = 5
        for i in range(MAX_ALERT_ROWS + extra):
            await _add_alert('ARP_SPOOF', 'WARNING', now - timedelta(minutes=i))

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert 'more. See the Alerts tab in Heimdall for the full list.' in call['message']
