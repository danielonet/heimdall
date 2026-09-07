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
        same caveat elsewhere in this suite). Uses synthetic alert_types
        (ZZZ_TEST_* — never used by any real detector) rather than real
        ones like ARP_SPOOF, since the digest now groups by type globally,
        not per-device — a real household alert of the same type would
        make a same-type assertion pass/fail for the wrong reason."""
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=6))
        await _add_alert('ZZZ_TEST_CRITICAL', 'CRITICAL', now - timedelta(hours=3))
        await _add_alert('ZZZ_TEST_WARNING', 'WARNING', now - timedelta(hours=2))
        await _add_alert('ZZZ_TEST_INFO', 'INFO', now - timedelta(hours=1))

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert '[CRITICAL] ZZZ_TEST_CRITICAL — 1 occurrence across 1 device' in call['message']
        assert '[WARNING] ZZZ_TEST_WARNING — 1 occurrence across 1 device' in call['message']
        assert '[INFO] ZZZ_TEST_INFO — 1 occurrence across 1 device' in call['message']
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
        since_cutoff_with_severity_breakdown's docstring, same reasoning
        for the synthetic ZZZ_TEST_* types (grouping is global by type now,
        not per-device, so a real alert_type would make the "excluded"
        assertion unreliable against the shared dev DB)."""
        await SettingsRepository().set_last_digest_sent_at(None)
        now = datetime.now(timezone.utc)
        await _add_alert('ZZZ_TEST_INSIDE_WINDOW', 'CRITICAL', now - timedelta(hours=23))
        await _add_alert('ZZZ_TEST_OUTSIDE_WINDOW', 'WARNING', now - timedelta(hours=25))  # just outside 24h

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert 'ZZZ_TEST_INSIDE_WINDOW' in call['message']
        assert 'ZZZ_TEST_OUTSIDE_WINDOW' not in call['message']

    async def test_advances_last_digest_sent_at(self, scheduler):
        before = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(before - timedelta(hours=1))

        await scheduler._security_digest_job()

        last_sent = await SettingsRepository().get_last_digest_sent_at()
        assert last_sent >= before

    async def test_a_burst_of_one_type_never_triggers_truncation(self, scheduler):
        """The actual point of grouping: however many times the *same*
        type fires, it's still exactly one group — MAX_ALERT_TYPES caps
        distinct types, not raw alert volume."""
        from sentinel.notifications.digest import MAX_ALERT_TYPES

        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=6))
        for i in range(MAX_ALERT_TYPES + 10):
            await _add_alert('ZZZ_TEST_BURST', 'WARNING', now - timedelta(minutes=i))

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        # Checks the group *header* appears exactly once, not the bare word
        # "ZZZ_TEST_BURST" — these seeded alerts have no description, so it
        # also appears a second time as the (correct, separately tested —
        # see test_digest.py) description fallback later in the same line.
        assert call['message'].count('] ZZZ_TEST_BURST —') == 1
        assert f'{MAX_ALERT_TYPES + 10} occurrences' in call['message']

    async def test_more_than_max_alert_types_gets_truncated_with_a_pointer_to_the_alerts_tab(self, scheduler):
        """Unlike the burst case above, genuinely *distinct* types beyond
        MAX_ALERT_TYPES do get truncated, with a pointer to the full list."""
        from sentinel.notifications.digest import MAX_ALERT_TYPES

        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=6))
        extra = 5
        for i in range(MAX_ALERT_TYPES + extra):
            await _add_alert(f'ZZZ_TEST_TYPE_{i}', 'WARNING', now - timedelta(minutes=i))

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert 'more alert type(s). See the Alerts tab in Heimdall for the full list.' in call['message']
