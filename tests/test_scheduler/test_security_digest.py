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

from sentinel.adapter.models import TrafficGranularity
from sentinel.db.models import Alert, Device, TrafficSample, WanStats
from sentinel.db.repositories import SettingsRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:f3'
# Distinct from _MAC (and from any real household MAC) so traffic-section
# tests don't collide with the alert-grouping tests above or with the
# shared dev DB's own live devices/samples.
_TRAFFIC_MAC = 'aa:bb:cc:dd:ee:f4'
_TRAFFIC_MAC_2 = 'aa:bb:cc:dd:ee:f5'
_WIRED_PORT_ALIAS = 'ZZZ_TEST_PORT1'


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
        await session.execute(
            delete(TrafficSample).where(
                TrafficSample.mac_address.in_([_TRAFFIC_MAC, _TRAFFIC_MAC_2, _WIRED_PORT_ALIAS])
            )
        )
        await session.execute(delete(Device).where(Device.mac_address.in_([_TRAFFIC_MAC, _TRAFFIC_MAC_2])))
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


async def _add_traffic(
    mac: str, upload: int, download: int, when: datetime,
    granularity: TrafficGranularity = TrafficGranularity.PER_DEVICE,
) -> None:
    async with get_session() as session:
        session.add(TrafficSample(
            time=when, mac_address=mac, bytes_sent_delta=upload, bytes_recv_delta=download,
            granularity=granularity.value,
        ))


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
        """Same shared-DB caveat as test_sends_all_clear_when_no_alerts_
        since_cutoff above: a real household CRITICAL alert landing inside
        this 6h window (independently of the two WARNING/INFO alerts seeded
        below) would legitimately flip the observed severity to CRITICAL —
        occasional failure here isn't necessarily a bug."""
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

    async def test_device_traffic_section_sums_per_device_samples_and_resolves_label(self, scheduler):
        """Requested directly 2026-09-08: per-device upload/download totals
        for the digest window. Uses a nickname to also confirm
        resolve_device_label's nickname > hostname precedence end-to-end
        through the real query (not just the unit-level digest.py tests)."""
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=6))
        async with get_session() as session:
            # is_trusted=True: this test is about nickname resolution, not
            # trust — an untrusted device would pick up the [UNTRUSTED] tag
            # (see TestDeviceTrafficTrust in test_digest.py) and break the
            # exact-string match below for an unrelated reason.
            session.add(Device(
                mac_address=_TRAFFIC_MAC, hostname='zzz-test-host', nickname='ZZZ Test Nickname', is_trusted=True,
            ))
        await _add_traffic(_TRAFFIC_MAC, upload=1024 * 1024 * 500, download=1024 * 1024 * 100, when=now - timedelta(hours=3))
        await _add_traffic(_TRAFFIC_MAC, upload=1024 * 1024 * 500, download=1024 * 1024 * 100, when=now - timedelta(hours=2))

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert 'DEVICE TRAFFIC' in call['message']
        assert 'ZZZ Test Nickname: 1000.00 MB up / 200.00 MB down' in call['message']
        assert 'zzz-test-host' not in call['message']  # nickname wins over hostname

    async def test_device_traffic_section_shows_regardless_of_alert_content(self, scheduler):
        """Traffic and alert volume are independent — see digest.py's own
        docstrings. Doesn't assert on 'all clear'/alert presence at all: the
        shared dev DB may have real household alerts land in this window
        (see test_sends_all_clear_when_no_alerts_since_cutoff's docstring
        for the same caveat on that pre-existing test) — that's an
        orthogonal concern to whether *this device's* traffic shows up.
        Uses a deliberately large volume (not just 1-2MB) so this sample
        stays inside the MAX_TRAFFIC_DEVICES=20 cap regardless of how busy
        the live household's own devices are — a small sample could
        otherwise get truncated out on a heavy-traffic day."""
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=1))
        await _add_traffic(
            _TRAFFIC_MAC, upload=1024 * 1024 * 5000, download=1024 * 1024 * 5000, when=now - timedelta(minutes=30),
        )

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert 'DEVICE TRAFFIC' in call['message']
        # [UNTRUSTED]: no Device row exists for this MAC at all (no seed
        # above) — correctly reads as untrusted, same as a real Device.
        # is_trusted=False row (see digest_query.py's own comment on the
        # outerjoin-finds-nothing case).
        assert f'{_TRAFFIC_MAC} [UNTRUSTED]: 5000.00 MB up / 5000.00 MB down' in call['message']

    async def test_wired_per_port_samples_are_excluded_from_device_traffic(self, scheduler):
        """CLAUDE.md rule 5: a PER_PORT sample has no real per-device figure
        to report, only a port aggregate — it must never be attributed to
        an individual device in this section. Doesn't assert the whole
        section is absent — the shared dev DB has its own live PER_DEVICE
        traffic constantly, so the section legitimately still appears; only
        this specific wired alias must never be in it."""
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=1))
        await _add_traffic(
            _WIRED_PORT_ALIAS, upload=1024 * 1024 * 999, download=1024 * 1024 * 999,
            when=now - timedelta(minutes=30), granularity=TrafficGranularity.PER_PORT,
        )

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert _WIRED_PORT_ALIAS not in call['message']

    async def test_device_traffic_excludes_samples_before_cutoff(self, scheduler):
        """Same reasoning as the PER_PORT test above for why this doesn't
        assert the whole section is absent — only that *this* MAC's
        before-cutoff sample doesn't leak in."""
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=1))
        await _add_traffic(_TRAFFIC_MAC, upload=1024 * 1024, download=1024 * 1024, when=now - timedelta(hours=5))

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert _TRAFFIC_MAC not in call['message']

    async def test_device_traffic_falls_back_to_mac_when_no_device_row_exists(self, scheduler):
        """outerjoin — a TrafficSample can outlive/predate its Device row
        (or, in this test, simply never has one) and must still show up,
        labeled by its bare MAC rather than silently dropped."""
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=1))
        await _add_traffic(_TRAFFIC_MAC_2, upload=1024 * 1024, download=1024 * 1024, when=now - timedelta(minutes=30))

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert _TRAFFIC_MAC_2 in call['message']

    async def test_bandwidth_by_hour_section_appears_with_real_polling_data(self, scheduler):
        """Requested directly 2026-09-08: an hourly household bandwidth bar
        chart. The live scheduler polls WanStats every ~15s regardless of
        this test, so the section should always have something to show —
        same 'regardless of alert content' reasoning as the device-traffic
        tests above. Doesn't assert on specific figures here (that's
        test_digest.py's own unit-level coverage) since real household
        values can't be controlled from this test."""
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=1))

        await scheduler._security_digest_job()

        call = scheduler._notifier.calls[0]
        assert 'BANDWIDTH BY HOUR' in call['message']

    async def test_bandwidth_by_hour_sums_wan_stats_into_the_right_bucket(self, scheduler):
        """WanStats has no MAC column to scope a synthetic row by (see its
        own docstring — a single household-wide time series), so isolation
        here comes from magnitude rather than identity: 1TB in an hour is
        far beyond anything a real household would ever produce, so this
        seeded row dominates its bucket and becomes the reported peak
        regardless of whatever real live traffic also landed in it.
        Cleanup targets this exact seeded timestamp only — never a blanket
        delete, since this table also holds live real WAN history."""
        now = datetime.now(timezone.utc)
        await SettingsRepository().set_last_digest_sent_at(now - timedelta(hours=2))
        seed_time = (now - timedelta(hours=1)).replace(minute=17, second=3, microsecond=424242)
        async with get_session() as session:
            session.add(WanStats(time=seed_time, bytes_sent_delta=1024**4, bytes_recv_delta=1024**4))

        try:
            await scheduler._security_digest_job()

            call = scheduler._notifier.calls[0]
            assert 'BANDWIDTH BY HOUR' in call['message']
            assert f'peak {seed_time:%H}:00' in call['message']
        finally:
            async with get_session() as session:
                await session.execute(delete(WanStats).where(WanStats.time == seed_time))
