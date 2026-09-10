"""Tests for build_digest_data — the query shared between the daily digest
email (SentinelScheduler._security_digest_job, tested end-to-end against
this same function in tests/test_scheduler/test_security_digest.py) and the
Reports tab (sentinel/api/routes/reports.py). This file focuses on what's
new/different about using it as a general [start, end) x optional-device
query rather than always [cutoff, now) x every device — the underlying
per-section query shapes (alert grouping, PER_DEVICE traffic-only, hourly
WAN bandwidth) are already covered there and unchanged by this refactor.
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.adapter.models import TrafficGranularity
from sentinel.db.models import Alert, Device, TrafficSample, WanStats
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.notifications.digest_query import build_digest_data

pytestmark = pytest.mark.asyncio

# Distinctive/synthetic — never collide with real household MACs or with
# other test files' own fixtures (see test_security_digest.py's own note on
# why this matters against the shared dev DB).
_MAC_A = 'aa:bb:cc:dd:ee:c1'
_MAC_B = 'aa:bb:cc:dd:ee:c2'
_ALL_MACS = [_MAC_A, _MAC_B]

_NOW = datetime.now(timezone.utc)
_START = _NOW - timedelta(hours=6)
_END = _NOW


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
        await session.execute(delete(TrafficSample).where(TrafficSample.mac_address.in_(_ALL_MACS)))
        await session.execute(delete(Device).where(Device.mac_address.in_(_ALL_MACS)))
    await get_engine().dispose()


async def _add_alert(alert_type: str, device_mac: str, created_at: datetime, severity: str = 'WARNING') -> None:
    async with get_session() as session:
        session.add(Alert(device_mac=device_mac, alert_type=alert_type, severity=severity, created_at=created_at))


async def _add_traffic(
    mac: str, upload: int, download: int, when: datetime,
    granularity: TrafficGranularity = TrafficGranularity.PER_DEVICE,
) -> None:
    async with get_session() as session:
        session.add(TrafficSample(
            time=when, mac_address=mac, bytes_sent_delta=upload, bytes_recv_delta=download,
            granularity=granularity.value,
        ))


class TestWindowBounds:
    async def test_start_is_inclusive(self):
        await _add_alert('ZZZ_TEST_AT_START', _MAC_A, _START)

        async with get_session() as session:
            digest = await build_digest_data(session, _START, _END)

        assert 'ZZZ_TEST_AT_START' in {g.alert_type for g in digest.digest_groups}

    async def test_end_is_exclusive(self):
        await _add_alert('ZZZ_TEST_AT_END', _MAC_A, _END)

        async with get_session() as session:
            digest = await build_digest_data(session, _START, _END)

        assert 'ZZZ_TEST_AT_END' not in {g.alert_type for g in digest.digest_groups}

    async def test_all_clear_when_no_alerts_in_window(self):
        async with get_session() as session:
            digest = await build_digest_data(
                session, _START - timedelta(hours=1), _START - timedelta(minutes=1), device_mac='no:such:ma:cc:00:00',
            )

        assert digest.total == 0
        assert digest.digest_groups == []


class TestDeviceFilter:
    async def test_scopes_alert_groups_to_the_given_device(self):
        await _add_alert('ZZZ_TEST_DEV_A', _MAC_A, _NOW - timedelta(hours=1))
        await _add_alert('ZZZ_TEST_DEV_B', _MAC_B, _NOW - timedelta(hours=1))

        async with get_session() as session:
            digest = await build_digest_data(session, _START, _END, device_mac=_MAC_A)

        types = {g.alert_type for g in digest.digest_groups}
        assert 'ZZZ_TEST_DEV_A' in types
        assert 'ZZZ_TEST_DEV_B' not in types

    async def test_scopes_traffic_to_the_given_device(self):
        await _add_traffic(_MAC_A, 1000, 2000, _NOW - timedelta(hours=1))
        await _add_traffic(_MAC_B, 3000, 4000, _NOW - timedelta(hours=1))

        async with get_session() as session:
            digest = await build_digest_data(session, _START, _END, device_mac=_MAC_A)

        macs_in_traffic = {t.device_label for t in digest.traffic}
        assert _MAC_A in macs_in_traffic
        assert _MAC_B not in macs_in_traffic

    async def test_hourly_bandwidth_is_never_scoped_by_device(self):
        """WanStats has no device dimension at all — a device filter must
        never silently empty this section out."""
        seed_time = (_NOW - timedelta(hours=1)).replace(minute=11, second=2, microsecond=987654)
        async with get_session() as session:
            session.add(WanStats(time=seed_time, bytes_sent_delta=1024**4, bytes_recv_delta=1024**4))

        try:
            async with get_session() as session:
                digest_no_filter = await build_digest_data(session, _START, _END)
                digest_with_filter = await build_digest_data(session, _START, _END, device_mac=_MAC_A)

            hours_no_filter = {h.hour for h in digest_no_filter.hourly_bandwidth}
            hours_with_filter = {h.hour for h in digest_with_filter.hourly_bandwidth}
            assert hours_no_filter == hours_with_filter
        finally:
            async with get_session() as session:
                await session.execute(delete(WanStats).where(WanStats.time == seed_time))

    async def test_wired_per_port_traffic_is_excluded_even_when_device_filtered(self):
        """CLAUDE.md rule 5 — still applies once the query is device-scoped,
        not just for the household-wide case."""
        await _add_traffic(_MAC_A, 5000, 6000, _NOW - timedelta(hours=1), granularity=TrafficGranularity.PER_PORT)

        async with get_session() as session:
            digest = await build_digest_data(session, _START, _END, device_mac=_MAC_A)

        assert digest.traffic == []


class TestCaps:
    async def test_none_cap_returns_every_type_uncapped(self):
        for i in range(3):
            await _add_alert(f'ZZZ_TEST_TYPE_{i}', _MAC_A, _NOW - timedelta(minutes=i + 1))

        async with get_session() as session:
            digest = await build_digest_data(session, _START, _END, device_mac=_MAC_A, max_alert_types=None)

        seeded = {f'ZZZ_TEST_TYPE_{i}' for i in range(3)}
        assert seeded <= {g.alert_type for g in digest.digest_groups}
        assert digest.truncated is False

    async def test_explicit_cap_truncates_and_reports_the_true_total(self):
        for i in range(3):
            await _add_alert(f'ZZZ_TEST_CAP_{i}', _MAC_A, _NOW - timedelta(minutes=i + 1))

        async with get_session() as session:
            digest = await build_digest_data(session, _START, _END, device_mac=_MAC_A, max_alert_types=1)

        assert len(digest.digest_groups) == 1
        assert digest.total_types == 3
        assert digest.truncated is True

    async def test_none_traffic_cap_returns_every_device(self):
        await _add_traffic(_MAC_A, 100, 200, _NOW - timedelta(hours=1))
        await _add_traffic(_MAC_B, 300, 400, _NOW - timedelta(hours=1))

        async with get_session() as session:
            digest = await build_digest_data(session, _START, _END, max_traffic_devices=None)

        labels = {t.device_label for t in digest.traffic}
        assert _MAC_A in labels
        assert _MAC_B in labels
