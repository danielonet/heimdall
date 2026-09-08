"""Integration tests for SentinelScheduler._data_retention_job against a real
Postgres/TimescaleDB. Constructs the scheduler directly (bypassing start(),
which spins up its own background thread/event loop) and calls the job
coroutine in-process on the current test event loop — consistent with how
tests/test_scheduler/test_jobs.py exercises poll_cycle() directly.

Note on chunk-granularity: drop_chunks() only removes a TimescaleDB chunk
once its *entire* time range is older than the cutoff (default
chunk_time_interval is 7 days) — a chunk straddling the cutoff is kept
whole. Every timestamp below is chosen many chunks away from "now" or from
the cutoff so these assertions don't depend on chunk-boundary alignment.
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select

from sentinel.db.models import Alert, AppSettings, PortStats, TrafficSample, WanStatusHistory
from sentinel.db.repositories import SettingsRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.notifications.service import NotificationConfig
from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'
_PORT = 'PHY9'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)

    # These tests call SettingsRepository().set_data_retention_days(...) to
    # exercise several windows — snapshot the AppSettings row that's
    # actually there first and restore it verbatim on teardown, rather than
    # the old `delete(AppSettings)` cleanup, which reset the *entire* row
    # (SMTP config, auto_block_on_threat, baseline_established_at,
    # everything) back to schema defaults — including on the shared dev DB
    # a live instance is also using. That silently wiped a real user's
    # settings whenever this suite happened to run — see 2026-09-08
    # incident.
    async with get_session() as session:
        original = await session.get(AppSettings, 1)
        original_values = (
            {c.name: getattr(original, c.name) for c in AppSettings.__table__.columns}
            if original is not None else None
        )

    yield
    async with get_session() as session:
        await session.execute(delete(TrafficSample).where(TrafficSample.mac_address == _MAC))
        await session.execute(delete(PortStats).where(PortStats.port_alias == _PORT))
        await session.execute(delete(Alert).where(Alert.device_mac == _MAC))
        await session.execute(delete(WanStatusHistory))
        await session.execute(delete(AppSettings))
        if original_values is not None:
            session.add(AppSettings(**original_values))
    await get_engine().dispose()


def _scheduler() -> SentinelScheduler:
    return SentinelScheduler(
        poll_interval_s=15,
        redis_url='redis://localhost:6379',
        ml_model_dir='/tmp/heimdall-test-models',
        ml_min_samples=100,
        ml_contamination=0.05,
        ml_anomaly_magnitude_multiplier=0.5,
        ml_anomaly_alert_magnitude_multiplier=1.5,
        ml_retrain_cron='0 3 * * *',
        sniff_iface='lo',
        otx_api_key='',
        nmap_scan_cron='0 2 * * *',
        threat_feed_refresh_cron='0 4 * * *',
        data_retention_cron='30 3 * * *',
        notification_config=NotificationConfig(),
        opencanary_log_path='/tmp/heimdall-test-opencanary.log',
        canary_poll_interval_s=10,
        zeek_log_dir='/tmp/heimdall-test-zeek',
        zeek_extract_dir='/tmp/heimdall-test-zeek-extracted',
        zeek_dns_poll_interval_s=10,
        zeek_beacon_scan_interval_s=300,
        spike_ip_enrichment_interval_s=300,
        clamav_host='localhost',
        clamav_port=3310,
        suricata_eve_log_path='/tmp/heimdall-test-suricata-eve.json',
        suricata_poll_interval_s=15,
        block_expiry_check_interval_s=900,
        correlation_scan_interval_s=300,
        alert_auto_resolve_check_interval_s=1800,
        device_identity_link_scan_interval_s=300,
        stale_device_reap_interval_s=120,
        device_archive_sweep_interval_s=3600,
        security_digest_cron='0 7 * * *',
    )


class TestDataRetentionJob:
    async def test_drops_old_traffic_samples_keeps_recent(self):
        old = datetime.now(timezone.utc) - timedelta(days=200)
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        async with get_session() as session:
            session.add(TrafficSample(time=old, mac_address=_MAC, granularity='per_device', poll_interval_s=15))
            session.add(TrafficSample(time=recent, mac_address=_MAC, granularity='per_device', poll_interval_s=15))
        await SettingsRepository().set_data_retention_days(90)

        await _scheduler()._data_retention_job()

        async with get_session() as session:
            result = await session.execute(select(TrafficSample).where(TrafficSample.mac_address == _MAC))
            rows = result.scalars().all()
        assert len(rows) == 1

    async def test_drops_old_port_stats_keeps_recent(self):
        old = datetime.now(timezone.utc) - timedelta(days=200)
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        async with get_session() as session:
            session.add(PortStats(time=old, port_alias=_PORT))
            session.add(PortStats(time=recent, port_alias=_PORT))
        await SettingsRepository().set_data_retention_days(90)

        await _scheduler()._data_retention_job()

        async with get_session() as session:
            result = await session.execute(select(PortStats).where(PortStats.port_alias == _PORT))
            rows = result.scalars().all()
        assert len(rows) == 1

    async def test_deletes_old_alerts_keeps_recent(self):
        async with get_session() as session:
            old_alert = Alert(device_mac=_MAC, alert_type='NEW_DEVICE', severity='CRITICAL')
            session.add(old_alert)
            await session.flush()
            old_alert.created_at = datetime.now(timezone.utc) - timedelta(days=200)
            session.add(Alert(device_mac=_MAC, alert_type='NEW_DEVICE', severity='CRITICAL'))
        await SettingsRepository().set_data_retention_days(90)

        await _scheduler()._data_retention_job()

        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            rows = result.scalars().all()
        assert len(rows) == 1

    async def test_deletes_old_wan_status_history_keeps_recent(self):
        async with get_session() as session:
            old = WanStatusHistory(status='UP')
            session.add(old)
            await session.flush()
            old.changed_at = datetime.now(timezone.utc) - timedelta(days=200)
            session.add(WanStatusHistory(status='DOWN'))
        await SettingsRepository().set_data_retention_days(90)

        await _scheduler()._data_retention_job()

        async with get_session() as session:
            result = await session.execute(select(WanStatusHistory))
            rows = result.scalars().all()
        assert len(rows) == 1

    async def test_reads_the_configured_retention_dynamically(self):
        """The retention window comes from SettingsRepository on every run,
        not a value frozen at scheduler construction — an admin's change in
        the Settings tab must take effect on the very next nightly run."""
        old = datetime.now(timezone.utc) - timedelta(days=100)
        async with get_session() as session:
            session.add(TrafficSample(time=old, mac_address=_MAC, granularity='per_device', poll_interval_s=15))

        await SettingsRepository().set_data_retention_days(365)  # longer than 100 days — must survive
        await _scheduler()._data_retention_job()
        async with get_session() as session:
            result = await session.execute(select(TrafficSample).where(TrafficSample.mac_address == _MAC))
            assert len(result.scalars().all()) == 1

        await SettingsRepository().set_data_retention_days(1)  # now shorter — must be dropped
        await _scheduler()._data_retention_job()
        async with get_session() as session:
            result = await session.execute(select(TrafficSample).where(TrafficSample.mac_address == _MAC))
            assert result.scalars().all() == []

    async def test_devices_and_trusted_macs_are_never_touched(self):
        """Retention is scoped to time-series history — devices/trusted_macs
        represent current known-device state, not a rolling log, and must
        survive regardless of how old first_seen/last_seen is."""
        from sentinel.db.models import Device, TrustedMac

        long_ago = datetime.now(timezone.utc) - timedelta(days=400)
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='ancient-but-still-owned', last_seen=long_ago))
            session.add(TrustedMac(mac_address=_MAC, trusted_at=long_ago))
        await SettingsRepository().set_data_retention_days(1)

        try:
            await _scheduler()._data_retention_job()

            async with get_session() as session:
                assert await session.get(Device, _MAC) is not None
                assert await session.get(TrustedMac, _MAC) is not None
        finally:
            async with get_session() as session:
                await session.execute(delete(Device).where(Device.mac_address == _MAC))
                await session.execute(delete(TrustedMac).where(TrustedMac.mac_address == _MAC))
