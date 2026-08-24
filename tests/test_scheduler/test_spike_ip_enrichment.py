"""Tests for SentinelScheduler._spike_ip_enrichment_job — correlates recent
traffic-spike alerts (ANOMALOUS_VOLUME/HIGH_UPLOAD/WAN_BANDWIDTH_SPIKE)
against Zeek's conn.log for a remote IP and checks it against threat intel,
escalating a malicious verdict via _raise_threat_alert. Mirrors
tests/test_scheduler/test_zeek_jobs.py's object.__new__(SentinelScheduler)
pattern — this job only ever touches self._conn_volume_correlator,
self._threat_intel, self._adapter, and the DB.
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select

from sentinel.adapter.mock.mock_adapter import MockSagemcomAdapter
from sentinel.api.extensions import socketio
from sentinel.db.models import Alert, Device, ThreatIntelCache
from sentinel.db.repositories import AlertRepository, SettingsRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.scheduler import SentinelScheduler
from sentinel.security.threat_intel import ThreatIntelService
from sentinel.security.zeek_parser import ConnTalker

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'
_MAC2 = 'aa:bb:cc:dd:ee:f2'
_IP = '10.100.102.50'
_IP2 = '10.100.102.51'
_REMOTE_IP = '203.0.113.10'


@pytest.fixture(autouse=True, scope='module')
def _init_socketio_once():
    """Wire up socketio.emit() — _raise_threat_alert broadcasts over it."""
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
        await session.execute(delete(Alert).where(Alert.device_mac.in_([_MAC, _MAC2])))
        await session.execute(delete(Alert).where(Alert.alert_type == 'WAN_BANDWIDTH_SPIKE'))
        await session.execute(delete(Device).where(Device.mac_address.in_([_MAC, _MAC2])))
        await session.execute(delete(ThreatIntelCache).where(ThreatIntelCache.ip_or_domain == _REMOTE_IP))
    await get_engine().dispose()


async def _seed_device(mac: str, ip: str, **overrides) -> None:
    async with get_session() as session:
        session.add(Device(mac_address=mac, ip_address=ip, hostname=f'device-{mac}', **overrides))


async def _seed_spike_alert(alert_type: str, device_mac: str | None, **overrides) -> int:
    kwargs = dict(created_at=datetime.now(timezone.utc) - timedelta(minutes=2))
    kwargs.update(overrides)
    async with get_session() as session:
        alert = Alert(device_mac=device_mac, alert_type=alert_type, severity='WARNING', **kwargs)
        session.add(alert)
        await session.flush()
        alert_id = alert.id
    return alert_id


async def _get_alert(alert_id: int) -> Alert:
    async with get_session() as session:
        return await session.get(Alert, alert_id)


async def _all_alerts_for(alert_type: str) -> list[Alert]:
    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.alert_type == alert_type))
        return list(result.scalars().all())


class _FakeCorrelator:
    def __init__(self, talkers: list[ConnTalker]) -> None:
        self._talkers = talkers
        self.calls: list[dict] = []

    def top_talkers(self, *, local_ips, since, until, top_n=3):
        self.calls.append({'local_ips': local_ips, 'since': since, 'until': until, 'top_n': top_n})
        return self._talkers


@pytest.fixture
def scheduler():
    sched = object.__new__(SentinelScheduler)
    sched._adapter = MockSagemcomAdapter()
    sched._threat_intel = ThreatIntelService('')
    sched._conn_volume_correlator = None
    sched._last_spike_ip_enrichment_at = None
    return sched


class TestSpikeIpEnrichmentJob:
    async def test_no_correlator_does_nothing(self, scheduler):
        alert_id = await _seed_spike_alert('HIGH_UPLOAD', _MAC)
        scheduler._conn_volume_correlator = None

        await scheduler._spike_ip_enrichment_job()

        refreshed = await _get_alert(alert_id)
        assert (refreshed.raw_data or {}).get('ip_enrichment_done') is None

    async def test_benign_top_talker_annotates_without_escalating(self, scheduler):
        await _seed_device(_MAC, _IP, is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        alert_id = await _seed_spike_alert('HIGH_UPLOAD', _MAC)
        scheduler._conn_volume_correlator = _FakeCorrelator(
            [ConnTalker(local_ip=_IP, remote_ip=_REMOTE_IP, total_bytes=5000, connection_count=3)]
        )

        await scheduler._spike_ip_enrichment_job()

        refreshed = await _get_alert(alert_id)
        assert refreshed.raw_data['ip_enrichment_done'] is True
        assert refreshed.raw_data['remote_ip'] == _REMOTE_IP
        assert refreshed.raw_data['remote_ip_bytes'] == 5000
        assert refreshed.raw_data['remote_ip_malicious'] is False
        assert refreshed.raw_data['remote_ip_internal'] is False
        assert await _all_alerts_for('MALICIOUS_TRAFFIC_DESTINATION') == []

    async def test_malicious_top_talker_escalates_to_a_new_critical_alert(self, scheduler):
        await _seed_device(_MAC, _IP, is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        alert_id = await _seed_spike_alert('ANOMALOUS_VOLUME', _MAC)
        scheduler._conn_volume_correlator = _FakeCorrelator(
            [ConnTalker(local_ip=_IP, remote_ip=_REMOTE_IP, total_bytes=9000, connection_count=5)]
        )
        scheduler._threat_intel._ip_block.add(_REMOTE_IP)

        await scheduler._spike_ip_enrichment_job()

        refreshed = await _get_alert(alert_id)
        assert refreshed.raw_data['remote_ip_malicious'] is True
        assert refreshed.raw_data['remote_ip_internal'] is False

        escalated = await _all_alerts_for('MALICIOUS_TRAFFIC_DESTINATION')
        assert len(escalated) == 1
        assert escalated[0].device_mac == _MAC
        assert escalated[0].severity == 'CRITICAL'
        assert escalated[0].dedup_key == _REMOTE_IP
        assert escalated[0].raw_data['trigger_alert_id'] == alert_id
        assert escalated[0].raw_data['trigger_alert_type'] == 'ANOMALOUS_VOLUME'
        assert 'auto-blocked' in escalated[0].description

    async def test_an_already_enriched_alert_is_not_reprocessed(self, scheduler):
        await _seed_device(_MAC, _IP, is_blocked=False)
        alert_id = await _seed_spike_alert(
            'HIGH_UPLOAD', _MAC, raw_data={'ip_enrichment_done': True, 'remote_ip': 'already-set'},
        )
        fake = _FakeCorrelator([ConnTalker(local_ip=_IP, remote_ip=_REMOTE_IP, total_bytes=1, connection_count=1)])
        scheduler._conn_volume_correlator = fake

        await scheduler._spike_ip_enrichment_job()

        assert fake.calls == []
        refreshed = await _get_alert(alert_id)
        assert refreshed.raw_data['remote_ip'] == 'already-set'

    async def test_no_talkers_marks_done_without_remote_ip(self, scheduler):
        await _seed_device(_MAC, _IP, is_blocked=False)
        alert_id = await _seed_spike_alert('HIGH_UPLOAD', _MAC)
        scheduler._conn_volume_correlator = _FakeCorrelator([])

        await scheduler._spike_ip_enrichment_job()

        refreshed = await _get_alert(alert_id)
        assert refreshed.raw_data['ip_enrichment_done'] is True
        assert 'remote_ip' not in refreshed.raw_data

    async def test_wan_bandwidth_spike_uses_only_online_devices(self, scheduler):
        await _seed_device(_MAC, _IP, is_online=True, is_blocked=False)
        await _seed_device(_MAC2, _IP2, is_online=False, is_blocked=False)
        alert_id = await _seed_spike_alert('WAN_BANDWIDTH_SPIKE', None)
        fake = _FakeCorrelator(
            [ConnTalker(local_ip=_IP, remote_ip=_REMOTE_IP, total_bytes=1000, connection_count=2)]
        )
        scheduler._conn_volume_correlator = fake

        await scheduler._spike_ip_enrichment_job()

        assert len(fake.calls) == 1
        assert fake.calls[0]['local_ips'] == {_IP}  # offline _IP2 excluded

        refreshed = await _get_alert(alert_id)
        assert refreshed.raw_data['remote_ip'] == _REMOTE_IP
        assert refreshed.raw_data['remote_ip_local_device'] == _IP

    async def test_wan_bandwidth_spike_with_no_online_devices_marks_done(self, scheduler):
        await _seed_device(_MAC, _IP, is_online=False, is_blocked=False)
        alert_id = await _seed_spike_alert('WAN_BANDWIDTH_SPIKE', None)
        fake = _FakeCorrelator([ConnTalker(local_ip=_IP, remote_ip=_REMOTE_IP, total_bytes=1, connection_count=1)])
        scheduler._conn_volume_correlator = fake

        await scheduler._spike_ip_enrichment_job()

        assert fake.calls == []  # never called — no local IPs to correlate
        refreshed = await _get_alert(alert_id)
        assert refreshed.raw_data['ip_enrichment_done'] is True

    async def test_alerts_outside_the_lookback_window_are_ignored(self, scheduler):
        await _seed_device(_MAC, _IP, is_blocked=False)
        alert_id = await _seed_spike_alert(
            'HIGH_UPLOAD', _MAC, created_at=datetime.now(timezone.utc) - timedelta(hours=2),
        )
        fake = _FakeCorrelator([ConnTalker(local_ip=_IP, remote_ip=_REMOTE_IP, total_bytes=1, connection_count=1)])
        scheduler._conn_volume_correlator = fake

        await scheduler._spike_ip_enrichment_job()

        assert fake.calls == []
        refreshed = await _get_alert(alert_id)
        assert (refreshed.raw_data or {}).get('ip_enrichment_done') is None

    async def test_a_correlator_exception_for_one_alert_does_not_stop_the_batch(self, scheduler):
        await _seed_device(_MAC, _IP, is_blocked=False)
        await _seed_device(_MAC2, _IP2, is_blocked=False)
        bad_id = await _seed_spike_alert('HIGH_UPLOAD', _MAC)
        good_id = await _seed_spike_alert('HIGH_UPLOAD', _MAC2)

        class _BoomCorrelator:
            def top_talkers(self, **kwargs):
                if kwargs['local_ips'] == {_IP}:
                    raise RuntimeError('conn.log unreadable')
                return [ConnTalker(local_ip=_IP2, remote_ip=_REMOTE_IP, total_bytes=1, connection_count=1)]

        scheduler._conn_volume_correlator = _BoomCorrelator()

        await scheduler._spike_ip_enrichment_job()  # must not raise

        bad_alert = await _get_alert(bad_id)
        good_alert = await _get_alert(good_id)
        assert (bad_alert.raw_data or {}).get('ip_enrichment_done') is None
        assert good_alert.raw_data['ip_enrichment_done'] is True


class TestInternalDestination:
    """A private-range top talker is informational only — see
    SentinelScheduler._is_internal_ip / _enrich_spike_alert. Threat intel
    is never consulted and MALICIOUS_TRAFFIC_DESTINATION never fires, even
    if that address happens to be in the (nonsensical, for a private IP)
    block list — proves the skip is unconditional, not just "happened to
    come back clean"."""

    _INTERNAL_REMOTE_IP = '10.100.102.77'  # another device on the same LAN

    async def test_annotates_as_internal_without_a_threat_intel_check(self, scheduler):
        await _seed_device(_MAC, _IP, is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        alert_id = await _seed_spike_alert('HIGH_UPLOAD', _MAC)
        scheduler._conn_volume_correlator = _FakeCorrelator(
            [ConnTalker(local_ip=_IP, remote_ip=self._INTERNAL_REMOTE_IP, total_bytes=5000, connection_count=3)]
        )
        # In the block list — if this were consulted, it would misfire as
        # malicious. It must not even be looked at.
        scheduler._threat_intel._ip_block.add(self._INTERNAL_REMOTE_IP)

        await scheduler._spike_ip_enrichment_job()

        refreshed = await _get_alert(alert_id)
        assert refreshed.raw_data['ip_enrichment_done'] is True
        assert refreshed.raw_data['remote_ip'] == self._INTERNAL_REMOTE_IP
        assert refreshed.raw_data['remote_ip_internal'] is True
        assert 'remote_ip_malicious' not in refreshed.raw_data
        assert await _all_alerts_for('MALICIOUS_TRAFFIC_DESTINATION') == []

    async def test_loopback_and_link_local_are_also_treated_as_internal(self, scheduler):
        await _seed_device(_MAC, _IP, is_blocked=False)
        for remote_ip in ('127.0.0.1', '169.254.1.1'):
            alert_id = await _seed_spike_alert('HIGH_UPLOAD', _MAC)
            scheduler._conn_volume_correlator = _FakeCorrelator(
                [ConnTalker(local_ip=_IP, remote_ip=remote_ip, total_bytes=1, connection_count=1)]
            )
            await scheduler._spike_ip_enrichment_job()
            refreshed = await _get_alert(alert_id)
            assert refreshed.raw_data['remote_ip_internal'] is True, remote_ip
