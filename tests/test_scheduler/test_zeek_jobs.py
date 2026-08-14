"""Focused tests for SentinelScheduler's Zeek/ClamAV job bodies
(_zeek_dns_poll_job, _zeek_beacon_scan_job, _zeek_file_scan_job) — mirrors
tests/test_scheduler/test_threat_auto_block.py's object.__new__(SentinelScheduler)
pattern: these methods only ever touch a handful of constructor-wired
collaborators (the Zeek reader/ingester/detector/watcher, ClamAV scanner,
threat intel service, adapter, DB), never self._loop or the rest of
__init__'s unrelated kwargs.
"""
import os
from typing import Optional

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select

from sentinel.adapter.mock.mock_adapter import MockSagemcomAdapter
from sentinel.api.extensions import socketio
from sentinel.db.models import Alert, Device, DnsQuery
from sentinel.db.repositories import SettingsRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.scheduler import SentinelScheduler
from sentinel.security.threat_intel import ThreatIntelService
from sentinel.security.zeek_parser import ZeekDnsIngester

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'
_IP = '10.100.102.50'


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
        await session.execute(delete(Alert).where(Alert.device_mac == _MAC))
        await session.execute(delete(DnsQuery).where(DnsQuery.device_mac == _MAC))
        await session.execute(delete(Device).where(Device.mac_address == _MAC))
    await get_engine().dispose()


async def _seed_device(**overrides) -> None:
    async with get_session() as session:
        session.add(Device(mac_address=_MAC, ip_address=_IP, hostname='test-device', **overrides))


async def _latest_alert() -> Optional[Alert]:
    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.device_mac == _MAC).order_by(Alert.created_at.desc())
        )
        return result.scalars().first()


async def _dns_queries() -> list[DnsQuery]:
    async with get_session() as session:
        result = await session.execute(select(DnsQuery).where(DnsQuery.device_mac == _MAC))
        return list(result.scalars().all())


async def _all_alerts() -> list[Alert]:
    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
        return list(result.scalars().all())


class _FakeReader:
    def __init__(self, lines: list[str]) -> None:
        self._lines = lines

    def read_new_lines(self) -> list[str]:
        return self._lines


class _FakeBeaconDetector:
    def __init__(self, results: list[dict]) -> None:
        self._results = results

    def detect(self) -> list[dict]:
        return self._results


class _FakeFileWatcher:
    def __init__(self, files: list[tuple]) -> None:
        self._files = files

    def collect(self) -> list[tuple]:
        return self._files


class _FakeClamAv:
    def __init__(self, scan_result: Optional[dict], reachable: bool = True) -> None:
        self._scan_result = scan_result
        self._reachable = reachable

    async def ping(self) -> bool:
        return self._reachable

    async def scan_bytes(self, data: bytes) -> Optional[dict]:
        return self._scan_result


@pytest.fixture
def scheduler():
    """A scheduler with only the collaborators these job methods touch — see
    module docstring."""
    sched = object.__new__(SentinelScheduler)
    sched._adapter = MockSagemcomAdapter()
    sched._threat_intel = ThreatIntelService('')
    return sched


class TestZeekDnsPollJob:
    async def test_benign_query_is_recorded_but_not_alerted(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        sched = scheduler
        sched._zeek_dns_reader = _FakeReader(
            [f'{{"id.orig_h": "{_IP}", "query": "example.com"}}']
        )
        sched._zeek_dns_ingester = ZeekDnsIngester()

        await sched._zeek_dns_poll_job()

        queries = await _dns_queries()
        assert len(queries) == 1
        assert queries[0].query == 'example.com'
        assert queries[0].blocked is False
        assert await _latest_alert() is None

    async def test_malicious_query_is_blocked_and_alerted(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        sched = scheduler
        sched._threat_intel._domains.add('malicious.example.com')
        sched._zeek_dns_reader = _FakeReader(
            [f'{{"id.orig_h": "{_IP}", "query": "malicious.example.com"}}']
        )
        sched._zeek_dns_ingester = ZeekDnsIngester()

        await sched._zeek_dns_poll_job()

        queries = await _dns_queries()
        assert len(queries) == 1
        assert queries[0].blocked is True
        assert queries[0].list_name == 'urlhaus'
        alert = await _latest_alert()
        assert alert is not None
        assert alert.alert_type == 'DNS_MALICIOUS_QUERY'
        assert 'auto-blocked' in alert.description

    async def test_repeated_query_to_the_same_domain_coalesces_into_one_touched_row(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(False)
        sched = scheduler
        sched._threat_intel._domains.add('malicious.example.com')
        sched._zeek_dns_reader = _FakeReader([
            f'{{"id.orig_h": "{_IP}", "query": "malicious.example.com"}}',
            f'{{"id.orig_h": "{_IP}", "query": "malicious.example.com"}}',
        ])
        sched._zeek_dns_ingester = ZeekDnsIngester()

        await sched._zeek_dns_poll_job()

        alerts = await _all_alerts()
        assert len(alerts) == 1
        assert alerts[0].occurrence_count == 2

    async def test_a_different_malicious_domain_does_not_coalesce(self, scheduler):
        """dedup_key=domain — a second, different malicious query on the
        same device is a distinct finding, not a repeat of the first."""
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(False)
        sched = scheduler
        sched._threat_intel._domains.add('malicious-1.example.com')
        sched._threat_intel._domains.add('malicious-2.example.com')
        sched._zeek_dns_reader = _FakeReader([
            f'{{"id.orig_h": "{_IP}", "query": "malicious-1.example.com"}}',
            f'{{"id.orig_h": "{_IP}", "query": "malicious-2.example.com"}}',
        ])
        sched._zeek_dns_ingester = ZeekDnsIngester()

        await sched._zeek_dns_poll_job()

        alerts = await _all_alerts()
        assert len(alerts) == 2

    async def test_malformed_lines_are_skipped(self, scheduler):
        sched = scheduler
        sched._zeek_dns_reader = _FakeReader(['not json {{{'])
        sched._zeek_dns_ingester = ZeekDnsIngester()

        await sched._zeek_dns_poll_job()  # must not raise

        assert await _dns_queries() == []


class TestZeekBeaconScanJob:
    async def test_suspicious_pair_raises_an_alert(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        sched = scheduler
        sched._zeek_beacon_detector = _FakeBeaconDetector([{
            'src': _IP, 'dst': '203.0.113.10', 'count': 20,
            'interval_mean_s': 60.0, 'interval_std_s': 0.5,
        }])

        await sched._zeek_beacon_scan_job()

        alert = await _latest_alert()
        assert alert is not None
        assert alert.alert_type == 'C2_BEACONING'
        assert '203.0.113.10' in alert.description

    async def test_no_suspicious_pairs_raises_nothing(self, scheduler):
        sched = scheduler
        sched._zeek_beacon_detector = _FakeBeaconDetector([])

        await sched._zeek_beacon_scan_job()  # must not raise

        assert await _latest_alert() is None

    async def test_a_second_scan_of_the_same_pair_coalesces_into_one_touched_row(self, scheduler):
        """dedup_key=dst — the same (src, dst) beaconing pair found again on
        a later scan touches the same row instead of flooding inserts."""
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(False)
        sched = scheduler
        pair = {'src': _IP, 'dst': '203.0.113.10', 'count': 20, 'interval_mean_s': 60.0, 'interval_std_s': 0.5}
        sched._zeek_beacon_detector = _FakeBeaconDetector([pair])

        await sched._zeek_beacon_scan_job()
        await sched._zeek_beacon_scan_job()

        alerts = await _all_alerts()
        assert len(alerts) == 1
        assert alerts[0].occurrence_count == 2


class TestZeekFileScanJob:
    async def test_infected_file_raises_malware_alert(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        sched = scheduler
        sched._zeek_file_watcher = _FakeFileWatcher([('evil.exe', b'payload', _IP)])
        sched._clamav = _FakeClamAv({'stream': ('FOUND', 'Eicar-Test-Signature')})

        await sched._zeek_file_scan_job()

        alert = await _latest_alert()
        assert alert is not None
        assert alert.alert_type == 'MALWARE_DETECTED'
        assert 'evil.exe' in alert.description
        assert sched._clamav_reachable is True

    async def test_clean_file_raises_nothing(self, scheduler):
        sched = scheduler
        sched._zeek_file_watcher = _FakeFileWatcher([('clean.txt', b'hello', _IP)])
        sched._clamav = _FakeClamAv(None)

        await sched._zeek_file_scan_job()

        assert await _latest_alert() is None

    async def test_unattributed_file_still_scanned(self, scheduler):
        """source_ip is None when files.log couldn't attribute the file —
        that shouldn't stop the file from being scanned, only from being
        attributed to a device."""
        sched = scheduler
        sched._zeek_file_watcher = _FakeFileWatcher([('unknown.exe', b'payload', None)])
        sched._clamav = _FakeClamAv({'stream': ('FOUND', 'Eicar-Test-Signature')})

        await sched._zeek_file_scan_job()

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.alert_type == 'MALWARE_DETECTED').order_by(Alert.created_at.desc())
            )
            alert = result.scalars().first()
        assert alert is not None
        assert alert.device_mac is None
        async with get_session() as session:
            await session.execute(delete(Alert).where(Alert.id == alert.id))

    async def test_clamav_reachability_is_recorded(self, scheduler):
        sched = scheduler
        sched._zeek_file_watcher = _FakeFileWatcher([])
        sched._clamav = _FakeClamAv(None, reachable=False)

        await sched._zeek_file_scan_job()

        assert sched._clamav_reachable is False
