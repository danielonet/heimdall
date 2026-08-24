"""Focused tests for SentinelScheduler._nmap_scan_job — mirrors
tests/test_scheduler/test_threat_auto_block.py's object.__new__(SentinelScheduler)
pattern: this method only ever touches self._scanner, self._adapter, and the
DB, never self._loop or any of __init__'s unrelated kwargs.

Covers the three alert paths this function raises: the pre-existing
HIGH_RISK_PORT_OPENED / VULNERABILITY_DETECTED (regression coverage, since
neither had a direct test before this file — this same function was edited
to add the two paths below) plus the two new ones added this session:
CREDENTIAL_EXPOSURE_DETECTED and OS_FINGERPRINT_CONFLICT.
"""
import os

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select

from sentinel.adapter.mock.mock_adapter import MockSagemcomAdapter
from sentinel.api.extensions import socketio
from sentinel.db.models import Alert, Device, PortAllowlistEntry
from sentinel.db.repositories import PortAllowlistRepository, SettingsRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.scheduler import SentinelScheduler
from sentinel.security.scanner import OpenPort, ScanResult

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
        await session.execute(delete(Device).where(Device.mac_address == _MAC))
        await session.execute(delete(PortAllowlistEntry).where(PortAllowlistEntry.device_mac == _MAC))
    await get_engine().dispose()


async def _seed_device(**overrides) -> None:
    async with get_session() as session:
        session.add(Device(mac_address=_MAC, ip_address=_IP, hostname='test-device', **overrides))


async def _latest_alert(alert_type: str | None = None) -> Alert | None:
    async with get_session() as session:
        query = select(Alert).where(Alert.device_mac == _MAC)
        if alert_type:
            query = query.where(Alert.alert_type == alert_type)
        result = await session.execute(query.order_by(Alert.created_at.desc()))
        return result.scalars().first()


class _FakeScanner:
    def __init__(self, scan_result, vuln_findings=None, credential_findings=None):
        self._scan_result = scan_result
        self._vuln_findings = vuln_findings or {}
        self._credential_findings = credential_findings or {}

    async def scan_device(self, ip):
        return self._scan_result

    async def vuln_scan(self, ip):
        return self._vuln_findings

    async def credential_scan(self, ip):
        return self._credential_findings


@pytest.fixture
def scheduler():
    """A scheduler with only self._adapter populated — see module docstring."""
    sched = object.__new__(SentinelScheduler)
    sched._adapter = MockSagemcomAdapter()
    return sched


class TestHighRiskPortRegression:
    async def test_newly_opened_high_risk_port_alerts(self, scheduler):
        await _seed_device(nmap_profile={'ports': []})
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(
            ScanResult(ip=_IP, os='Unknown', ports=[
                OpenPort(port=23, protocol='tcp', service='telnet', version='', state='open'),
            ]),
        )

        await scheduler._nmap_scan_job()

        alert = await _latest_alert('HIGH_RISK_PORT_OPENED')
        assert alert is not None
        assert 'Telnet' in alert.description

    async def test_previously_open_high_risk_port_does_not_re_alert(self, scheduler):
        await _seed_device(nmap_profile={'ports': [{'port': 23, 'state': 'open'}]})
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(
            ScanResult(ip=_IP, os='Unknown', ports=[
                OpenPort(port=23, protocol='tcp', service='telnet', version='', state='open'),
            ]),
        )

        await scheduler._nmap_scan_job()

        assert await _latest_alert('HIGH_RISK_PORT_OPENED') is None

    async def test_two_different_newly_opened_ports_do_not_coalesce(self, scheduler):
        """dedup_key=port — a second, different port opening on a later
        scan is a distinct finding, not a repeat of the first."""
        await _seed_device(nmap_profile={'ports': []})
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(
            ScanResult(ip=_IP, os='Unknown', ports=[
                OpenPort(port=23, protocol='tcp', service='telnet', version='', state='open'),
            ]),
        )
        await scheduler._nmap_scan_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
            device.nmap_profile = {'ports': [{'port': 23, 'state': 'open'}]}
        scheduler._scanner = _FakeScanner(
            ScanResult(ip=_IP, os='Unknown', ports=[
                OpenPort(port=23, protocol='tcp', service='telnet', version='', state='open'),
                OpenPort(port=3389, protocol='tcp', service='rdp', version='', state='open'),
            ]),
        )
        await scheduler._nmap_scan_job()

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.device_mac == _MAC, Alert.alert_type == 'HIGH_RISK_PORT_OPENED')
            )
            alerts = result.scalars().all()
        assert len(alerts) == 2


class TestPortAllowlist:
    async def test_allowlisted_port_does_not_alert(self, scheduler):
        await _seed_device(nmap_profile={'ports': []})
        await SettingsRepository().set_auto_block_on_threat(False)
        await PortAllowlistRepository().allow(_MAC, 445, 'SMB', note='print server')
        scheduler._scanner = _FakeScanner(
            ScanResult(ip=_IP, os='Unknown', ports=[
                OpenPort(port=445, protocol='tcp', service='microsoft-ds', version='', state='open'),
            ]),
        )

        await scheduler._nmap_scan_job()

        assert await _latest_alert('HIGH_RISK_PORT_OPENED') is None

    async def test_allowlisting_one_port_does_not_suppress_a_different_high_risk_port(self, scheduler):
        await _seed_device(nmap_profile={'ports': []})
        await SettingsRepository().set_auto_block_on_threat(False)
        await PortAllowlistRepository().allow(_MAC, 445, 'SMB')
        scheduler._scanner = _FakeScanner(
            ScanResult(ip=_IP, os='Unknown', ports=[
                OpenPort(port=445, protocol='tcp', service='microsoft-ds', version='', state='open'),
                OpenPort(port=23, protocol='tcp', service='telnet', version='', state='open'),
            ]),
        )

        await scheduler._nmap_scan_job()

        assert await _latest_alert('HIGH_RISK_PORT_OPENED') is not None
        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.device_mac == _MAC, Alert.alert_type == 'HIGH_RISK_PORT_OPENED')
            )
            alerts = result.scalars().all()
        assert len(alerts) == 1
        assert 'Telnet' in alerts[0].description

    async def test_allowlisting_does_not_affect_a_different_device(self, scheduler):
        other_mac = '11:22:33:44:55:66'
        await _seed_device(nmap_profile={'ports': []})
        async with get_session() as session:
            session.add(Device(mac_address=other_mac, ip_address='10.100.102.51', hostname='other-device'))
        await SettingsRepository().set_auto_block_on_threat(False)
        await PortAllowlistRepository().allow(other_mac, 445, 'SMB')
        scheduler._scanner = _FakeScanner(
            ScanResult(ip=_IP, os='Unknown', ports=[
                OpenPort(port=445, protocol='tcp', service='microsoft-ds', version='', state='open'),
            ]),
        )

        await scheduler._nmap_scan_job()

        assert await _latest_alert('HIGH_RISK_PORT_OPENED') is not None
        async with get_session() as session:
            await session.execute(delete(Device).where(Device.mac_address == other_mac))
            await session.execute(delete(PortAllowlistEntry).where(PortAllowlistEntry.device_mac == other_mac))


class TestVulnScanRegression:
    async def test_vuln_findings_alert(self, scheduler):
        await _seed_device(nmap_profile={'ports': []})
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(
            ScanResult(ip=_IP, os='Unknown', ports=[]),
            vuln_findings={'some-vuln-script': 'VULNERABLE'},
        )

        await scheduler._nmap_scan_job()

        alert = await _latest_alert('VULNERABILITY_DETECTED')
        assert alert is not None
        assert 'some-vuln-script' in alert.description

    async def test_repeated_scan_with_the_same_findings_coalesces_into_one_touched_row(self, scheduler):
        await _seed_device(nmap_profile={'ports': []})
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(
            ScanResult(ip=_IP, os='Unknown', ports=[]),
            vuln_findings={'some-vuln-script': 'VULNERABLE'},
        )

        await scheduler._nmap_scan_job()
        await scheduler._nmap_scan_job()

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.device_mac == _MAC, Alert.alert_type == 'VULNERABILITY_DETECTED')
            )
            alerts = result.scalars().all()
        assert len(alerts) == 1
        assert alerts[0].occurrence_count == 2


class TestCredentialExposure:
    async def test_credential_findings_alert(self, scheduler):
        await _seed_device(nmap_profile={'ports': []})
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(
            ScanResult(ip=_IP, os='Unknown', ports=[]),
            credential_findings={'default-accounts': 'admin:admin found on http'},
        )

        await scheduler._nmap_scan_job()

        alert = await _latest_alert('CREDENTIAL_EXPOSURE_DETECTED')
        assert alert is not None
        assert 'default-accounts' in alert.description

    async def test_no_credential_findings_no_alert(self, scheduler):
        await _seed_device(nmap_profile={'ports': []})
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(ScanResult(ip=_IP, os='Unknown', ports=[]))

        await scheduler._nmap_scan_job()

        assert await _latest_alert('CREDENTIAL_EXPOSURE_DETECTED') is None


class TestOsFingerprintConflict:
    async def test_conflicting_families_alert(self, scheduler):
        await _seed_device(nmap_profile={'ports': []}, os_fingerprint='Windows')
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(ScanResult(ip=_IP, os='Linux 5.x', ports=[]))

        await scheduler._nmap_scan_job()

        alert = await _latest_alert('OS_FINGERPRINT_CONFLICT')
        assert alert is not None
        assert 'Windows' in alert.description
        assert 'Linux 5.x' in alert.description

    async def test_agreeing_families_do_not_alert(self, scheduler):
        await _seed_device(nmap_profile={'ports': []}, os_fingerprint='Linux / Android')
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(ScanResult(ip=_IP, os='Linux 5.x', ports=[]))

        await scheduler._nmap_scan_job()

        assert await _latest_alert('OS_FINGERPRINT_CONFLICT') is None

    async def test_no_prior_passive_fingerprint_does_not_alert(self, scheduler):
        await _seed_device(nmap_profile={'ports': []}, os_fingerprint=None)
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(ScanResult(ip=_IP, os='Linux 5.x', ports=[]))

        await scheduler._nmap_scan_job()

        assert await _latest_alert('OS_FINGERPRINT_CONFLICT') is None

    async def test_unknown_active_scan_does_not_alert(self, scheduler):
        await _seed_device(nmap_profile={'ports': []}, os_fingerprint='Windows')
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(ScanResult(ip=_IP, os='Unknown', ports=[]))

        await scheduler._nmap_scan_job()

        assert await _latest_alert('OS_FINGERPRINT_CONFLICT') is None

    async def test_updates_os_fingerprint_to_the_active_result_regardless(self, scheduler):
        """The conflict is worth alerting on, but the active scan still wins
        for the stored value going forward — same behavior as before this
        change."""
        await _seed_device(nmap_profile={'ports': []}, os_fingerprint='Windows')
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._scanner = _FakeScanner(ScanResult(ip=_IP, os='Linux 5.x', ports=[]))

        await scheduler._nmap_scan_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
            assert device.os_fingerprint == 'Linux 5.x'
