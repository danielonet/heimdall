"""Focused tests for SentinelScheduler._canary_poll_job — mirrors
tests/test_scheduler/test_suricata_job.py's object.__new__(SentinelScheduler)
pattern: this job only ever touches self._canary_reader/_ingester,
self._adapter (for auto-block), and the DB.
"""
import os

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select

from sentinel.adapter.mock.mock_adapter import MockSagemcomAdapter
from sentinel.api.extensions import socketio
from sentinel.db.models import Alert, Device
from sentinel.db.repositories import SettingsRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.scheduler import SentinelScheduler
from sentinel.security.canary import OpenCanaryIngester

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:f5'
_IP = '10.100.102.52'


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
    await get_engine().dispose()


async def _seed_device(**overrides) -> None:
    async with get_session() as session:
        session.add(Device(mac_address=_MAC, ip_address=_IP, hostname='test-device', **overrides))


async def _latest_alert() -> Alert | None:
    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.device_mac == _MAC).order_by(Alert.created_at.desc())
        )
        return result.scalars().first()


class _FakeReader:
    def __init__(self, lines: list[str]) -> None:
        self._lines = lines

    def read_new_lines(self) -> list[str]:
        return self._lines


def _honeypot_line(*, src_host: str = _IP, logtype: int = 2000, service: str = 'telnet') -> str:
    return (
        '{"logtype": %d, "src_host": "%s", "dst_host": "10.100.102.1", '
        '"logdata": {"SERVICE": "%s"}}'
    ) % (logtype, src_host, service)


@pytest.fixture
def scheduler():
    """A scheduler with only the collaborators _canary_poll_job touches —
    see module docstring."""
    sched = object.__new__(SentinelScheduler)
    sched._adapter = MockSagemcomAdapter()
    sched._canary_ingester = OpenCanaryIngester()
    return sched


class TestCanaryPollJob:
    async def test_alert_is_persisted_and_attributed_by_source_ip(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._canary_reader = _FakeReader([_honeypot_line()])

        await scheduler._canary_poll_job()

        alert = await _latest_alert()
        assert alert is not None
        assert alert.alert_type == 'HONEYPOT_ACCESS'
        assert alert.device_mac == _MAC
        assert alert.severity == 'CRITICAL'
        assert alert.mitigation is not None  # see sentinel/security/remediation.py
        assert 'telnet' in alert.mitigation.lower()

    async def test_repeated_honeypot_hits_coalesce_into_one_touched_row(self, scheduler):
        """No natural "this stopped" signal for a log-line-triggered source
        — dedup is AlertRepository.upsert()'s job, not this job's."""
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._canary_reader = _FakeReader([_honeypot_line(), _honeypot_line()])

        await scheduler._canary_poll_job()

        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            alerts = result.scalars().all()
        assert len(alerts) == 1
        assert alerts[0].occurrence_count == 2

    async def test_auto_block_armed_blocks_the_source_device(self, scheduler):
        """A honeypot hit is inherently malicious — it must auto-block exactly
        like ARP-spoof/Suricata/Zeek findings do, not just get logged."""
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        scheduler._canary_reader = _FakeReader([_honeypot_line()])

        await scheduler._canary_poll_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_blocked is True
        alert = await _latest_alert()
        assert 'auto-blocked' in alert.description

    async def test_auto_block_disarmed_does_not_block(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._canary_reader = _FakeReader([_honeypot_line()])

        await scheduler._canary_poll_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_blocked is False

    async def test_unattributed_source_host_still_persists_the_alert(self, scheduler):
        """No matching device row for src_host — the alert must still be
        recorded, just with device_mac=None (mirrors Suricata/Zeek's
        _mac_for_ip behavior when the lookup misses)."""
        await SettingsRepository().set_auto_block_on_threat(False)
        scheduler._canary_reader = _FakeReader([_honeypot_line(src_host='10.100.102.250')])

        await scheduler._canary_poll_job()

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.alert_type == 'HONEYPOT_ACCESS').order_by(Alert.created_at.desc())
            )
            alert = result.scalars().first()
        assert alert is not None
        assert alert.device_mac is None
        async with get_session() as session:
            await session.execute(delete(Alert).where(Alert.id == alert.id))

    async def test_non_interaction_logtypes_are_skipped(self, scheduler):
        """logtype outside _INTERACTION_LOGTYPES (e.g. startup/ping housekeeping)."""
        scheduler._canary_reader = _FakeReader([_honeypot_line(logtype=1)])

        await scheduler._canary_poll_job()  # must not raise

        assert await _latest_alert() is None

    async def test_malformed_lines_are_skipped(self, scheduler):
        scheduler._canary_reader = _FakeReader(['not json {{{'])

        await scheduler._canary_poll_job()  # must not raise

        assert await _latest_alert() is None

    async def test_updates_last_check_timestamp_even_with_no_lines(self, scheduler):
        scheduler._canary_reader = _FakeReader([])
        assert scheduler.__dict__.get('_last_canary_check_at') is None

        await scheduler._canary_poll_job()

        assert scheduler._last_canary_check_at is not None
