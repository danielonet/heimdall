"""Tests for SentinelScheduler._stale_device_reap_job — mirrors
tests/test_scheduler/test_identity_link_job.py's object.__new__(SentinelScheduler)
pattern: this job only ever touches self._liveness_probe and the DB.
"""
import os

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.db.models import Device
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.scheduler import SentinelScheduler
from sentinel.security.liveness import LivenessProbeError

pytestmark = pytest.mark.asyncio

_MAC = 'ee:22:00:00:00:01'
_MAC_2 = 'ee:22:00:00:00:02'
_ALL_MACS = [_MAC, _MAC_2]


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Device).where(Device.mac_address.in_(_ALL_MACS)))
    await get_engine().dispose()


async def _add_device(mac: str, **overrides) -> None:
    defaults = dict(hostname='test-device', is_online=True, ip_address='10.0.0.9')
    defaults.update(overrides)
    async with get_session() as session:
        session.add(Device(mac_address=mac, **defaults))


class _FakeLivenessProbe:
    def __init__(self, reachable=False, raises_for: set[str] | None = None) -> None:
        self._reachable = reachable
        self._raises_for = raises_for or set()

    async def is_reachable(self, ip: str) -> bool:
        if ip in self._raises_for:
            raise LivenessProbeError(f'probe failed for {ip}')
        if isinstance(self._reachable, dict):
            return self._reachable.get(ip, False)
        return self._reachable


@pytest.fixture
def scheduler():
    return object.__new__(SentinelScheduler)


class TestStaleDeviceReapJob:
    async def test_marks_offline_when_unreachable(self, scheduler):
        await _add_device(_MAC, is_online=True, ip_address='10.0.0.9')
        scheduler._liveness_probe = _FakeLivenessProbe(reachable=False)

        await scheduler._stale_device_reap_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_online is False

    async def test_leaves_reachable_devices_online(self, scheduler):
        await _add_device(_MAC, is_online=True, ip_address='10.0.0.9')
        scheduler._liveness_probe = _FakeLivenessProbe(reachable=True)

        await scheduler._stale_device_reap_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_online is True

    async def test_leaves_a_device_alone_when_the_probe_fails(self, scheduler):
        await _add_device(_MAC, is_online=True, ip_address='10.0.0.9')
        scheduler._liveness_probe = _FakeLivenessProbe(raises_for={'10.0.0.9'})

        await scheduler._stale_device_reap_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_online is True

    async def test_skips_devices_with_no_ip_address(self, scheduler):
        await _add_device(_MAC, is_online=True, ip_address=None)
        scheduler._liveness_probe = _FakeLivenessProbe(reachable=False)

        await scheduler._stale_device_reap_job()  # must not raise

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_online is True  # untouched, never probed

    async def test_skips_already_offline_devices(self, scheduler):
        await _add_device(_MAC, is_online=False, ip_address='10.0.0.9')
        probe = _FakeLivenessProbe(reachable=False)
        scheduler._liveness_probe = probe

        await scheduler._stale_device_reap_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_online is False

    async def test_skips_linked_away_devices(self, scheduler):
        await _add_device(
            _MAC, is_online=True, ip_address='10.0.0.9',
            linked_to_mac=_MAC_2, linked_at=None, link_reason='x',
        )
        scheduler._liveness_probe = _FakeLivenessProbe(reachable=False)

        await scheduler._stale_device_reap_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_online is True  # untouched — its own identity is stale, not this row's job

    async def test_one_bad_device_does_not_abort_the_batch(self, scheduler):
        await _add_device(_MAC, is_online=True, ip_address='10.0.0.9')
        await _add_device(_MAC_2, is_online=True, ip_address='10.0.0.10')
        scheduler._liveness_probe = _FakeLivenessProbe(reachable={'10.0.0.9': True, '10.0.0.10': False})

        await scheduler._stale_device_reap_job()

        async with get_session() as session:
            a = await session.get(Device, _MAC)
            b = await session.get(Device, _MAC_2)
        assert a.is_online is True
        assert b.is_online is False
