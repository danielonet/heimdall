"""Tests for SentinelScheduler._identity_link_job — mirrors
tests/test_scheduler/test_alert_auto_resolve_job.py's
object.__new__(SentinelScheduler) pattern: this job only ever touches
self._identity_linker, self._liveness_probe, and the DB.
"""
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select

from sentinel.api.extensions import socketio
from sentinel.db.models import Alert, Device
from sentinel.db.repositories import SettingsRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.device_identity import DeviceIdentityLinker
from sentinel.scheduler.scheduler import SentinelScheduler
from sentinel.security.liveness import LivenessProbeError

pytestmark = pytest.mark.asyncio

# Distinctive, obviously-synthetic MACs — this suite runs against the
# shared dev DB, which has genuine device rows in it (see
# test_device_identity.py's note on the same issue).
_MAC_A = 'ee:11:00:00:00:01'
_MAC_B = 'ee:11:00:00:00:02'
_MAC_C = 'ee:11:00:00:00:03'
_ALL_MACS = [_MAC_A, _MAC_B, _MAC_C]
_NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True, scope='module')
def _init_socketio_once():
    """_identity_link_job broadcasts DEVICE_IDENTITY_LINKED over the socket."""
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
        await session.execute(delete(Device).where(Device.mac_address.in_(_ALL_MACS)))
        await session.execute(delete(Alert).where(Alert.device_mac.in_(_ALL_MACS)))
    await get_engine().dispose()


async def _add_device(mac: str, hostname: str, **overrides) -> None:
    defaults = dict(is_online=False, first_seen=_NOW, last_seen=_NOW, ip_address='10.0.0.9')
    defaults.update(overrides)
    async with get_session() as session:
        session.add(Device(mac_address=mac, hostname=hostname, **defaults))


class _FakeLivenessProbe:
    """reachable: dict mapping ip -> bool, or a plain bool for every ip.
    raises_for: set of ips that raise LivenessProbeError instead.
    resolved_macs: dict mapping ip -> the MAC resolve_mac should report as
    currently answering there, for the IP-continuity fallback path."""

    def __init__(
        self, reachable=False, raises_for: set[str] | None = None, resolved_macs: dict[str, str] | None = None,
    ) -> None:
        self._reachable = reachable
        self._raises_for = raises_for or set()
        self._resolved_macs = resolved_macs or {}

    async def is_reachable(self, ip: str) -> bool:
        if ip in self._raises_for:
            raise LivenessProbeError(f'probe failed for {ip}')
        if isinstance(self._reachable, dict):
            return self._reachable.get(ip, False)
        return self._reachable

    async def resolve_mac(self, ip: str) -> str | None:
        if ip in self._raises_for:
            raise LivenessProbeError(f'probe failed for {ip}')
        return self._resolved_macs.get(ip)


@pytest.fixture
def scheduler():
    sched = object.__new__(SentinelScheduler)
    sched._identity_linker = DeviceIdentityLinker()
    return sched


async def _open_alert(mac: str) -> Alert | None:
    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.device_mac == mac, Alert.alert_type == 'DEVICE_IDENTITY_LINKED')
        )
        return result.scalars().first()


class TestIdentityLinkJob:
    async def test_links_the_unreachable_member_to_the_sole_reachable_one(self, scheduler):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9')
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10')
        scheduler._liveness_probe = _FakeLivenessProbe(reachable={'10.0.0.9': False, '10.0.0.10': True})

        await scheduler._identity_link_job()

        async with get_session() as session:
            a = await session.get(Device, _MAC_A)
        assert a.linked_to_mac == _MAC_B
        alert = await _open_alert(_MAC_B)
        assert alert is not None
        assert alert.severity == 'INFO'
        assert alert.raw_data['old_mac'] == _MAC_A
        assert alert.raw_data['new_mac'] == _MAC_B

    async def test_a_successful_link_resolves_the_old_macs_open_new_device_alert(self, scheduler):
        """Regression: NewDeviceDetector fires a CRITICAL NEW_DEVICE alert
        within one poll of any first-seen MAC, including a phone's own
        address rotating under WiFi MAC randomization, with zero awareness
        of identity-linking. Confirmed in production: that alert stayed
        open indefinitely even after the exact same phone was later
        successfully linked here. A successful link must resolve it."""
        from sentinel.db.repositories import AlertRepository

        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9')
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10')
        await AlertRepository().upsert(
            device_mac=_MAC_A, alert_type='NEW_DEVICE', severity='CRITICAL',
            description='New device joined the network: phone (10.0.0.9)',
        )
        scheduler._liveness_probe = _FakeLivenessProbe(reachable={'10.0.0.9': False, '10.0.0.10': True})

        await scheduler._identity_link_job()

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.device_mac == _MAC_A, Alert.alert_type == 'NEW_DEVICE')
            )
            new_device_alert = result.scalars().first()
        assert new_device_alert.resolved is True

    async def test_does_nothing_when_all_members_are_reachable(self, scheduler):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9')
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10')
        scheduler._liveness_probe = _FakeLivenessProbe(reachable=True)

        await scheduler._identity_link_job()

        async with get_session() as session:
            a = await session.get(Device, _MAC_A)
            b = await session.get(Device, _MAC_B)
        assert a.linked_to_mac is None
        assert b.linked_to_mac is None

    async def test_does_nothing_when_no_members_are_reachable(self, scheduler):
        """The phone is currently fully offline — too soon to guess which
        MAC it'll come back as."""
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9')
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10')
        scheduler._liveness_probe = _FakeLivenessProbe(reachable=False)

        await scheduler._identity_link_job()

        async with get_session() as session:
            a = await session.get(Device, _MAC_A)
            b = await session.get(Device, _MAC_B)
        assert a.linked_to_mac is None
        assert b.linked_to_mac is None

    async def test_links_multiple_unreachable_members_onto_the_one_survivor(self, scheduler):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9')
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10')
        await _add_device(_MAC_C, 'phone', ip_address='10.0.0.11')
        scheduler._liveness_probe = _FakeLivenessProbe(
            reachable={'10.0.0.9': False, '10.0.0.10': False, '10.0.0.11': True},
        )

        await scheduler._identity_link_job()

        async with get_session() as session:
            a = await session.get(Device, _MAC_A)
            b = await session.get(Device, _MAC_B)
        assert a.linked_to_mac == _MAC_C
        assert b.linked_to_mac == _MAC_C

    async def test_a_failed_probe_excludes_that_member_without_aborting_the_group(self, scheduler):
        """A LivenessProbeError (couldn't confirm) must never be treated as
        confirmed-dead or confirmed-alive — the member is simply left out
        of both lists for this scan."""
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9')
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10')
        scheduler._liveness_probe = _FakeLivenessProbe(
            reachable={'10.0.0.10': True}, raises_for={'10.0.0.9'},
        )

        await scheduler._identity_link_job()  # must not raise

        async with get_session() as session:
            a = await session.get(Device, _MAC_A)
        assert a.linked_to_mac is None  # excluded from "unreachable", so never linked

    async def test_no_groups_does_not_raise(self, scheduler):
        scheduler._liveness_probe = _FakeLivenessProbe(reachable=False)
        await scheduler._identity_link_job()  # must not raise


class TestBlockPropagationOnLink:
    """Confirmed real bypass, not theoretical: block_device() blacklists
    old_mac's own Host entry — new_mac gets a fresh, unblocked one the
    moment it appears, and DeviceRepository.link() only ever touches
    linked_to_mac/linked_at/link_reason. Without this, blocking a device
    and then having its MAC rotate (which _identity_link_job exists to
    recognize) would silently un-block it in every way that matters."""

    async def test_blocked_old_mac_propagates_the_block_to_the_new_mac(self, scheduler):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9', is_blocked=True)
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10', is_blocked=False)
        scheduler._liveness_probe = _FakeLivenessProbe(reachable={'10.0.0.9': False, '10.0.0.10': True})
        scheduler._adapter = AsyncMock()
        scheduler._adapter.block_device = AsyncMock(return_value=True)
        await SettingsRepository().set_auto_block_expiry_hours(0)

        await scheduler._identity_link_job()

        scheduler._adapter.block_device.assert_awaited_once_with(_MAC_B)
        async with get_session() as session:
            b = await session.get(Device, _MAC_B)
        assert b.is_blocked is True
        alert = await _open_alert(_MAC_B)
        assert f'block propagated to {_MAC_B}' in alert.description

    async def test_propagation_failure_is_never_silently_claimed_as_success(self, scheduler):
        """Same 'AUTO-BLOCK FAILED' convention as _raise_threat_alert — a
        linked device that's actually still unprotected must not read as
        if nothing needs attention."""
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9', is_blocked=True)
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10', is_blocked=False)
        scheduler._liveness_probe = _FakeLivenessProbe(reachable={'10.0.0.9': False, '10.0.0.10': True})
        scheduler._adapter = AsyncMock()
        scheduler._adapter.block_device = AsyncMock(return_value=False)  # router didn't confirm

        await scheduler._identity_link_job()

        async with get_session() as session:
            b = await session.get(Device, _MAC_B)
        assert b.is_blocked is False  # never claim success it can't back up
        alert = await _open_alert(_MAC_B)
        assert 'AUTO-BLOCK PROPAGATION' in alert.description
        assert 'FAILED' in alert.description

    async def test_disable_auto_block_dev_override_skips_propagation(self, scheduler, monkeypatch):
        from sentinel.config import settings
        monkeypatch.setattr(settings, 'DISABLE_AUTO_BLOCK', True)
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9', is_blocked=True)
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10', is_blocked=False)
        scheduler._liveness_probe = _FakeLivenessProbe(reachable={'10.0.0.9': False, '10.0.0.10': True})
        scheduler._adapter = AsyncMock()
        scheduler._adapter.block_device = AsyncMock(return_value=True)

        await scheduler._identity_link_job()

        scheduler._adapter.block_device.assert_not_awaited()
        async with get_session() as session:
            b = await session.get(Device, _MAC_B)
        assert b.is_blocked is False
        alert = await _open_alert(_MAC_B)
        assert 'AUTO-BLOCK DISABLED' in alert.description

    async def test_unblocked_old_mac_does_not_touch_the_adapter_at_all(self, scheduler):
        """The common case — most links have nothing to propagate."""
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9', is_blocked=False)
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10', is_blocked=False)
        scheduler._liveness_probe = _FakeLivenessProbe(reachable={'10.0.0.9': False, '10.0.0.10': True})
        scheduler._adapter = AsyncMock()
        scheduler._adapter.block_device = AsyncMock(return_value=True)

        await scheduler._identity_link_job()

        scheduler._adapter.block_device.assert_not_awaited()
        alert = await _open_alert(_MAC_B)
        assert 'propagat' not in alert.description.lower()


class TestIpContinuityLink:
    """The fallback path for a rotated MAC that never reported a hostname —
    see _identity_link_job's docstring for the live incident this closes."""

    async def test_links_when_arp_confirms_the_new_mac_holds_the_ip(self, scheduler):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.18', is_online=False)
        await _add_device(_MAC_B, '', ip_address='10.0.0.18', is_online=True)
        scheduler._liveness_probe = _FakeLivenessProbe(resolved_macs={'10.0.0.18': _MAC_B})

        await scheduler._identity_link_job()

        async with get_session() as session:
            a = await session.get(Device, _MAC_A)
        assert a.linked_to_mac == _MAC_B
        alert = await _open_alert(_MAC_B)
        assert alert is not None
        assert alert.raw_data['match'] == 'ip_continuity'

    async def test_does_not_link_when_arp_resolves_a_different_mac(self, scheduler):
        """Something else is answering at that IP right now — not (yet)
        confirmed as new_mac, so no link."""
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.18', is_online=False)
        await _add_device(_MAC_B, '', ip_address='10.0.0.18', is_online=True)
        scheduler._liveness_probe = _FakeLivenessProbe(resolved_macs={'10.0.0.18': 'ee:11:00:00:00:99'})

        await scheduler._identity_link_job()

        async with get_session() as session:
            a = await session.get(Device, _MAC_A)
        assert a.linked_to_mac is None

    async def test_does_not_link_when_nothing_answers(self, scheduler):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.18', is_online=False)
        await _add_device(_MAC_B, '', ip_address='10.0.0.18', is_online=True)
        scheduler._liveness_probe = _FakeLivenessProbe(resolved_macs={})  # nothing resolves

        await scheduler._identity_link_job()

        async with get_session() as session:
            a = await session.get(Device, _MAC_A)
        assert a.linked_to_mac is None

    async def test_probe_failure_excludes_the_candidate_without_aborting(self, scheduler):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.18', is_online=False)
        await _add_device(_MAC_B, '', ip_address='10.0.0.18', is_online=True)
        scheduler._liveness_probe = _FakeLivenessProbe(raises_for={'10.0.0.18'})

        await scheduler._identity_link_job()  # must not raise

        async with get_session() as session:
            a = await session.get(Device, _MAC_A)
        assert a.linked_to_mac is None

    async def test_resolves_the_new_macs_open_arp_spoof_alert(self, scheduler):
        """The exact case this fallback exists for: the rotation already
        tripped ARP_SPOOF (DHCP verification couldn't confirm it in time),
        and identity-linking explaining it after the fact should close
        that alert instead of leaving it open forever."""
        from sentinel.db.repositories import AlertRepository
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.18', is_online=False)
        await _add_device(_MAC_B, '', ip_address='10.0.0.18', is_online=True)
        await AlertRepository().upsert(
            device_mac=_MAC_B, alert_type='ARP_SPOOF', severity='CRITICAL',
            description='ARP spoofing suspected: 10.0.0.18 changed',
        )
        scheduler._liveness_probe = _FakeLivenessProbe(resolved_macs={'10.0.0.18': _MAC_B})

        await scheduler._identity_link_job()

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.device_mac == _MAC_B, Alert.alert_type == 'ARP_SPOOF')
            )
            arp_spoof_alert = result.scalars().first()
        assert arp_spoof_alert.resolved is True
