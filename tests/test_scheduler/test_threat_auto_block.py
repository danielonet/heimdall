"""Focused tests for SentinelScheduler._raise_threat_alert and its three
callers — the auto-block wiring behind the auto_block_on_threat setting.

Exercises the scheduler methods directly against object.__new__(SentinelScheduler)
rather than driving a full background scheduler thread: _raise_threat_alert
and its callers only ever touch self._adapter and the DB (never self._loop or
any of the other constructor-wired state), so __init__'s many unrelated
kwargs (poll interval, ML config, cron strings, ...) would just be noise here.
"""
import os
from datetime import datetime, timedelta, timezone

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

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'
_IP = '10.0.0.50'


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
        # test_alert_with_no_mac_is_never_blocked deliberately raises an
        # alert with device_mac=None (no device to attribute it to) — clean
        # that up too, or it leaks into the shared sentinel_test DB forever
        # and trips other tests (e.g. test_api/test_alerts.py's
        # empty-list assertion) whenever they happen to run afterward.
        await session.execute(delete(Alert).where(Alert.device_mac.is_(None)))
        await session.execute(delete(Device).where(Device.mac_address == _MAC))
    await get_engine().dispose()


@pytest.fixture
def scheduler():
    """A scheduler with only self._adapter populated — see module docstring."""
    sched = object.__new__(SentinelScheduler)
    sched._adapter = MockSagemcomAdapter()
    return sched


async def _seed_device(**overrides) -> None:
    async with get_session() as session:
        session.add(Device(mac_address=_MAC, ip_address=_IP, hostname='test-device', **overrides))


async def _get_device() -> Device | None:
    async with get_session() as session:
        return await session.get(Device, _MAC)


async def _latest_alert() -> Alert | None:
    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.device_mac == _MAC).order_by(Alert.created_at.desc())
        )
        return result.scalars().first()


class TestRaiseThreatAlert:
    async def test_blocks_and_annotates_the_alert_when_armed(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)

        await scheduler._raise_threat_alert(_MAC, 'ARP_SPOOF', 'CRITICAL', 'spoofing suspected')

        device = await _get_device()
        assert device.is_blocked is True
        alert = await _latest_alert()
        assert alert.alert_type == 'ARP_SPOOF'
        assert 'auto-blocked' in alert.description

    async def test_does_not_block_when_disarmed(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(False)

        await scheduler._raise_threat_alert(_MAC, 'ARP_SPOOF', 'CRITICAL', 'spoofing suspected')

        device = await _get_device()
        assert device.is_blocked is False
        alert = await _latest_alert()
        assert 'auto-blocked' not in alert.description

    async def test_still_reblocks_a_device_already_marked_blocked_in_the_db(self, scheduler, monkeypatch):
        """Regression: an earlier version skipped re-blocking whenever
        device.is_blocked was already True in the DB. That flag is only a
        cache of the last known outcome — it went stale in production (an
        earlier attempt's is_blocked=True outlived the actual router state)
        and a real, live ARP-spoof attacker was never re-blocked as a result.
        block_device() is idempotent, so there's no reason to ever skip it."""
        await _seed_device(is_blocked=True)
        await SettingsRepository().set_auto_block_on_threat(True)
        calls = []

        async def _fake_block_device(mac):
            calls.append(mac)
            return True

        monkeypatch.setattr(scheduler._adapter, 'block_device', _fake_block_device)

        await scheduler._raise_threat_alert(_MAC, 'ARP_SPOOF', 'CRITICAL', 'spoofing suspected')

        assert calls == [_MAC]

    async def test_surfaces_a_failed_block_instead_of_claiming_success(self, scheduler, monkeypatch):
        """Regression: adapter.block_device() used to unconditionally return
        True even when the router never confirmed the rule (missing UID),
        so the alert claimed "auto-blocked" while the device stayed on the
        network. block_device() now returns False in that case, and this
        must surface as a visible failure, never a silent no-op."""
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)

        async def _fake_block_device(mac):
            return False  # router didn't confirm the rule

        monkeypatch.setattr(scheduler._adapter, 'block_device', _fake_block_device)

        await scheduler._raise_threat_alert(_MAC, 'ARP_SPOOF', 'CRITICAL', 'spoofing suspected')

        device = await _get_device()
        assert device.is_blocked is False
        alert = await _latest_alert()
        assert 'AUTO-BLOCK FAILED' in alert.description
        assert 'auto-blocked' not in alert.description

    async def test_alert_with_no_mac_is_never_blocked(self, scheduler):
        await SettingsRepository().set_auto_block_on_threat(True)
        await scheduler._raise_threat_alert(None, 'ARP_SPOOF', 'CRITICAL', 'spoofing suspected, no known MAC')
        # Must not raise — the assertion here is simply that this completes.


class TestRaiseThreatAlertBlockExpiry:
    """blocked_at/blocked_until — see _raise_threat_alert's docstring for
    why these must be (re-)stamped on every successful auto-block, not just
    the first one."""

    async def test_sets_blocked_at_and_blocked_until_on_auto_block(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        await SettingsRepository().set_auto_block_expiry_hours(24)

        before = datetime.now(timezone.utc)
        await scheduler._raise_threat_alert(_MAC, 'ARP_SPOOF', 'CRITICAL', 'spoofing suspected')
        after = datetime.now(timezone.utc)

        device = await _get_device()
        assert before <= device.blocked_at <= after
        assert abs((device.blocked_until - device.blocked_at) - timedelta(hours=24)) < timedelta(seconds=5)

    async def test_expiry_hours_zero_means_no_expiry(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        await SettingsRepository().set_auto_block_expiry_hours(0)

        await scheduler._raise_threat_alert(_MAC, 'ARP_SPOOF', 'CRITICAL', 'spoofing suspected')

        device = await _get_device()
        assert device.blocked_at is not None
        assert device.blocked_until is None

    async def test_reblock_refreshes_the_expiry_timer(self, scheduler):
        """The race flagged in docs/section-b.../section-d plan: a fresh
        threat must always reset the clock, or the expiry job could unblock
        a device moments after a legitimate re-block for a NEW reason."""
        await _seed_device(is_blocked=True)
        await SettingsRepository().set_auto_block_on_threat(True)
        await SettingsRepository().set_auto_block_expiry_hours(24)

        stale_time = datetime.now(timezone.utc) - timedelta(hours=23)
        async with get_session() as session:
            device = await session.get(Device, _MAC)
            device.blocked_at = stale_time
            device.blocked_until = stale_time + timedelta(hours=1)  # due in ~1h

        await scheduler._raise_threat_alert(_MAC, 'ARP_SPOOF', 'CRITICAL', 'spoofing suspected again')

        device = await _get_device()
        assert device.blocked_at > stale_time
        assert device.blocked_until > stale_time + timedelta(hours=1)

    async def test_failed_block_does_not_set_expiry_fields(self, scheduler, monkeypatch):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)

        async def _fake_block_device(mac):
            return False

        monkeypatch.setattr(scheduler._adapter, 'block_device', _fake_block_device)
        await scheduler._raise_threat_alert(_MAC, 'ARP_SPOOF', 'CRITICAL', 'spoofing suspected')

        device = await _get_device()
        assert device.blocked_at is None
        assert device.blocked_until is None


class TestPersistArpAlert:
    async def test_arp_spoof_attributes_the_alert_to_the_new_mac_and_blocks_it(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)

        await scheduler._persist_arp_alert({
            'type': 'ARP_SPOOF', 'severity': 'CRITICAL', 'ip': _IP,
            'old_mac': 'de:ad:be:ef:00:01', 'new_mac': _MAC,
            'description': f'ARP spoofing suspected: {_IP} changed',
        })

        alert = await _latest_alert()
        assert alert.device_mac == _MAC
        device = await _get_device()
        assert device.is_blocked is True


class TestPersistDhcpAlert:
    async def test_rogue_dhcp_offer_attributes_the_alert_to_the_servers_mac_and_blocks_it(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)

        await scheduler._persist_dhcp_alert({
            'type': 'ROGUE_DHCP_SERVER', 'severity': 'CRITICAL', 'ip': _IP, 'mac': _MAC,
            'description': f'DHCP OFFER received from {_IP} ({_MAC}), not the known router',
        })

        alert = await _latest_alert()
        assert alert.device_mac == _MAC
        assert alert.alert_type == 'ROGUE_DHCP_SERVER'
        device = await _get_device()
        assert device.is_blocked is True

    async def test_alert_with_no_mac_is_never_blocked(self, scheduler):
        await SettingsRepository().set_auto_block_on_threat(True)
        await scheduler._persist_dhcp_alert({
            'type': 'ROGUE_DHCP_SERVER', 'severity': 'CRITICAL', 'ip': '10.100.102.66', 'mac': None,
            'description': 'DHCP OFFER received from 10.100.102.66 (unknown MAC), not the known router',
        })
        # Must not raise — the assertion here is simply that this completes.


class TestPersistFingerprint:
    async def test_signature_change_on_a_known_device_is_flagged_and_blocked(self, scheduler):
        await _seed_device(is_blocked=False, os_fingerprint='Linux / Android')
        await SettingsRepository().set_auto_block_on_threat(True)

        await scheduler._persist_fingerprint(_IP, 'Windows')

        device = await _get_device()
        assert device.os_fingerprint == 'Windows'
        assert device.is_blocked is True
        alert = await _latest_alert()
        assert alert.alert_type == 'FINGERPRINT_MISMATCH'

    async def test_first_ever_fingerprint_is_not_treated_as_a_mismatch(self, scheduler):
        await _seed_device(is_blocked=False, os_fingerprint=None)
        await SettingsRepository().set_auto_block_on_threat(True)

        await scheduler._persist_fingerprint(_IP, 'Windows')

        device = await _get_device()
        assert device.os_fingerprint == 'Windows'
        assert device.is_blocked is False
        assert await _latest_alert() is None

    async def test_unknown_guess_is_not_treated_as_a_mismatch(self, scheduler):
        await _seed_device(is_blocked=False, os_fingerprint='Linux / Android')
        await SettingsRepository().set_auto_block_on_threat(True)

        await scheduler._persist_fingerprint(_IP, 'Unknown')

        device = await _get_device()
        assert device.is_blocked is False
        assert await _latest_alert() is None
