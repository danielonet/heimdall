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
from unittest.mock import AsyncMock, Mock

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select

from sentinel.adapter.mock.mock_adapter import MockSagemcomAdapter
from sentinel.adapter.models import DhcpLease
from sentinel.api.extensions import socketio
from sentinel.db.models import Alert, Device, TrustedMac
from sentinel.db.repositories import SettingsRepository, TrustedMacRepository
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
        await session.execute(delete(TrustedMac).where(TrustedMac.mac_address == _MAC))
    await get_engine().dispose()


@pytest.fixture
def scheduler():
    """A scheduler with only self._adapter populated — see module docstring.

    _arp_verify_max_attempts=1 / _arp_verify_retry_interval_s=0: every
    TestPersistArpAlert case below is testing what happens once ARP-DHCP
    verification comes back unresolved (MockSagemcomAdapter's synthetic
    leases never match these tests' MACs/IPs, so it always does) — none of
    them need or want to sit through the real ~45s retry budget
    (_verify_arp_change_against_dhcp) to get there.
    """
    sched = object.__new__(SentinelScheduler)
    sched._adapter = MockSagemcomAdapter()
    sched._ip_conflict_quiet_until = {}
    sched._arp_verify_max_attempts = 1
    sched._arp_verify_retry_interval_s = 0
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

    async def test_repeated_event_coalesces_into_one_touched_row(self, scheduler):
        """No resolve() call for this source (no natural "this stopped"
        signal) — but a still-recurring attack signal must still touch the
        same open row via AlertRepository.upsert(), not flood inserts."""
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)

        await scheduler._raise_threat_alert(_MAC, 'ARP_SPOOF', 'CRITICAL', 'spoofing suspected')
        await scheduler._raise_threat_alert(_MAC, 'ARP_SPOOF', 'CRITICAL', 'spoofing suspected again')

        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            alerts = result.scalars().all()
        assert len(alerts) == 1
        assert alerts[0].occurrence_count == 2
        assert 'again' in alerts[0].description

    async def test_dedup_key_keeps_distinct_findings_on_the_same_device_separate(self, scheduler):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)

        await scheduler._raise_threat_alert(
            _MAC, 'HIGH_RISK_PORT_OPENED', 'CRITICAL', 'port 22 opened', dedup_key='port:22',
        )
        await scheduler._raise_threat_alert(
            _MAC, 'HIGH_RISK_PORT_OPENED', 'CRITICAL', 'port 3389 opened', dedup_key='port:3389',
        )

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.device_mac == _MAC, Alert.alert_type == 'HIGH_RISK_PORT_OPENED')
            )
            alerts = result.scalars().all()
        assert len(alerts) == 2


class TestSelfHostSafeguard:
    """Regression coverage for the incident this safeguard exists to
    prevent: ZeekConnBeaconDetector misread Heimdall's own nmap scan as C2
    beaconing and auto-blocked the machine Heimdall itself runs on, cutting
    it off its own network. _raise_threat_alert must never block a MAC that
    resolves to one of the scheduler's own self._local_ips (see
    discover_local_ips() / SentinelScheduler._is_own_host)."""

    async def test_never_blocks_when_the_mac_resolves_to_a_local_ip(self, scheduler, monkeypatch):
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        scheduler._local_ips = {_IP}
        calls = []

        async def _fake_block_device(mac):
            calls.append(mac)
            return True

        monkeypatch.setattr(scheduler._adapter, 'block_device', _fake_block_device)

        await scheduler._raise_threat_alert(_MAC, 'C2_BEACONING', 'CRITICAL', 'beaconing suspected')

        assert calls == []  # block_device() must never even be called
        device = await _get_device()
        assert device.is_blocked is False
        alert = await _latest_alert()
        assert 'auto-block suppressed' in alert.description
        assert 'Heimdall host itself' in alert.description
        assert 'auto-blocked' not in alert.description

    async def test_still_raises_the_alert_itself_even_when_suppressed(self, scheduler):
        """The finding is still worth a human's attention — only the block
        is suppressed, not the alert."""
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        scheduler._local_ips = {_IP}

        await scheduler._raise_threat_alert(_MAC, 'C2_BEACONING', 'CRITICAL', 'beaconing suspected')

        alert = await _latest_alert()
        assert alert is not None
        assert alert.alert_type == 'C2_BEACONING'

    async def test_a_different_devices_mac_is_still_blocked_normally(self, scheduler, monkeypatch):
        """The safeguard must be scoped to the matching IP only — it must
        not accidentally disable auto-block globally just because
        self._local_ips is non-empty."""
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        scheduler._local_ips = {'10.0.0.99'}  # does not match _seed_device's _IP

        await scheduler._raise_threat_alert(_MAC, 'C2_BEACONING', 'CRITICAL', 'beaconing suspected')

        device = await _get_device()
        assert device.is_blocked is True
        alert = await _latest_alert()
        assert 'auto-blocked' in alert.description

    async def test_empty_local_ips_never_suppresses_a_block(self, scheduler):
        """Default scheduler fixture state (self._local_ips unset/empty,
        e.g. discover_local_ips() failed at startup) must behave exactly
        like today — never silently disable auto-block network-wide."""
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)

        await scheduler._raise_threat_alert(_MAC, 'C2_BEACONING', 'CRITICAL', 'beaconing suspected')

        device = await _get_device()
        assert device.is_blocked is True

    async def test_unknown_mac_is_not_treated_as_self(self, scheduler, monkeypatch):
        """A MAC with no matching device row (no IP to compare) must not be
        mistaken for the host itself just because local_ips is populated —
        uses _MAC without seeding a Device row, so is_self resolves to
        False (no device -> no ip_address to compare)."""
        await SettingsRepository().set_auto_block_on_threat(True)
        scheduler._local_ips = {_IP}
        calls = []

        async def _fake_block_device(mac):
            calls.append(mac)
            return True

        monkeypatch.setattr(scheduler._adapter, 'block_device', _fake_block_device)

        await scheduler._raise_threat_alert(_MAC, 'C2_BEACONING', 'CRITICAL', 'beaconing suspected')

        assert calls == [_MAC]  # not suppressed — block_device() was called normally


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

    async def test_dhcp_confirmed_reassignment_is_never_blocked_and_raises_no_alert(self, scheduler):
        """The adaptive-cadence fix: an untrusted MAC change that the
        router's own live DHCP leases confirm is a legitimate reassignment
        must not be treated as spoofing at all — no ARP_SPOOF, no block,
        not even the softer IP_CONFLICT (unlike the trusted-MAC path below,
        this MAC was never trusted; DHCP itself is the authority here, not
        Heimdall's trust registry). ArpWatcher's table gets corrected
        instead, so a repeat of the same, now-known-good pairing doesn't
        re-trigger this at all next time."""
        await _seed_device(is_blocked=False)
        await SettingsRepository().set_auto_block_on_threat(True)
        scheduler._adapter.get_dhcp_leases = AsyncMock(
            return_value=[DhcpLease(mac_address=_MAC, ip_address=_IP, hostname='confirmed-by-dhcp')]
        )
        scheduler._arp_watcher = Mock()

        await scheduler._persist_arp_alert({
            'type': 'ARP_SPOOF', 'severity': 'CRITICAL', 'ip': _IP,
            'old_mac': 'de:ad:be:ef:00:01', 'new_mac': _MAC,
            'description': f'ARP spoofing suspected: {_IP} changed',
        })

        device = await _get_device()
        assert device.is_blocked is False
        assert await _latest_alert() is None
        scheduler._arp_watcher.seed.assert_called_once_with([(_IP, _MAC)])

    async def test_trusted_new_mac_is_never_blocked_and_downgrades_to_ip_conflict_info(self, scheduler):
        """Regression coverage for a real incident: ArpWatcher can't tell an
        attacker impersonating a known IP apart from two of the user's own
        devices both configured with the same static IP — it only sees a
        MAC change. If the device now holding the IP is already trusted,
        that's the benign case: never auto-block it, and raise a single
        INFO-severity IP_CONFLICT alert instead of a CRITICAL ARP_SPOOF one."""
        await _seed_device(is_blocked=False)
        await TrustedMacRepository().trust(_MAC)
        await SettingsRepository().set_auto_block_on_threat(True)

        await scheduler._persist_arp_alert({
            'type': 'ARP_SPOOF', 'severity': 'CRITICAL', 'ip': _IP,
            'old_mac': 'de:ad:be:ef:00:01', 'new_mac': _MAC,
            'description': f'ARP spoofing suspected: {_IP} changed',
        })

        device = await _get_device()
        assert device.is_blocked is False
        alert = await _latest_alert()
        assert alert.alert_type == 'IP_CONFLICT'
        assert alert.severity == 'INFO'
        assert alert.device_mac == _MAC
        assert _IP in alert.description

    async def test_repeated_conflict_on_the_same_ip_is_suppressed(self, scheduler):
        """Must not flood the Alerts tab while the same IP keeps flapping
        between two known devices — only the first occurrence is recorded
        until IP_CONFLICT_QUIET_MINUTES passes."""
        await _seed_device(is_blocked=False)
        await TrustedMacRepository().trust(_MAC)

        event = {
            'type': 'ARP_SPOOF', 'severity': 'CRITICAL', 'ip': _IP,
            'old_mac': 'de:ad:be:ef:00:01', 'new_mac': _MAC,
            'description': f'ARP spoofing suspected: {_IP} changed',
        }
        await scheduler._persist_arp_alert(event)
        first_alert = await _latest_alert()

        await scheduler._persist_arp_alert(event)
        await scheduler._persist_arp_alert(event)

        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.alert_type == 'IP_CONFLICT'))
            conflict_alerts = result.scalars().all()
        assert len(conflict_alerts) == 1
        assert conflict_alerts[0].id == first_alert.id

    async def test_conflict_quiet_window_is_keyed_by_ip_not_by_device(self, scheduler):
        """A different IP conflicting for the same trusted device must still
        alert — the quiet window tracks 'have I already reported this IP',
        not 'have I already reported this device'."""
        await _seed_device(is_blocked=False)
        await TrustedMacRepository().trust(_MAC)

        await scheduler._persist_arp_alert({
            'type': 'ARP_SPOOF', 'severity': 'CRITICAL', 'ip': _IP,
            'old_mac': 'de:ad:be:ef:00:01', 'new_mac': _MAC,
            'description': f'ARP spoofing suspected: {_IP} changed',
        })
        await scheduler._persist_arp_alert({
            'type': 'ARP_SPOOF', 'severity': 'CRITICAL', 'ip': '10.0.0.99',
            'old_mac': 'de:ad:be:ef:00:02', 'new_mac': _MAC,
            'description': 'ARP spoofing suspected: 10.0.0.99 changed',
        })

        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.alert_type == 'IP_CONFLICT'))
            conflict_alerts = result.scalars().all()
        assert len(conflict_alerts) == 2

    async def test_untrusted_new_mac_on_a_previously_conflicted_ip_still_gets_full_treatment(self, scheduler):
        """The quiet window only ever suppresses the trusted-device path —
        an actually-untrusted MAC taking over that same IP later must still
        raise a full CRITICAL ARP_SPOOF and attempt to block, regardless of
        the IP's conflict history."""
        await _seed_device(is_blocked=False)
        await TrustedMacRepository().trust(_MAC)
        await SettingsRepository().set_auto_block_on_threat(True)

        await scheduler._persist_arp_alert({
            'type': 'ARP_SPOOF', 'severity': 'CRITICAL', 'ip': _IP,
            'old_mac': 'de:ad:be:ef:00:01', 'new_mac': _MAC,
            'description': f'ARP spoofing suspected: {_IP} changed',
        })

        other_mac = '11:22:33:44:55:66'
        await scheduler._persist_arp_alert({
            'type': 'ARP_SPOOF', 'severity': 'CRITICAL', 'ip': _IP,
            'old_mac': _MAC, 'new_mac': other_mac,
            'description': f'ARP spoofing suspected: {_IP} changed',
        })

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.device_mac == other_mac).order_by(Alert.created_at.desc())
            )
            alert = result.scalars().first()
            await session.execute(delete(Alert).where(Alert.device_mac == other_mac))
        assert alert is not None
        assert alert.alert_type == 'ARP_SPOOF'
        # MockSagemcomAdapter.block_device() unconditionally succeeds even
        # with no matching Device row — the point here is just that the
        # full CRITICAL/auto-block path ran at all, not the mock's own
        # block-target-lookup behavior (see xmo_adapter.py for the real
        # adapter's stricter host-lookup requirement).
        assert 'auto-blocked' in alert.description


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
