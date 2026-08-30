"""Integration tests for DeviceIdentityLinker against the real migrated
schema — mirrors test_correlation.py's real-DB style.
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.db.models import Device
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.device_identity import DeviceIdentityLinker

pytestmark = pytest.mark.asyncio

# Locally-administered (U/L bit set — 0xee & 0b10 == 2) — randomized-MAC
# candidates. Deliberately a distinctive, obviously-synthetic prefix, not a
# real-looking address — this suite runs against the shared dev DB, which
# has genuine device rows in it.
_MAC_A = 'ee:00:00:00:00:01'
_MAC_B = 'ee:00:00:00:00:02'
_MAC_C = 'ee:00:00:00:00:03'
# Real manufacturer OUI (U/L bit clear — 0x00 & 0b10 == 0) — not a
# randomization candidate.
_MANUFACTURER_MAC = '00:00:00:00:00:05'

_ALL_MACS = [_MAC_A, _MAC_B, _MAC_C, _MANUFACTURER_MAC]
_NOW = datetime.now(timezone.utc)


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


async def _add_device(mac: str, hostname: str, **overrides) -> None:
    defaults = dict(is_online=False, first_seen=_NOW, last_seen=_NOW, ip_address='10.0.0.5')
    defaults.update(overrides)
    async with get_session() as session:
        session.add(Device(mac_address=mac, hostname=hostname, **defaults))


@pytest.fixture
def linker() -> DeviceIdentityLinker:
    return DeviceIdentityLinker()


class TestFindCandidateGroups:
    async def test_two_devices_sharing_a_hostname_form_a_group(self, linker):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9')
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10')

        async with get_session() as session:
            groups = await linker.find_candidate_groups(session)

        matches = [g for g in groups if g['hostname'] == 'phone']
        assert len(matches) == 1
        assert {m['mac_address'] for m in matches[0]['members']} == {_MAC_A, _MAC_B}

    async def test_a_lone_device_produces_no_group(self, linker):
        await _add_device(_MAC_A, 'lonely-phone')

        async with get_session() as session:
            groups = await linker.find_candidate_groups(session)

        assert not any(g['hostname'] == 'lonely-phone' for g in groups)

    async def test_already_linked_member_is_excluded_from_the_group(self, linker):
        await _add_device(_MAC_A, 'phone')
        await _add_device(_MAC_B, 'phone')
        await _add_device(
            _MAC_C, 'phone', linked_to_mac=_MAC_A, linked_at=_NOW, link_reason='already linked',
        )

        async with get_session() as session:
            groups = await linker.find_candidate_groups(session)

        matches = [g for g in groups if g['hostname'] == 'phone']
        assert len(matches) == 1
        assert {m['mac_address'] for m in matches[0]['members']} == {_MAC_A, _MAC_B}

    async def test_non_randomized_mac_is_excluded_from_the_group(self, linker):
        """A real manufacturer OUI has no reason to be treated as a
        possible duplicate of another MAC — restricts the heuristic to the
        phenomenon it exists for."""
        await _add_device(_MAC_A, 'phone')
        await _add_device(_MANUFACTURER_MAC, 'phone')

        async with get_session() as session:
            groups = await linker.find_candidate_groups(session)

        assert not any(g['hostname'] == 'phone' for g in groups)

    async def test_is_online_does_not_exclude_a_member(self, linker):
        """Regression: an earlier version filtered candidates on
        is_online=False, which silently never matched a device this exact
        router keeps (incorrectly) re-reporting as online — see the module
        docstring. is_online must have no bearing on group membership;
        only a direct ARP probe (done by the caller) decides who's alive."""
        await _add_device(_MAC_A, 'phone', is_online=True)
        await _add_device(_MAC_B, 'phone', is_online=True)

        async with get_session() as session:
            groups = await linker.find_candidate_groups(session)

        matches = [g for g in groups if g['hostname'] == 'phone']
        assert len(matches) == 1
        assert {m['mac_address'] for m in matches[0]['members']} == {_MAC_A, _MAC_B}

    async def test_stale_beyond_the_lookback_window_is_excluded(self, linker):
        await _add_device(_MAC_A, 'phone', last_seen=_NOW - timedelta(hours=48))
        await _add_device(_MAC_B, 'phone')
        await _add_device(_MAC_C, 'phone')

        async with get_session() as session:
            groups = await linker.find_candidate_groups(session)

        matches = [g for g in groups if g['hostname'] == 'phone']
        assert len(matches) == 1
        assert {m['mac_address'] for m in matches[0]['members']} == {_MAC_B, _MAC_C}

    async def test_blank_hostname_is_excluded(self, linker):
        await _add_device(_MAC_A, '')
        await _add_device(_MAC_B, '')

        async with get_session() as session:
            groups = await linker.find_candidate_groups(session)

        assert not any(g['hostname'] == '' for g in groups)

    async def test_member_ip_addresses_are_included(self, linker):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.9')
        await _add_device(_MAC_B, 'phone', ip_address='10.0.0.10')

        async with get_session() as session:
            groups = await linker.find_candidate_groups(session)

        matches = [g for g in groups if g['hostname'] == 'phone']
        ips = {m['mac_address']: m['ip_address'] for m in matches[0]['members']}
        assert ips == {_MAC_A: '10.0.0.9', _MAC_B: '10.0.0.10'}


def _for(candidates, new_mac: str) -> list:
    """This suite runs against the shared dev DB (see module docstring),
    and find_ip_continuity_candidates' outer query has no IP scoping of
    its own — it's expected to see genuine unrelated rows alongside each
    test's own synthetic ones (confirmed live: this file routinely also
    surfaces a real production candidate on every run). Filter to just
    this test's own new_mac before asserting, same reasoning as
    TestFindCandidateGroups' `matches = [g for g in groups if ...]`."""
    return [c for c in candidates if c['new_mac'] == new_mac]


class TestFindIpContinuityCandidates:
    """The fallback for a rotated MAC that never reported a hostname at
    all, so find_candidate_groups' hostname rule can never match it — see
    that method's docstring for the live incident this closes."""

    async def test_matches_a_hostnameless_mac_claiming_the_old_devices_ip(self, linker):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.18', last_seen=_NOW - timedelta(hours=1))
        await _add_device(_MAC_B, '', ip_address='10.0.0.18', first_seen=_NOW, last_seen=_NOW)

        async with get_session() as session:
            candidates = await linker.find_ip_continuity_candidates(session)

        matches = _for(candidates, _MAC_B)
        assert len(matches) == 1
        assert matches[0]['old_mac'] == _MAC_A
        assert matches[0]['ip_address'] == '10.0.0.18'
        assert matches[0]['hostname'] == 'phone'

    async def test_new_mac_with_a_real_manufacturer_oui_is_excluded(self, linker):
        """A device with a genuine hardware MAC claiming a freed IP is just
        an ordinary new device on the network, not a rotation of anything."""
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.18', last_seen=_NOW - timedelta(hours=1))
        await _add_device(_MANUFACTURER_MAC, '', ip_address='10.0.0.18', first_seen=_NOW, last_seen=_NOW)

        async with get_session() as session:
            candidates = await linker.find_ip_continuity_candidates(session)

        assert _for(candidates, _MANUFACTURER_MAC) == []

    async def test_old_mac_with_a_real_manufacturer_oui_is_excluded(self, linker):
        await _add_device(_MANUFACTURER_MAC, 'printer', ip_address='10.0.0.18', last_seen=_NOW - timedelta(hours=1))
        await _add_device(_MAC_B, '', ip_address='10.0.0.18', first_seen=_NOW, last_seen=_NOW)

        async with get_session() as session:
            candidates = await linker.find_ip_continuity_candidates(session)

        assert _for(candidates, _MAC_B) == []

    async def test_new_mac_with_a_hostname_is_excluded(self, linker):
        """Has a hostname of its own — find_candidate_groups is the right
        (stronger) path for this one, not the fallback."""
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.18', last_seen=_NOW - timedelta(hours=1))
        await _add_device(_MAC_B, 'phone-2', ip_address='10.0.0.18', first_seen=_NOW, last_seen=_NOW)

        async with get_session() as session:
            candidates = await linker.find_ip_continuity_candidates(session)

        assert _for(candidates, _MAC_B) == []

    async def test_old_device_with_no_hostname_is_excluded(self, linker):
        """Nothing to carry forward — the whole point is anchoring on the
        old device's hostname."""
        await _add_device(_MAC_A, '', ip_address='10.0.0.18', last_seen=_NOW - timedelta(hours=1))
        await _add_device(_MAC_B, '', ip_address='10.0.0.18', first_seen=_NOW, last_seen=_NOW)

        async with get_session() as session:
            candidates = await linker.find_ip_continuity_candidates(session)

        assert _for(candidates, _MAC_B) == []

    async def test_different_ips_do_not_match(self, linker):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.18', last_seen=_NOW - timedelta(hours=1))
        await _add_device(_MAC_B, '', ip_address='10.0.0.19', first_seen=_NOW, last_seen=_NOW)

        async with get_session() as session:
            candidates = await linker.find_ip_continuity_candidates(session)

        assert _for(candidates, _MAC_B) == []

    async def test_old_device_beyond_the_lookback_window_is_excluded(self, linker):
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.18', last_seen=_NOW - timedelta(hours=30))
        await _add_device(_MAC_B, '', ip_address='10.0.0.18', first_seen=_NOW, last_seen=_NOW)

        async with get_session() as session:
            candidates = await linker.find_ip_continuity_candidates(session)

        assert _for(candidates, _MAC_B) == []

    async def test_new_devices_stale_first_seen_does_not_exclude_it(self, linker):
        """Regression for a real, confirmed-live bug: an earlier version of
        this query required the new MAC's first_seen to be recent, which
        silently broke on a devices table seeded in bulk (see
        scripts/seed_baseline.py) — every row from that seed shares the
        exact same (long-past) first_seen no matter how many times it's
        rotated in since, since _upsert_devices never touches first_seen
        for an already-existing row. A device that's actively answering
        right now (fresh last_seen) must still match even when first_seen
        is old."""
        await _add_device(_MAC_A, 'phone', ip_address='10.0.0.18', last_seen=_NOW - timedelta(hours=1))
        await _add_device(
            _MAC_B, '', ip_address='10.0.0.18',
            first_seen=_NOW - timedelta(days=4), last_seen=_NOW,
        )

        async with get_session() as session:
            candidates = await linker.find_ip_continuity_candidates(session)

        assert len(_for(candidates, _MAC_B)) == 1

    async def test_already_linked_anchor_resolves_through_its_own_link(self, linker):
        """Regression for a real, confirmed-live bug: a phone that had
        already rotated once (MAC_A already linked to MAC_C from that
        first rotation) rotated *again* to MAC_B. MAC_A is still the
        on-file anchor at this IP with the right hostname — excluding it
        just because it's already linked meant every rotation after the
        first one could never match anything, forever. old_mac must
        resolve to MAC_A's own target (MAC_C), not MAC_A itself, so MAC_B
        attaches to the original canonical identity rather than a stale
        intermediate one."""
        await _add_device(
            _MAC_A, 'phone', ip_address='10.0.0.18', last_seen=_NOW - timedelta(hours=1),
            linked_to_mac=_MAC_C,
        )
        await _add_device(_MAC_B, '', ip_address='10.0.0.18', first_seen=_NOW, last_seen=_NOW)

        async with get_session() as session:
            candidates = await linker.find_ip_continuity_candidates(session)

        matches = _for(candidates, _MAC_B)
        assert len(matches) == 1
        assert matches[0]['old_mac'] == _MAC_C
        assert matches[0]['hostname'] == 'phone'

    async def test_anchor_already_linked_to_the_new_mac_itself_is_excluded(self, linker):
        """Nothing to do — it already resolves to exactly the target this
        would try to create."""
        await _add_device(
            _MAC_A, 'phone', ip_address='10.0.0.18', last_seen=_NOW - timedelta(hours=1),
            linked_to_mac=_MAC_B,
        )
        await _add_device(_MAC_B, '', ip_address='10.0.0.18', first_seen=_NOW, last_seen=_NOW)

        async with get_session() as session:
            candidates = await linker.find_ip_continuity_candidates(session)

        assert _for(candidates, _MAC_B) == []
