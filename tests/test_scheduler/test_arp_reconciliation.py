"""Focused tests for the DHCP-lease reconciliation fix in
SentinelScheduler._startup_job / _reconcile_arp_table / _verify_arp_change_
against_dhcp.

Root cause being fixed: ArpWatcher.seed() was only ever called once, at
startup, from `devices.ip_address`/`mac_address` — Heimdall's own,
sometimes-stale cache. A device's DHCP lease can legitimately move it to a
new IP between polls; when that happened, the very next live ARP packet for
that IP looked exactly like spoofing to ArpWatcher, which has no way to
tell "the router just reassigned this" from "someone is attacking this"
from inside its own table. Confirmed live 2026-08-28: a burst of 6 false
ARP_SPOOF findings (and auto-blocks) fired within 6 seconds of a restart,
one per device whose seeded MAC no longer matched the router's live truth.

Follow-up requested by the user once that fix was live: reconciling every
single 15s poll cycle, forever, was itself unwanted router chatter — this
file also covers the adaptive-cadence rework: _reconcile_arp_table now only
actually fetches once ARP_DHCP_RECONCILE_INTERVAL_S has elapsed (default 5
minutes), while a live suspected-spoof event instead goes through the
faster, bounded _verify_arp_change_against_dhcp retry loop before
_persist_arp_alert (tested in test_threat_auto_block.py, not here — see
that file's TestPersistArpAlert for the "verification confirms it, no
alert raised" case) is allowed to escalate to ARP_SPOOF/auto-block.

Mirrors tests/test_scheduler/test_threat_auto_block.py's
object.__new__(SentinelScheduler) pattern — every method under test here
only ever touches self._adapter, self._arp_watcher/_fingerprinter/
_dhcp_watcher/_router_ip/_last_arp_reconcile_at/_arp_verify_*, and (for
_startup_job) a read-only `devices` query; never self._loop or __init__'s
many unrelated kwargs.

_startup_job's own devices-table read is intentionally unscoped (seed from
every known device — the same "whole network" shape the nmap-job pollution
bug taught this file's siblings to be wary of), but unlike that job this
method only *reads* devices, never writes one — there is nothing here that
could corrupt the shared dev DB the way the nmap/spike-enrichment jobs did,
so no DB seeding or cleanup is needed: every assertion below just checks
that the expected pairs are *present* in what got passed to seed(), never
that the list equals a fully-controlled set.
"""
import os
from unittest.mock import AsyncMock, Mock

import pytest
import pytest_asyncio
from flask import Flask

from sentinel.adapter.models import DhcpLease
from sentinel.db.session import init_db
from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    """_startup_job reads the devices table (read-only — see module
    docstring) before seeding; needs a real engine to do that against."""
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)


def _scheduler_with_mocks(leases_result) -> tuple[SentinelScheduler, Mock, AsyncMock]:
    """A scheduler with just enough state for _startup_job/_reconcile_arp_table/
    _verify_arp_change_against_dhcp to run, and every side effect mocked out.

    _arp_verify_max_attempts/_retry_interval_s are set to a small/instant
    budget by default so a test that wants the real retry-loop shape can
    override them explicitly, and every other test doesn't pay for real
    asyncio.sleep() calls it doesn't care about.
    """
    scheduler = object.__new__(SentinelScheduler)
    arp_watcher = Mock()
    arp_watcher.is_active = True
    scheduler._arp_watcher = arp_watcher
    scheduler._fingerprinter = Mock()
    scheduler._dhcp_watcher = Mock()
    scheduler._router_ip = '10.100.102.1'
    scheduler._last_arp_reconcile_at = None
    scheduler._arp_verify_max_attempts = 2
    scheduler._arp_verify_retry_interval_s = 0

    adapter = AsyncMock()
    if isinstance(leases_result, Exception):
        adapter.get_dhcp_leases = AsyncMock(side_effect=leases_result)
    else:
        adapter.get_dhcp_leases = AsyncMock(return_value=leases_result)
    scheduler._adapter = adapter  # _ensure_adapter() returns this as-is, never calls create_router_adapter()

    return scheduler, arp_watcher, adapter


class TestStartupJobSeeding:
    async def test_seeds_from_live_dhcp_leases(self):
        """The core fix: a lease the router reports overrides the DB's
        cached pairing, since seed() lets later entries in the list win
        per-IP and lease pairs are appended after the DB ones."""
        scheduler, arp_watcher, _ = _scheduler_with_mocks([
            DhcpLease(mac_address='00:e0:4c:68:04:8c', ip_address='10.100.102.2', hostname='MIBOX4'),
        ])

        await scheduler._startup_job()

        seeded_pairs = arp_watcher.seed.call_args[0][0]
        assert ('10.100.102.2', '00:e0:4c:68:04:8c') in seeded_pairs
        arp_watcher.start.assert_called_once()

    async def test_falls_back_to_db_pairings_when_leases_fetch_fails(self):
        """A router/adapter error must not stop the watcher from starting
        at all — it just starts seeded from whatever the DB already has,
        same as before this fix existed."""
        scheduler, arp_watcher, _ = _scheduler_with_mocks(RuntimeError('router unreachable'))

        await scheduler._startup_job()  # must not raise

        arp_watcher.seed.assert_called_once()
        arp_watcher.start.assert_called_once()
        scheduler._fingerprinter.start.assert_called_once()

    async def test_empty_lease_list_does_not_prevent_seeding(self):
        scheduler, arp_watcher, _ = _scheduler_with_mocks([])

        await scheduler._startup_job()

        arp_watcher.seed.assert_called_once()
        arp_watcher.start.assert_called_once()


class TestReconcileArpTable:
    async def test_reseeds_from_fresh_leases_on_first_call(self):
        scheduler, arp_watcher, adapter = _scheduler_with_mocks([
            DhcpLease(mac_address='aa:bb:cc:dd:ee:01', ip_address='10.100.102.9', hostname='thing'),
        ])

        await scheduler._reconcile_arp_table(adapter)

        arp_watcher.seed.assert_called_once_with([('10.100.102.9', 'aa:bb:cc:dd:ee:01')])

    async def test_skips_when_watcher_is_not_active(self):
        """No raw-socket permission (or not started yet) — nothing to
        reconcile, and no point paying for a leases fetch."""
        scheduler, arp_watcher, adapter = _scheduler_with_mocks([
            DhcpLease(mac_address='aa:bb:cc:dd:ee:01', ip_address='10.100.102.9', hostname='thing'),
        ])
        arp_watcher.is_active = False

        await scheduler._reconcile_arp_table(adapter)

        adapter.get_dhcp_leases.assert_not_awaited()
        arp_watcher.seed.assert_not_called()

    async def test_leases_fetch_failure_does_not_raise(self):
        scheduler, arp_watcher, adapter = _scheduler_with_mocks(RuntimeError('router unreachable'))

        await scheduler._reconcile_arp_table(adapter)  # must not raise

        arp_watcher.seed.assert_not_called()

    async def test_no_leases_does_not_call_seed_with_an_empty_list(self):
        """An empty result (router reachable but nothing leased right now)
        is different from a fetch failure, but still nothing to reconcile —
        seed() shouldn't be called with an empty list either way."""
        scheduler, arp_watcher, adapter = _scheduler_with_mocks([])

        await scheduler._reconcile_arp_table(adapter)

        arp_watcher.seed.assert_not_called()

    async def test_lease_with_no_ip_is_excluded(self):
        scheduler, arp_watcher, adapter = _scheduler_with_mocks([
            DhcpLease(mac_address='aa:bb:cc:dd:ee:01', ip_address='', hostname='thing'),
        ])

        await scheduler._reconcile_arp_table(adapter)

        arp_watcher.seed.assert_not_called()


class TestReconcileArpTableCadence:
    """The user-requested follow-up: reconciling every 15s poll cycle,
    forever, was itself the complaint — this pins down the resulting
    ARP_DHCP_RECONCILE_INTERVAL_S rate limit."""

    async def test_second_call_within_the_interval_is_a_no_op(self):
        scheduler, arp_watcher, adapter = _scheduler_with_mocks([
            DhcpLease(mac_address='aa:bb:cc:dd:ee:01', ip_address='10.100.102.9', hostname='thing'),
        ])

        await scheduler._reconcile_arp_table(adapter)
        await scheduler._reconcile_arp_table(adapter)  # e.g. the very next 15s poll cycle

        arp_watcher.seed.assert_called_once()
        adapter.get_dhcp_leases.assert_awaited_once()

    async def test_call_after_the_interval_has_elapsed_reconciles_again(self):
        scheduler, arp_watcher, adapter = _scheduler_with_mocks([
            DhcpLease(mac_address='aa:bb:cc:dd:ee:01', ip_address='10.100.102.9', hostname='thing'),
        ])

        await scheduler._reconcile_arp_table(adapter)
        # Simulate ARP_DHCP_RECONCILE_INTERVAL_S having elapsed since the
        # first call, without a real 5-minute sleep in the test.
        scheduler._last_arp_reconcile_at -= 301
        await scheduler._reconcile_arp_table(adapter)

        assert arp_watcher.seed.call_count == 2
        assert adapter.get_dhcp_leases.await_count == 2

    async def test_watcher_going_inactive_between_calls_does_not_consume_the_cadence(self):
        """Skipping via the is_active guard must not itself count as a
        reconciliation — otherwise a watcher that starts inactive and later
        activates could sit un-reconciled for a full interval it never
        actually used."""
        scheduler, arp_watcher, adapter = _scheduler_with_mocks([
            DhcpLease(mac_address='aa:bb:cc:dd:ee:01', ip_address='10.100.102.9', hostname='thing'),
        ])
        arp_watcher.is_active = False

        await scheduler._reconcile_arp_table(adapter)
        arp_watcher.is_active = True
        await scheduler._reconcile_arp_table(adapter)

        arp_watcher.seed.assert_called_once()


class TestVerifyArpChangeAgainstDhcp:
    """The "actively poll" half of the request — a live suspected-spoof
    event re-polls DHCP leases directly (bypassing ARP_DHCP_RECONCILE_
    INTERVAL_S entirely) rather than waiting for the next scheduled
    reconciliation. See test_threat_auto_block.py's TestPersistArpAlert for
    how this gates the actual ARP_SPOOF/auto-block decision.
    """

    async def test_confirmed_on_the_first_attempt_returns_true_without_sleeping(self):
        scheduler, _, adapter = _scheduler_with_mocks([
            DhcpLease(mac_address='00:e0:4c:68:04:8c', ip_address='10.100.102.2', hostname='MIBOX4'),
        ])

        result = await scheduler._verify_arp_change_against_dhcp('10.100.102.2', '00:e0:4c:68:04:8c')

        assert result is True
        adapter.get_dhcp_leases.assert_awaited_once()  # no retries needed

    async def test_confirmed_on_a_later_attempt_returns_true(self, monkeypatch):
        """The router's own DHCP exchange for a fresh lease can take a
        moment to settle — a lease that only shows up on the second poll
        must still resolve as confirmed, not exhaust straight to False."""
        scheduler, _, adapter = _scheduler_with_mocks([])
        scheduler._arp_verify_max_attempts = 3
        adapter.get_dhcp_leases = AsyncMock(side_effect=[
            [],
            [DhcpLease(mac_address='00:e0:4c:68:04:8c', ip_address='10.100.102.2', hostname='MIBOX4')],
        ])
        sleeps = []
        monkeypatch.setattr('asyncio.sleep', AsyncMock(side_effect=lambda s: sleeps.append(s)))

        result = await scheduler._verify_arp_change_against_dhcp('10.100.102.2', '00:e0:4c:68:04:8c')

        assert result is True
        assert adapter.get_dhcp_leases.await_count == 2
        assert sleeps == [0]  # slept once, between the two attempts

    async def test_never_confirmed_exhausts_every_attempt_and_returns_false(self):
        scheduler, _, adapter = _scheduler_with_mocks([
            DhcpLease(mac_address='11:22:33:44:55:66', ip_address='10.100.102.2', hostname='someone-else'),
        ])
        scheduler._arp_verify_max_attempts = 3

        result = await scheduler._verify_arp_change_against_dhcp('10.100.102.2', '00:e0:4c:68:04:8c')

        assert result is False
        assert adapter.get_dhcp_leases.await_count == 3

    async def test_leases_fetch_failure_counts_as_an_unconfirmed_attempt_not_a_hard_stop(self):
        """A transient router error on one attempt shouldn't give up
        immediately — it's treated the same as 'no matching lease yet' and
        the retry loop continues."""
        scheduler, _, adapter = _scheduler_with_mocks([])
        scheduler._arp_verify_max_attempts = 2
        adapter.get_dhcp_leases = AsyncMock(side_effect=[
            RuntimeError('router unreachable'),
            [DhcpLease(mac_address='00:e0:4c:68:04:8c', ip_address='10.100.102.2', hostname='MIBOX4')],
        ])

        result = await scheduler._verify_arp_change_against_dhcp('10.100.102.2', '00:e0:4c:68:04:8c')

        assert result is True
        assert adapter.get_dhcp_leases.await_count == 2

    async def test_missing_ip_or_mac_returns_false_without_calling_the_adapter(self):
        scheduler, _, adapter = _scheduler_with_mocks([])

        assert await scheduler._verify_arp_change_against_dhcp('', '00:e0:4c:68:04:8c') is False
        assert await scheduler._verify_arp_change_against_dhcp('10.100.102.2', '') is False
        adapter.get_dhcp_leases.assert_not_awaited()
