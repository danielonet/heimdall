"""Pure unit tests for SentinelScheduler.security_services_snapshot() — a
function of a handful of self._* attributes only, so no DB/adapter is
needed (see test_metrics_snapshot.py for the same reasoning)."""
from sentinel.scheduler.scheduler import SentinelScheduler


def _scheduler(tier='full', **overrides):
    sched = object.__new__(SentinelScheduler)
    sched._tier = tier
    sched._arp_watcher = None
    sched._dhcp_watcher = None
    sched._fingerprinter = None
    sched._sniff_iface = 'eth0'
    sched._last_nmap_scan_at = None
    sched._last_canary_check_at = None
    sched._last_zeek_dns_check_at = None
    sched._last_zeek_beacon_scan_at = None
    sched._last_spike_ip_enrichment_at = None
    sched._clamav_reachable = None
    sched._last_suricata_check_at = None
    for key, value in overrides.items():
        setattr(sched, key, value)
    return sched


class TestSecurityServicesSnapshot:
    def test_reports_the_deployment_tier(self):
        snapshot = _scheduler(tier='intermediate').security_services_snapshot()
        assert snapshot['deployment_tier'] == 'intermediate'

    def test_minimal_active_services_excludes_all_docker_backed_rows(self):
        snapshot = _scheduler(tier='minimal').security_services_snapshot()
        for key in ('opencanary', 'zeek_dns', 'zeek_beacon', 'clamav', 'suricata'):
            assert key not in snapshot['active_services']
        assert 'postgres' in snapshot['active_services']

    def test_intermediate_active_services_includes_only_opencanary(self):
        snapshot = _scheduler(tier='intermediate').security_services_snapshot()
        assert 'opencanary' in snapshot['active_services']
        for key in ('zeek_dns', 'zeek_beacon', 'clamav', 'suricata'):
            assert key not in snapshot['active_services']

    def test_full_active_services_includes_everything(self):
        snapshot = _scheduler(tier='full').security_services_snapshot()
        for key in ('opencanary', 'zeek_dns', 'zeek_beacon', 'clamav', 'suricata'):
            assert key in snapshot['active_services']

    def test_still_reports_the_existing_liveness_fields(self):
        class _FakeWatcher:
            is_active = True

        snapshot = _scheduler(tier='full', _arp_watcher=_FakeWatcher()).security_services_snapshot()
        assert snapshot['arp_watch_active'] is True
        assert snapshot['dhcp_watch_active'] is False
