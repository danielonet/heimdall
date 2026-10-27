class TestHealth:
    def test_reports_degraded_without_scheduler(self, client):
        """SCHEDULER_ENABLED=False in the test app, so scheduler_running is always False."""
        resp = client.get('/api/health')
        assert resp.status_code == 503
        body = resp.get_json()
        assert body['status'] == 'degraded'
        assert body['scheduler']['scheduler_running'] is False

    def test_reports_postgres_and_redis_reachable(self, client):
        resp = client.get('/api/health')
        body = resp.get_json()
        assert body['postgres']['reachable'] is True
        assert body['redis']['reachable'] is True

    def test_reports_security_services_defaults_without_scheduler(self, client):
        """Same key shape security_services_snapshot() returns when a
        scheduler exists — a scheduler that never started shouldn't hand the
        frontend a smaller/different JSON shape to special-case."""
        resp = client.get('/api/health')
        body = resp.get_json()
        assert body['security_services'] == {
            'deployment_tier': 'minimal',
            'active_services': [
                'postgres', 'redis', 'router_poll', 'arp_watch', 'dhcp_watch',
                'fingerprint', 'nmap', 'threat_intel', 'wifi_monitor',
            ],
            'arp_watch_active': False, 'dhcp_watch_active': False, 'fingerprint_active': False,
            'sniff_iface': '', 'wifi_monitor_active': False,
            'nmap_last_scan_at': None, 'canary_last_check_at': None,
            'zeek_dns_last_check_at': None, 'zeek_beacon_last_scan_at': None,
            'clamav_reachable': None, 'suricata_last_check_at': None,
        }
        assert body['threat_intel_feeds'] == {}


class TestServiceDetails:
    def test_returns_an_entry_for_every_service(self, client):
        resp = client.get('/api/service-details')
        assert resp.status_code == 200
        body = resp.get_json()
        assert set(body) == {
            'postgres', 'redis', 'router_poll', 'arp_watch', 'dhcp_watch', 'fingerprint',
            'nmap', 'opencanary', 'threat_intel', 'zeek_dns', 'zeek_beacon', 'clamav', 'suricata',
            'wifi_monitor',
        }
        for entry in body.values():
            assert entry['description']
            assert 'last_alert_at' in entry

    def test_postgres_reports_a_live_version_and_size(self, client):
        resp = client.get('/api/service-details')
        postgres = resp.get_json()['postgres']
        assert postgres['version'].startswith('PostgreSQL ')
        assert postgres['database_size_bytes'] > 0

    def test_redis_reports_a_live_version_and_memory_usage(self, client):
        resp = client.get('/api/service-details')
        redis_entry = resp.get_json()['redis']
        assert redis_entry['version'].startswith('Redis ')
        assert redis_entry['used_memory_bytes'] > 0

    def test_nmap_and_clamav_versions_are_none_without_a_running_scheduler(self, client):
        """SCHEDULER_ENABLED=False in the test app — same "no fabricated
        signal" contract as /health's security_services defaults."""
        resp = client.get('/api/service-details')
        body = resp.get_json()
        assert body['nmap']['version'] is None
        assert body['clamav']['version'] is None

    def test_last_alert_at_is_none_with_no_alerts_raised(self, client):
        resp = client.get('/api/service-details')
        assert resp.get_json()['arp_watch']['last_alert_at'] is None

    def test_last_alert_at_reflects_the_most_recent_matching_alert_type(self, client):
        import asyncio
        from datetime import datetime, timedelta, timezone

        from sentinel.db.models import Alert
        from sentinel.db.session import get_session

        older = datetime.now(timezone.utc) - timedelta(days=2)
        newer = datetime.now(timezone.utc) - timedelta(hours=1)

        async def _seed():
            async with get_session() as session:
                session.add(Alert(
                    device_mac='AA:BB:CC:DD:EE:FF', alert_type='ARP_SPOOF', severity='CRITICAL',
                    description='old', created_at=older, resolved=True,
                ))
                session.add(Alert(
                    device_mac='AA:BB:CC:DD:EE:FF', alert_type='ARP_SPOOF', severity='CRITICAL',
                    description='new', created_at=newer, resolved=True,
                ))
        asyncio.run(_seed())

        resp = client.get('/api/service-details')
        last_alert_at = resp.get_json()['arp_watch']['last_alert_at']
        assert last_alert_at is not None
        assert datetime.fromisoformat(last_alert_at) == newer


class TestRouterInfo:
    def test_returns_503_without_running_scheduler(self, client):
        resp = client.get('/api/router')
        assert resp.status_code == 503


class TestWanStats:
    def test_returns_404_when_nothing_recorded_yet(self, client):
        """The real, common case until Device/IP/Interfaces/Interface[Alias=
        'IP_DATA']/Stats is verified against a live router — see
        SagemcomXmoAdapter.get_wan_stats."""
        resp = client.get('/api/wan-stats')
        assert resp.status_code == 404

    def test_returns_the_latest_row(self, client):
        import asyncio
        from datetime import datetime, timezone

        from sentinel.db.models import WanStats as WanStatsModel
        from sentinel.db.session import get_session

        async def _seed():
            async with get_session() as session:
                session.add(WanStatsModel(
                    time=datetime.now(timezone.utc), bytes_sent_delta=1000, bytes_recv_delta=5000,
                    throughput_up_kbps=10, throughput_dn_kbps=50,
                ))
        asyncio.run(_seed())

        resp = client.get('/api/wan-stats')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['bytes_sent_delta'] == 1000
        assert body['throughput_dn_kbps'] == 50
