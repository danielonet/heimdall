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
        resp = client.get('/api/health')
        body = resp.get_json()
        assert body['security_services'] == {
            'arp_watch_active': False, 'fingerprint_active': False,
            'nmap_last_scan_at': None, 'canary_last_check_at': None,
        }
        assert body['threat_intel_feeds'] == {}


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
