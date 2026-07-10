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


class TestRouterInfo:
    def test_returns_503_without_running_scheduler(self, client):
        resp = client.get('/api/router')
        assert resp.status_code == 503
