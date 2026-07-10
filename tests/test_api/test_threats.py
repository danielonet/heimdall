class TestFeedStatus:
    def test_returns_503_without_running_scheduler(self, client):
        resp = client.get('/api/threats/feeds')
        assert resp.status_code == 503


class TestLookupIp:
    def test_returns_503_without_running_scheduler(self, client):
        resp = client.get('/api/threats/lookup/198.51.100.10')
        assert resp.status_code == 503


class TestDnsStats:
    def test_returns_not_implemented(self, client):
        resp = client.get('/api/threats/dns-stats')
        assert resp.status_code == 501
