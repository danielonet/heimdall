import asyncio
from datetime import datetime, timedelta, timezone

from sentinel.db.models import DnsQuery
from sentinel.db.session import get_session


class TestFeedStatus:
    def test_returns_503_without_running_scheduler(self, client):
        resp = client.get('/api/threats/feeds')
        assert resp.status_code == 503


class TestUrlhausSetup:
    def test_key_import_and_remove_need_a_login(self, client):
        assert client.put('/api/threats/feeds/urlhaus/key', json={'auth_key': 'abcdefgh1234'}).status_code == 401
        assert client.delete('/api/threats/feeds/urlhaus/key').status_code == 401
        assert client.post('/api/threats/feeds/urlhaus/import').status_code == 401

    def test_return_503_without_running_scheduler(self, client, auth_headers):
        resp = client.put('/api/threats/feeds/urlhaus/key', json={'auth_key': 'abcdefgh1234'}, headers=auth_headers)
        assert resp.status_code == 503


class TestLookupIp:
    def test_returns_503_without_running_scheduler(self, client):
        resp = client.get('/api/threats/lookup/198.51.100.10')
        assert resp.status_code == 503


def _seed_dns_queries(rows: list[dict]) -> None:
    async def _insert():
        async with get_session() as session:
            for row in rows:
                session.add(DnsQuery(**row))
    asyncio.run(_insert())


class TestDnsStats:
    def test_empty_returns_zero_counts(self, client):
        resp = client.get('/api/threats/dns-stats')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['total_queries'] == 0
        assert body['blocked_queries'] == 0
        assert body['top_blocked_domains'] == []
        assert body['top_blocked_lists'] == []

    def test_aggregates_real_and_blocked_queries(self, client):
        now = datetime.now(timezone.utc)
        _seed_dns_queries([
            {'time': now, 'device_mac': 'aa:bb:cc:dd:ee:ff', 'query': 'example.com', 'blocked': False},
            {
                'time': now, 'device_mac': 'aa:bb:cc:dd:ee:ff', 'query': 'bad.example.com',
                'blocked': True, 'list_name': 'urlhaus',
            },
            {
                'time': now + timedelta(seconds=1), 'device_mac': 'aa:bb:cc:dd:ee:ff', 'query': 'bad.example.com',
                'blocked': True, 'list_name': 'urlhaus',
            },
        ])

        resp = client.get('/api/threats/dns-stats')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['total_queries'] == 3
        assert body['blocked_queries'] == 2
        assert body['top_blocked_domains'] == [{'domain': 'bad.example.com', 'count': 2}]
        assert body['top_blocked_lists'] == [{'list_name': 'urlhaus', 'count': 2}]

    def test_queries_older_than_24h_are_excluded(self, client):
        stale = datetime.now(timezone.utc) - timedelta(hours=25)
        _seed_dns_queries([
            {'time': stale, 'device_mac': 'aa:bb:cc:dd:ee:ff', 'query': 'old.example.com', 'blocked': False},
        ])

        resp = client.get('/api/threats/dns-stats')
        assert resp.status_code == 200
        assert resp.get_json()['total_queries'] == 0
