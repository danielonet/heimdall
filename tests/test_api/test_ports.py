import asyncio
from datetime import datetime, timedelta, timezone

from sentinel.db.models import PortStats
from sentinel.db.session import get_session


def _seed_port_stats(port_alias: str = 'PHY1', status: str = 'UP', offset_s: int = 0) -> None:
    async def _seed():
        async with get_session() as session:
            session.add(PortStats(
                time=datetime.now(timezone.utc) + timedelta(seconds=offset_s),
                port_alias=port_alias,
                status=status,
                link_speed_mbps=1000,
                bytes_sent_delta=100,
                bytes_recv_delta=200,
            ))
    asyncio.run(_seed())


class TestListPorts:
    def test_empty_list(self, client):
        resp = client.get('/api/ports')
        assert resp.get_json()['ports'] == []

    def test_returns_latest_row_per_port(self, client):
        _seed_port_stats('PHY1', status='DOWN', offset_s=0)
        _seed_port_stats('PHY1', status='UP', offset_s=5)
        resp = client.get('/api/ports')
        ports = resp.get_json()['ports']
        assert len(ports) == 1
        assert ports[0]['status'] == 'UP'  # the later row

    def test_multiple_ports(self, client):
        _seed_port_stats('PHY1')
        _seed_port_stats('PHY2')
        resp = client.get('/api/ports')
        aliases = {p['port_alias'] for p in resp.get_json()['ports']}
        assert aliases == {'PHY1', 'PHY2'}


class TestGetPortHistory:
    def test_not_found(self, client):
        resp = client.get('/api/ports/PHY9')
        assert resp.status_code == 404

    def test_returns_history(self, client):
        _seed_port_stats('PHY1', offset_s=0)
        _seed_port_stats('PHY1', offset_s=5)
        resp = client.get('/api/ports/PHY1')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['port_alias'] == 'PHY1'
        assert len(body['history']) == 2

    def test_limit_param(self, client):
        for i in range(5):
            _seed_port_stats('PHY1', offset_s=i)
        resp = client.get('/api/ports/PHY1?limit=2')
        assert len(resp.get_json()['history']) == 2
