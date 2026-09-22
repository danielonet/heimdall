import asyncio

from sentinel.db.models import WifiSighting
from sentinel.db.session import get_session


def _seed_sighting(mac: str = 'aa:bb:cc:dd:ee:01', signal: int = -70) -> None:
    async def _seed():
        async with get_session() as session:
            session.add(WifiSighting(mac_address=mac, strongest_signal_dbm=signal, last_probed_ssid='SomeNet'))
    asyncio.run(_seed())


class TestListSightings:
    def test_empty_list(self, client):
        resp = client.get('/api/wifi/sightings')
        assert resp.get_json()['sightings'] == []

    def test_returns_a_seeded_sighting(self, client):
        _seed_sighting()
        resp = client.get('/api/wifi/sightings')
        sightings = resp.get_json()['sightings']
        assert len(sightings) == 1
        assert sightings[0]['mac_address'] == 'aa:bb:cc:dd:ee:01'
        assert sightings[0]['strongest_signal_dbm'] == -70
        assert sightings[0]['last_probed_ssid'] == 'SomeNet'


class TestMonitorInterfaces:
    def test_returns_a_list(self, client):
        resp = client.get('/api/wifi/monitor-interfaces')
        assert isinstance(resp.get_json()['interfaces'], list)
