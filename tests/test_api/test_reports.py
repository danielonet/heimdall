from datetime import datetime, timedelta, timezone

from sentinel.db.models import Alert, Device, TrafficSample, WanStats
from sentinel.db.session import get_session

import asyncio

_NOW = datetime.now(timezone.utc)


def _run(coro):
    return asyncio.run(coro)


def _seed_alert(**overrides) -> None:
    defaults = dict(device_mac='aa:bb:cc:dd:ee:ff', alert_type='NEW_DEVICE', severity='CRITICAL', created_at=_NOW)
    defaults.update(overrides)

    async def _seed():
        async with get_session() as session:
            session.add(Alert(**defaults))
    _run(_seed())


def _seed_traffic(**overrides) -> None:
    defaults = dict(
        mac_address='aa:bb:cc:dd:ee:ff', time=_NOW, bytes_sent_delta=1000, bytes_recv_delta=2000,
        granularity='per_device',
    )
    defaults.update(overrides)

    async def _seed():
        async with get_session() as session:
            session.add(TrafficSample(**defaults))
    _run(_seed())


def _seed_device(**overrides) -> None:
    defaults = dict(mac_address='aa:bb:cc:dd:ee:ff', hostname='test-device')
    defaults.update(overrides)

    async def _seed():
        async with get_session() as session:
            session.add(Device(**defaults))
    _run(_seed())


def _seed_wan_stats(**overrides) -> None:
    defaults = dict(time=_NOW, bytes_sent_delta=500, bytes_recv_delta=700)
    defaults.update(overrides)

    async def _seed():
        async with get_session() as session:
            session.add(WanStats(**defaults))
    _run(_seed())


class TestGetReport:
    def test_defaults_to_last_24h_with_no_params(self, client):
        _seed_alert(created_at=_NOW - timedelta(hours=1))
        resp = client.get('/api/reports')
        body = resp.get_json()
        assert body['total'] == 1

    def test_excludes_alerts_outside_the_default_24h_window(self, client):
        _seed_alert(created_at=_NOW - timedelta(hours=30))
        resp = client.get('/api/reports')
        body = resp.get_json()
        assert body['total'] == 0

    def test_explicit_start_and_end(self, client):
        _seed_alert(alert_type='ZZZ_IN_RANGE', created_at=_NOW - timedelta(hours=2))
        _seed_alert(alert_type='ZZZ_OUT_OF_RANGE', created_at=_NOW - timedelta(hours=10))
        start = (_NOW - timedelta(hours=3)).isoformat()
        end = _NOW.isoformat()

        resp = client.get('/api/reports', query_string={'start': start, 'end': end})
        body = resp.get_json()
        types = {g['alert_type'] for g in body['digest_groups']}
        assert 'ZZZ_IN_RANGE' in types
        assert 'ZZZ_OUT_OF_RANGE' not in types

    def test_rejects_start_after_end(self, client):
        start = _NOW.isoformat()
        end = (_NOW - timedelta(hours=1)).isoformat()
        resp = client.get('/api/reports', query_string={'start': start, 'end': end})
        assert resp.status_code == 400

    def test_device_mac_filters_alerts_and_traffic(self, client):
        _seed_device(mac_address='aa:aa:aa:aa:aa:aa', hostname='device-a')
        _seed_device(mac_address='bb:bb:bb:bb:bb:bb', hostname='device-b')
        _seed_alert(device_mac='aa:aa:aa:aa:aa:aa', alert_type='ZZZ_DEVICE_A', created_at=_NOW - timedelta(hours=1))
        _seed_alert(device_mac='bb:bb:bb:bb:bb:bb', alert_type='ZZZ_DEVICE_B', created_at=_NOW - timedelta(hours=1))
        _seed_traffic(mac_address='aa:aa:aa:aa:aa:aa', time=_NOW - timedelta(hours=1))
        _seed_traffic(mac_address='bb:bb:bb:bb:bb:bb', time=_NOW - timedelta(hours=1))

        resp = client.get('/api/reports', query_string={'device_mac': 'aa:aa:aa:aa:aa:aa'})
        body = resp.get_json()

        types = {g['alert_type'] for g in body['digest_groups']}
        assert types == {'ZZZ_DEVICE_A'}
        labels = {t['device_label'] for t in body['traffic']}
        assert labels == {'device-a'}

    def test_hourly_bandwidth_present_and_unaffected_by_device_filter(self, client):
        _seed_wan_stats(time=_NOW - timedelta(hours=1))
        resp = client.get('/api/reports', query_string={'device_mac': 'aa:aa:aa:aa:aa:aa'})
        body = resp.get_json()
        assert len(body['hourly_bandwidth']) >= 1

    def test_no_result_caps_unlike_the_email(self, client):
        """Unlike the digest email's MAX_ALERT_TYPES/MAX_TRAFFIC_DEVICES/
        MAX_BANDWIDTH_HOURS, this endpoint never truncates — see reports.py
        and digest_query.py's own docstrings."""
        for i in range(15):
            _seed_alert(alert_type=f'ZZZ_TYPE_{i}', created_at=_NOW - timedelta(minutes=i + 1))
        resp = client.get('/api/reports')
        body = resp.get_json()
        assert body['truncated'] is False
        assert len(body['digest_groups']) == 15
