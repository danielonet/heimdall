"""Tests for GET /api/metrics — the Prometheus-style exposition endpoint.

SCHEDULER_ENABLED=False in the test app (see conftest.py), so every test
here exercises the "scheduler not running" branch (heimdall_scheduler_up 0,
no poll-timing lines) — the "scheduler actually polled" branch is covered
end-to-end in test_scheduler_integration.py, which runs a real live scheduler.
"""
import asyncio
from datetime import datetime, timedelta, timezone

from sentinel.db.models import Alert, Device
from sentinel.db.session import get_session

_MAC = 'aa:bb:cc:dd:ee:ff'


def _seed_device(**overrides) -> None:
    async def _seed():
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device', **overrides))
    asyncio.run(_seed())


def _seed_alert(**overrides) -> None:
    async def _seed():
        async with get_session() as session:
            defaults = dict(device_mac=_MAC, alert_type='NEW_DEVICE', severity='CRITICAL', acknowledged=False)
            defaults.update(overrides)
            session.add(Alert(**defaults))
    asyncio.run(_seed())


class TestMetricsEndpoint:
    def test_returns_prometheus_text_content_type(self, client):
        resp = client.get('/api/metrics')
        assert resp.status_code == 200
        assert resp.content_type.startswith('text/plain')

    def test_empty_state_reports_zero_counts(self, client):
        resp = client.get('/api/metrics')
        text = resp.get_data(as_text=True)
        assert 'heimdall_devices_total 0' in text
        assert 'heimdall_alerts_total{severity="CRITICAL"} 0' in text
        assert 'heimdall_alerts_total{severity="WARNING"} 0' in text
        assert 'heimdall_alerts_total{severity="INFO"} 0' in text

    def test_device_counts_reflect_seeded_devices(self, client):
        _seed_device(is_online=True, is_blocked=False, is_quarantined=False, is_trusted=True)
        resp = client.get('/api/metrics')
        text = resp.get_data(as_text=True)
        assert 'heimdall_devices_total 1' in text
        assert 'heimdall_devices_online 1' in text
        assert 'heimdall_devices_trusted 1' in text
        assert 'heimdall_devices_blocked 0' in text
        assert 'heimdall_devices_quarantined 0' in text

    def test_blocked_and_quarantined_counts(self, client):
        _seed_device(is_blocked=True, is_quarantined=True)
        resp = client.get('/api/metrics')
        text = resp.get_data(as_text=True)
        assert 'heimdall_devices_blocked 1' in text
        assert 'heimdall_devices_quarantined 1' in text

    def test_alert_counts_by_severity_and_ack_state(self, client):
        _seed_device()
        _seed_alert(severity='CRITICAL', acknowledged=False)
        _seed_alert(severity='CRITICAL', acknowledged=True)
        _seed_alert(severity='WARNING', acknowledged=False)

        resp = client.get('/api/metrics')
        text = resp.get_data(as_text=True)
        assert 'heimdall_alerts_total{severity="CRITICAL"} 2' in text
        assert 'heimdall_alerts_unacknowledged{severity="CRITICAL"} 1' in text
        assert 'heimdall_alerts_total{severity="WARNING"} 1' in text
        assert 'heimdall_alerts_total{severity="INFO"} 0' in text

    def test_last_1h_and_24h_windows(self, client):
        _seed_device()
        now = datetime.now(timezone.utc)
        _seed_alert(severity='CRITICAL', created_at=now - timedelta(minutes=30))
        _seed_alert(severity='CRITICAL', created_at=now - timedelta(hours=10))
        _seed_alert(severity='CRITICAL', created_at=now - timedelta(hours=30))  # outside both windows

        resp = client.get('/api/metrics')
        text = resp.get_data(as_text=True)
        assert 'heimdall_alerts_last_1h{severity="CRITICAL"} 1' in text
        assert 'heimdall_alerts_last_24h{severity="CRITICAL"} 2' in text
        assert 'heimdall_alerts_total{severity="CRITICAL"} 3' in text

    def test_scheduler_down_reports_zero_and_omits_poll_timing(self, client):
        resp = client.get('/api/metrics')
        text = resp.get_data(as_text=True)
        assert 'heimdall_scheduler_up 0' in text
        assert 'heimdall_poll_last_duration_seconds' not in text
        assert 'heimdall_poll_last_success_age_seconds' not in text

    def test_output_includes_help_and_type_lines(self, client):
        resp = client.get('/api/metrics')
        text = resp.get_data(as_text=True)
        assert '# HELP heimdall_devices_total Total devices ever seen' in text
        assert '# TYPE heimdall_devices_total gauge' in text

    def test_no_auth_required(self, client):
        """Same posture as /api/health — a standard Prometheus scrape config
        can't refresh this app's short-lived JWT access tokens."""
        resp = client.get('/api/metrics')
        assert resp.status_code == 200
