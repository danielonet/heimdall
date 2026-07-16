import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.db.models import Alert, Device, TrustedMac
from sentinel.db.repositories import SettingsRepository
from sentinel.db.session import get_session
from tests.test_api.conftest import TEST_ADMIN_PASSWORD, _test_config

_MAC = 'aa:bb:cc:dd:ee:ff'


@pytest.fixture
def app(tmp_path):
    """Overrides conftest's app fixture to point ML_MODEL_DIR at a throwaway
    directory — the purge route deletes every file under it, and the real
    default (Settings.ML_MODEL_DIR) is the actual on-disk model store this
    dev install uses. Must never point at that in a test."""
    from sentinel.api.app import create_app
    return create_app(config=_test_config(ML_MODEL_DIR=str(tmp_path)))


def _seed_device(**overrides) -> None:
    async def _seed():
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device', **overrides))
    asyncio.run(_seed())


class TestGetSettings:
    def test_returns_the_env_default_with_no_override(self, client):
        from sentinel.config import settings
        resp = client.get('/api/settings')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['ml_learning_period_hours'] == settings.ML_LEARNING_PERIOD_HOURS
        assert body['data_retention_days'] == settings.DATA_RETENTION_DAYS

    def test_no_auth_required_to_read(self, client):
        resp = client.get('/api/settings')
        assert resp.status_code == 200

    def test_reports_db_size(self, client):
        """Just needs to be a real, positive number — the exact value depends
        on whatever else happens to be in the test database at the moment."""
        resp = client.get('/api/settings')
        assert resp.get_json()['db_size_mb'] > 0

    def test_status_is_learning_when_database_is_empty(self, client):
        resp = client.get('/api/settings')
        assert resp.get_json()['status'] == 'LEARNING'
        assert resp.get_json()['baseline_established_at'] is None

    def test_status_is_armed_once_baseline_is_older_than_the_learning_period(self, client):
        old_baseline = datetime.now(timezone.utc) - timedelta(hours=100)
        asyncio.run(SettingsRepository().set_baseline_established_at(old_baseline))
        asyncio.run(SettingsRepository().set_ml_learning_period_hours(72))

        resp = client.get('/api/settings')
        assert resp.get_json()['status'] == 'ARMED'

    def test_status_stays_learning_within_the_learning_period(self, client):
        recent_baseline = datetime.now(timezone.utc) - timedelta(hours=1)
        asyncio.run(SettingsRepository().set_baseline_established_at(recent_baseline))
        asyncio.run(SettingsRepository().set_ml_learning_period_hours(72))

        resp = client.get('/api/settings')
        assert resp.get_json()['status'] == 'LEARNING'

    def test_pre_existing_install_with_devices_but_no_baseline_is_grandfathered_armed(self, client):
        """A devices row without a stamped baseline_established_at means this
        install predates the LEARNING/ARMED feature — must not force a fake
        new learning period onto an already-established network."""
        _seed_device()
        resp = client.get('/api/settings')
        assert resp.get_json()['status'] == 'ARMED'


class TestUpdateSettings:
    def test_requires_auth(self, client):
        resp = client.patch('/api/settings', json={'ml_learning_period_hours': 24})
        assert resp.status_code == 401

    def test_updates_the_learning_period(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'ml_learning_period_hours': 24}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['ml_learning_period_hours'] == 24

        resp = client.get('/api/settings')
        assert resp.get_json()['ml_learning_period_hours'] == 24

    def test_rejects_zero(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'ml_learning_period_hours': 0}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_negative(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'ml_learning_period_hours': -5}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_absurdly_large_values(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'ml_learning_period_hours': 999999}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_non_integer(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'ml_learning_period_hours': 'a lot'}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_boolean(self, client, auth_headers):
        """bool is a subclass of int in Python — must not silently accept True/False as 1/0."""
        resp = client.patch('/api/settings', json={'ml_learning_period_hours': True}, headers=auth_headers)
        assert resp.status_code == 400

    def test_unrelated_fields_are_ignored(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'unrelated': 'value'}, headers=auth_headers)
        assert resp.status_code == 200

    def test_updates_the_retention_days(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'data_retention_days': 30}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['data_retention_days'] == 30

        resp = client.get('/api/settings')
        assert resp.get_json()['data_retention_days'] == 30

    def test_retention_rejects_zero(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'data_retention_days': 0}, headers=auth_headers)
        assert resp.status_code == 400

    def test_retention_rejects_non_integer(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'data_retention_days': 'a lot'}, headers=auth_headers)
        assert resp.status_code == 400

    def test_can_update_both_fields_in_one_request(self, client, auth_headers):
        resp = client.patch(
            '/api/settings',
            json={'ml_learning_period_hours': 48, 'data_retention_days': 30},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['ml_learning_period_hours'] == 48
        assert body['data_retention_days'] == 30

    def test_an_invalid_field_leaves_a_valid_one_in_the_same_request_unapplied(self, client, auth_headers):
        """Validate-then-apply, not apply-then-validate — a bad
        data_retention_days shouldn't silently let ml_learning_period_hours
        through in the same request."""
        resp = client.patch(
            '/api/settings',
            json={'ml_learning_period_hours': 48, 'data_retention_days': -1},
            headers=auth_headers,
        )
        assert resp.status_code == 400

        resp = client.get('/api/settings')
        from sentinel.config import settings
        assert resp.get_json()['ml_learning_period_hours'] == settings.ML_LEARNING_PERIOD_HOURS


class TestPurge:
    def test_requires_auth(self, client):
        resp = client.post('/api/settings/purge', json={'password': TEST_ADMIN_PASSWORD})
        assert resp.status_code == 401

    def test_requires_correct_password_even_with_valid_jwt(self, client, auth_headers):
        resp = client.post('/api/settings/purge', json={'password': 'wrong'}, headers=auth_headers)
        assert resp.status_code == 401

    def test_missing_password_rejected(self, client, auth_headers):
        resp = client.post('/api/settings/purge', json={}, headers=auth_headers)
        assert resp.status_code == 401

    def test_correct_password_wipes_devices_and_alerts(self, client, auth_headers):
        _seed_device()

        async def _seed_alert():
            async with get_session() as session:
                session.add(Alert(device_mac=_MAC, alert_type='NEW_DEVICE', severity='CRITICAL'))
        asyncio.run(_seed_alert())

        async def _trust():
            async with get_session() as session:
                session.add(TrustedMac(mac_address=_MAC))
        asyncio.run(_trust())

        resp = client.post('/api/settings/purge', json={'password': TEST_ADMIN_PASSWORD}, headers=auth_headers)
        assert resp.status_code == 200

        assert client.get(f'/api/devices/{_MAC}').status_code == 404

        async def _counts():
            from sqlalchemy import func, select
            async with get_session() as session:
                devices = await session.scalar(select(func.count()).select_from(Device))
                alerts = await session.scalar(select(func.count()).select_from(Alert))
                trusted = await session.scalar(select(func.count()).select_from(TrustedMac))
                return devices, alerts, trusted
        devices, alerts, trusted = asyncio.run(_counts())
        assert (devices, alerts, trusted) == (0, 0, 0)

    def test_deletes_persisted_model_files(self, client, auth_headers, tmp_path):
        model_file = tmp_path / 'aa-bb-cc-dd-ee-ff.joblib'
        model_file.write_bytes(b'not a real model, just needs to exist')

        resp = client.post('/api/settings/purge', json={'password': TEST_ADMIN_PASSWORD}, headers=auth_headers)
        assert resp.status_code == 200
        assert not model_file.exists()

    def test_preserves_configured_preferences(self, client, auth_headers):
        """Purging is 'delete all recorded data', not 'reset my settings' —
        an admin's ml_learning_period_hours/data_retention_days choices must
        survive a purge."""
        client.patch(
            '/api/settings',
            json={'ml_learning_period_hours': 24, 'data_retention_days': 30},
            headers=auth_headers,
        )

        resp = client.post('/api/settings/purge', json={'password': TEST_ADMIN_PASSWORD}, headers=auth_headers)
        assert resp.status_code == 200

        resp = client.get('/api/settings')
        body = resp.get_json()
        assert body['ml_learning_period_hours'] == 24
        assert body['data_retention_days'] == 30

    def test_clears_baseline_established_at_and_returns_to_learning(self, client, auth_headers):
        asyncio.run(SettingsRepository().set_baseline_established_at(
            datetime.now(timezone.utc) - timedelta(hours=200)
        ))
        assert client.get('/api/settings').get_json()['status'] == 'ARMED'

        resp = client.post('/api/settings/purge', json={'password': TEST_ADMIN_PASSWORD}, headers=auth_headers)
        assert resp.status_code == 200

        body = client.get('/api/settings').get_json()
        assert body['baseline_established_at'] is None
        assert body['status'] == 'LEARNING'
