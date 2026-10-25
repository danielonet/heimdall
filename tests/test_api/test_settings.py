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


class TestAlertStaleHours:
    def test_default_is_24(self, client):
        resp = client.get('/api/settings')
        assert resp.get_json()['alert_stale_hours'] == 24

    def test_updates_the_threshold(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_stale_hours': 72}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['alert_stale_hours'] == 72

        resp = client.get('/api/settings')
        assert resp.get_json()['alert_stale_hours'] == 72

    def test_rejects_zero(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_stale_hours': 0}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_negative(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_stale_hours': -1}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_absurdly_large_values(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_stale_hours': 999999}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_non_integer(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_stale_hours': 'a lot'}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_boolean(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_stale_hours': True}, headers=auth_headers)
        assert resp.status_code == 400

    def test_requires_auth(self, client):
        resp = client.patch('/api/settings', json={'alert_stale_hours': 48})
        assert resp.status_code == 401


class TestAlertAutoResolveHours:
    def test_default_is_72(self, client):
        resp = client.get('/api/settings')
        assert resp.get_json()['alert_auto_resolve_hours'] == 72

    def test_updates_the_threshold(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_auto_resolve_hours': 48}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['alert_auto_resolve_hours'] == 48

        resp = client.get('/api/settings')
        assert resp.get_json()['alert_auto_resolve_hours'] == 48

    def test_rejects_zero(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_auto_resolve_hours': 0}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_negative(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_auto_resolve_hours': -1}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_absurdly_large_values(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_auto_resolve_hours': 999999}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_non_integer(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_auto_resolve_hours': 'a lot'}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_boolean(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'alert_auto_resolve_hours': True}, headers=auth_headers)
        assert resp.status_code == 400

    def test_requires_auth(self, client):
        resp = client.patch('/api/settings', json={'alert_auto_resolve_hours': 48})
        assert resp.status_code == 401

    def test_independent_from_alert_stale_hours(self, client, auth_headers):
        """Deliberately separate settings — changing one must not affect
        the other. See the a4e19d6b3c72 migration docstring."""
        client.patch('/api/settings', json={'alert_stale_hours': 10}, headers=auth_headers)
        resp = client.get('/api/settings')
        assert resp.get_json()['alert_auto_resolve_hours'] == 72


class TestDeviceArchiveAfterDays:
    def test_default_is_90(self, client):
        resp = client.get('/api/settings')
        assert resp.get_json()['device_archive_after_days'] == 90

    def test_updates_the_threshold(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_archive_after_days': 30}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['device_archive_after_days'] == 30

        resp = client.get('/api/settings')
        assert resp.get_json()['device_archive_after_days'] == 30

    def test_rejects_zero(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_archive_after_days': 0}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_negative(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_archive_after_days': -1}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_absurdly_large_values(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_archive_after_days': 999999}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_non_integer(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_archive_after_days': 'a lot'}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_boolean(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_archive_after_days': True}, headers=auth_headers)
        assert resp.status_code == 400

    def test_requires_auth(self, client):
        resp = client.patch('/api/settings', json={'device_archive_after_days': 30})
        assert resp.status_code == 401


class TestDevicePurgeAfterDays:
    def test_default_is_90(self, client):
        resp = client.get('/api/settings')
        assert resp.get_json()['device_purge_after_days'] == 90

    def test_updates_the_threshold(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_purge_after_days': 30}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['device_purge_after_days'] == 30

        resp = client.get('/api/settings')
        assert resp.get_json()['device_purge_after_days'] == 30

    def test_rejects_zero(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_purge_after_days': 0}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_negative(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_purge_after_days': -1}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_absurdly_large_values(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_purge_after_days': 999999}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_non_integer(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_purge_after_days': 'a lot'}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_boolean(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'device_purge_after_days': True}, headers=auth_headers)
        assert resp.status_code == 400

    def test_requires_auth(self, client):
        resp = client.patch('/api/settings', json={'device_purge_after_days': 30})
        assert resp.status_code == 401

    def test_independent_from_device_archive_after_days(self, client, auth_headers):
        """Setting one must not clobber the other — they're separate columns
        despite the shared 'device_' prefix and identical validation shape."""
        client.patch('/api/settings', json={'device_archive_after_days': 45}, headers=auth_headers)
        client.patch('/api/settings', json={'device_purge_after_days': 60}, headers=auth_headers)

        resp = client.get('/api/settings')
        data = resp.get_json()
        assert data['device_archive_after_days'] == 45
        assert data['device_purge_after_days'] == 60


class TestWifiMonitorSettings:
    def test_defaults(self, client):
        data = client.get('/api/settings').get_json()
        assert data['wifi_monitor_iface'] is None
        assert data['wifi_protected_ssids'] == []
        assert data['wifi_trusted_bssids'] == []

    def test_updates_ssids_and_bssids(self, client, auth_headers):
        resp = client.patch(
            '/api/settings',
            json={'wifi_protected_ssids': ['MyHomeWiFi'], 'wifi_trusted_bssids': ['c4:eb:42:94:80:4c']},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['wifi_protected_ssids'] == ['MyHomeWiFi']
        assert data['wifi_trusted_bssids'] == ['c4:eb:42:94:80:4c']  # already lowercase, unchanged

    def test_bssids_are_lowercased_on_write(self, client, auth_headers):
        resp = client.patch(
            '/api/settings', json={'wifi_trusted_bssids': ['C4:EB:42:94:80:4C']}, headers=auth_headers,
        )
        assert resp.get_json()['wifi_trusted_bssids'] == ['c4:eb:42:94:80:4c']

    def test_rejects_malformed_bssid(self, client, auth_headers):
        resp = client.patch(
            '/api/settings', json={'wifi_trusted_bssids': ['not-a-mac']}, headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_rejects_non_list_ssids(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'wifi_protected_ssids': 'MyHomeWiFi'}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_iface_not_currently_detected(self, client, auth_headers):
        resp = client.patch(
            '/api/settings', json={'wifi_monitor_iface': 'not-a-real-adapter'}, headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_blank_iface_is_accepted_as_disabled(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'wifi_monitor_iface': ''}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['wifi_monitor_iface'] is None

    def test_requires_auth(self, client):
        resp = client.patch('/api/settings', json={'wifi_protected_ssids': ['MyHomeWiFi']})
        assert resp.status_code == 401


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

    def test_restamps_baseline_established_at_to_now_and_returns_to_learning(self, client, auth_headers):
        """Regression: an earlier version cleared baseline_established_at to
        None and relied on the next poll noticing an empty devices table to
        restamp it — racy against the concurrently-running poll loop (see
        settings.py:purge's docstring), and confirmed in production to
        permanently skip the learning window when it lost that race. Purge
        now stamps the real timestamp itself, atomically, so there's nothing
        left for a later poll to get right or wrong."""
        asyncio.run(SettingsRepository().set_baseline_established_at(
            datetime.now(timezone.utc) - timedelta(hours=200)
        ))
        assert client.get('/api/settings').get_json()['status'] == 'ARMED'

        before = datetime.now(timezone.utc)
        resp = client.post('/api/settings/purge', json={'password': TEST_ADMIN_PASSWORD}, headers=auth_headers)
        assert resp.status_code == 200

        body = client.get('/api/settings').get_json()
        assert body['baseline_established_at'] is not None
        restamped = datetime.fromisoformat(body['baseline_established_at'])
        assert restamped >= before
        assert body['status'] == 'LEARNING'


class TestRouterCredentials:
    def test_get_never_includes_the_password_only_whether_one_is_set(self, client):
        body = client.get('/api/settings').get_json()
        assert 'router_password' not in body
        assert isinstance(body['router_password_configured'], bool)

    def test_updates_username(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'router_username': 'newadmin'}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['router_username'] == 'newadmin'
        assert client.get('/api/settings').get_json()['router_username'] == 'newadmin'

    def test_rejects_blank_username(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'router_username': '   '}, headers=auth_headers)
        assert resp.status_code == 400

    def test_password_change_rejected_when_no_secret_file_configured(self, client, auth_headers):
        """This sandbox's test process doesn't run through scripts/run.sh, so
        ROUTER_PASSWORD_FILE is blank — the route must refuse rather than
        silently no-op or crash trying to write to an empty path."""
        from sentinel.config import settings
        assert not settings.ROUTER_PASSWORD_FILE  # sanity-check the premise
        resp = client.patch('/api/settings', json={'router_password': 'hunter2'}, headers=auth_headers)
        assert resp.status_code == 503

    def test_blank_password_is_a_no_op_not_an_error(self, client, auth_headers):
        """An empty string means 'leave it unchanged' — must not hit the
        'no secret file configured' path just because the field was present."""
        resp = client.patch('/api/settings', json={'router_password': ''}, headers=auth_headers)
        assert resp.status_code == 200

    def test_password_writes_to_the_configured_file_and_applies_live(self, client, auth_headers, tmp_path):
        import sentinel.config as config_module
        pw_file = tmp_path / 'router_password.txt'
        original = config_module.settings.ROUTER_PASSWORD_FILE
        object.__setattr__(config_module.settings, 'ROUTER_PASSWORD_FILE', str(pw_file))
        try:
            resp = client.patch('/api/settings', json={'router_password': 'hunter2'}, headers=auth_headers)
            assert resp.status_code == 200
            assert pw_file.read_text().strip() == 'hunter2'
            assert config_module.settings.ROUTER_PASSWORD == 'hunter2'
            assert client.get('/api/settings').get_json()['router_password_configured'] is True
        finally:
            object.__setattr__(config_module.settings, 'ROUTER_PASSWORD_FILE', original)
            object.__setattr__(config_module.settings, 'ROUTER_PASSWORD', '')

    def test_read_only_password_file_is_refused_cleanly_not_a_500(self, client, auth_headers, tmp_path):
        """Docker-native `secrets:` mounts are read-only — the route must say
        so (503) before touching anything, instead of failing mid-PATCH."""
        import os

        import pytest

        import sentinel.config as config_module
        if os.geteuid() == 0:
            pytest.skip('root bypasses file permissions')
        pw_file = tmp_path / 'router_password.txt'
        pw_file.write_text('old\n')
        pw_file.chmod(0o444)
        original = config_module.settings.ROUTER_PASSWORD_FILE
        object.__setattr__(config_module.settings, 'ROUTER_PASSWORD_FILE', str(pw_file))
        try:
            resp = client.patch('/api/settings', json={'router_password': 'hunter2'}, headers=auth_headers)
            assert resp.status_code == 503
            assert 'not writable' in resp.get_json()['error']
            assert pw_file.read_text().strip() == 'old'
        finally:
            object.__setattr__(config_module.settings, 'ROUTER_PASSWORD_FILE', original)


class TestSmtpSettings:
    def test_get_never_includes_the_password_only_whether_one_is_set(self, client):
        body = client.get('/api/settings').get_json()
        assert 'smtp_password' not in body
        assert isinstance(body['smtp_password_configured'], bool)

    def test_updates_smtp_fields(self, client, auth_headers):
        resp = client.patch('/api/settings', json={
            'smtp_host': 'smtp.example.com', 'smtp_port': 465, 'smtp_from': 'heimdall@example.com',
            'smtp_to': 'me@example.com', 'smtp_username': 'heimdall@example.com', 'smtp_use_tls': False,
        }, headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['smtp_host'] == 'smtp.example.com'
        assert body['smtp_port'] == 465
        assert body['smtp_from'] == 'heimdall@example.com'
        assert body['smtp_to'] == 'me@example.com'
        assert body['smtp_username'] == 'heimdall@example.com'
        assert body['smtp_use_tls'] is False

    def test_partial_update_preserves_unspecified_fields(self, client, auth_headers):
        client.patch('/api/settings', json={'smtp_host': 'smtp.example.com', 'smtp_from': 'a@b.com'}, headers=auth_headers)
        resp = client.patch('/api/settings', json={'smtp_port': 25}, headers=auth_headers)
        body = resp.get_json()
        assert body['smtp_port'] == 25
        assert body['smtp_host'] == 'smtp.example.com'
        assert body['smtp_from'] == 'a@b.com'

    def test_rejects_out_of_range_port(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'smtp_port': 0}, headers=auth_headers)
        assert resp.status_code == 400
        resp = client.patch('/api/settings', json={'smtp_port': 70000}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_non_boolean_use_tls(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'smtp_use_tls': 'yes'}, headers=auth_headers)
        assert resp.status_code == 400

    def test_password_change_rejected_when_no_secret_file_configured(self, client, auth_headers):
        from sentinel.config import settings
        assert not settings.SMTP_PASSWORD_FILE  # sanity-check the premise
        resp = client.patch('/api/settings', json={'smtp_password': 'hunter2'}, headers=auth_headers)
        assert resp.status_code == 503

    def test_blank_password_is_a_no_op_not_an_error(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'smtp_password': ''}, headers=auth_headers)
        assert resp.status_code == 200

    def test_password_writes_to_the_configured_file_and_applies_live(self, client, auth_headers, tmp_path):
        import sentinel.config as config_module
        pw_file = tmp_path / 'smtp_password.txt'
        original = config_module.settings.SMTP_PASSWORD_FILE
        object.__setattr__(config_module.settings, 'SMTP_PASSWORD_FILE', str(pw_file))
        try:
            resp = client.patch('/api/settings', json={'smtp_password': 'app-password'}, headers=auth_headers)
            assert resp.status_code == 200
            assert pw_file.read_text().strip() == 'app-password'
            assert config_module.settings.SMTP_PASSWORD == 'app-password'
            assert client.get('/api/settings').get_json()['smtp_password_configured'] is True
        finally:
            object.__setattr__(config_module.settings, 'SMTP_PASSWORD_FILE', original)
            object.__setattr__(config_module.settings, 'SMTP_PASSWORD', '')
