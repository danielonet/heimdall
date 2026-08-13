"""Tests for GET/PUT/DELETE /api/device-type-profiles/<device_type>."""
import asyncio

import pytest

from sentinel.db.repositories import DeviceTypeProfileRepository

_TEST_TYPE = '__test_device_type__'


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    asyncio.run(DeviceTypeProfileRepository().delete_profile(_TEST_TYPE))


class TestListProfiles:
    def test_no_auth_required_to_read(self, client):
        resp = client.get('/api/device-type-profiles')
        assert resp.status_code == 200

    def test_includes_seeded_smartphone_row(self, client):
        resp = client.get('/api/device-type-profiles')
        body = resp.get_json()
        types = {p['device_type'] for p in body['profiles']}
        assert 'Smartphone' in types

    def test_observed_extremes_degrades_gracefully_with_no_scheduler(self, client):
        """conftest's app fixture runs with SCHEDULER_ENABLED=False — no
        scheduler means no cached observed-extremes stats yet, not a 500."""
        resp = client.get('/api/device-type-profiles')
        assert resp.status_code == 200
        assert resp.get_json()['observed_extremes'] == {'extremes': None, 'computed_at': None}


class TestUpsertProfile:
    def test_requires_auth(self, client):
        resp = client.put(
            f'/api/device-type-profiles/{_TEST_TYPE}',
            json={'high_upload_ratio_threshold': 3.0, 'volume_sustained_polls': 3, 'contamination': 0.05},
        )
        assert resp.status_code == 401

    def test_creates_a_new_profile(self, client, auth_headers):
        resp = client.put(
            f'/api/device-type-profiles/{_TEST_TYPE}',
            json={'high_upload_ratio_threshold': 4.5, 'volume_sustained_polls': 7, 'contamination': 0.12},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['high_upload_ratio_threshold'] == 4.5
        assert body['volume_sustained_polls'] == 7
        assert body['contamination'] == 0.12

        resp = client.get('/api/device-type-profiles')
        matching = [p for p in resp.get_json()['profiles'] if p['device_type'] == _TEST_TYPE]
        assert len(matching) == 1

    def test_updates_an_existing_profile_in_place(self, client, auth_headers):
        client.put(
            f'/api/device-type-profiles/{_TEST_TYPE}',
            json={'high_upload_ratio_threshold': 1.0, 'volume_sustained_polls': 1, 'contamination': 0.01},
            headers=auth_headers,
        )
        resp = client.put(
            f'/api/device-type-profiles/{_TEST_TYPE}',
            json={'high_upload_ratio_threshold': 2.0, 'volume_sustained_polls': 2, 'contamination': 0.02},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.get_json()['high_upload_ratio_threshold'] == 2.0

        resp = client.get('/api/device-type-profiles')
        matching = [p for p in resp.get_json()['profiles'] if p['device_type'] == _TEST_TYPE]
        assert len(matching) == 1  # updated, not duplicated

    def test_rejects_out_of_range_ratio_threshold(self, client, auth_headers):
        resp = client.put(
            f'/api/device-type-profiles/{_TEST_TYPE}',
            json={'high_upload_ratio_threshold': 0, 'volume_sustained_polls': 3, 'contamination': 0.05},
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_rejects_zero_sustained_polls(self, client, auth_headers):
        resp = client.put(
            f'/api/device-type-profiles/{_TEST_TYPE}',
            json={'high_upload_ratio_threshold': 3.0, 'volume_sustained_polls': 0, 'contamination': 0.05},
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_rejects_boolean_sustained_polls(self, client, auth_headers):
        """bool is a subclass of int in Python — must not silently accept True/False as 1/0."""
        resp = client.put(
            f'/api/device-type-profiles/{_TEST_TYPE}',
            json={'high_upload_ratio_threshold': 3.0, 'volume_sustained_polls': True, 'contamination': 0.05},
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_rejects_contamination_above_point_five(self, client, auth_headers):
        resp = client.put(
            f'/api/device-type-profiles/{_TEST_TYPE}',
            json={'high_upload_ratio_threshold': 3.0, 'volume_sustained_polls': 3, 'contamination': 0.9},
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_rejects_missing_field(self, client, auth_headers):
        resp = client.put(
            f'/api/device-type-profiles/{_TEST_TYPE}',
            json={'high_upload_ratio_threshold': 3.0, 'volume_sustained_polls': 3},
            headers=auth_headers,
        )
        assert resp.status_code == 400


class TestDeleteProfile:
    def test_requires_auth(self, client):
        resp = client.delete(f'/api/device-type-profiles/{_TEST_TYPE}')
        assert resp.status_code == 401

    def test_deletes_an_existing_override(self, client, auth_headers):
        client.put(
            f'/api/device-type-profiles/{_TEST_TYPE}',
            json={'high_upload_ratio_threshold': 3.0, 'volume_sustained_polls': 3, 'contamination': 0.05},
            headers=auth_headers,
        )
        resp = client.delete(f'/api/device-type-profiles/{_TEST_TYPE}', headers=auth_headers)
        assert resp.status_code == 204

        resp = client.get('/api/device-type-profiles')
        matching = [p for p in resp.get_json()['profiles'] if p['device_type'] == _TEST_TYPE]
        assert matching == []

    def test_deleting_unknown_profile_returns_404(self, client, auth_headers):
        resp = client.delete(f'/api/device-type-profiles/{_TEST_TYPE}', headers=auth_headers)
        assert resp.status_code == 404
