"""Integration tests for device_profiles.get_profile() — a thin async wrapper
around DeviceTypeProfileRepository (see tests/test_db/test_repositories.py
for CRUD coverage of the repository itself). Runs against the real migrated
schema's seeded rows (see sentinel/db/migrations/versions/
e91a4c7d3f28_device_type_profiles.py), same pattern as tests/test_db/
test_repositories.py.
"""
import os

import pytest
from flask import Flask

from sentinel.db.session import init_db
from sentinel.detection.device_profiles import DEFAULT_PROFILE, get_profile

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield


class TestGetProfile:
    async def test_unknown_device_type_returns_default(self):
        assert await get_profile('Some Unrecognized Router String') == DEFAULT_PROFILE

    async def test_blank_device_type_returns_default(self):
        assert await get_profile('') == DEFAULT_PROFILE

    async def test_none_device_type_returns_default(self):
        assert await get_profile(None) == DEFAULT_PROFILE

    async def test_nas_gets_a_more_lenient_ratio_and_streak(self):
        profile = await get_profile('Network Attached Storage')
        assert profile['high_upload_ratio_threshold'] > DEFAULT_PROFILE['high_upload_ratio_threshold']
        assert profile['volume_sustained_polls'] > DEFAULT_PROFILE['volume_sustained_polls']

    async def test_ip_camera_gets_a_more_lenient_ratio_and_streak(self):
        profile = await get_profile('IP Camera')
        assert profile['high_upload_ratio_threshold'] > DEFAULT_PROFILE['high_upload_ratio_threshold']
        assert profile['volume_sustained_polls'] > DEFAULT_PROFILE['volume_sustained_polls']

    async def test_printer_gets_a_stricter_ratio_and_streak(self):
        profile = await get_profile('Printer')
        assert profile['high_upload_ratio_threshold'] < DEFAULT_PROFILE['high_upload_ratio_threshold']
        assert profile['volume_sustained_polls'] < DEFAULT_PROFILE['volume_sustained_polls']

    async def test_smartphone_gets_a_lenient_ratio_and_a_longer_streak(self):
        """Smartphone used to only override high_upload_ratio_threshold,
        silently falling back to the generic 3-poll streak for
        volume_sustained_polls — the direct cause of a phone that's normally
        idle and then bursts (video call, streaming) reliably tripping
        ANOMALOUS_VOLUME. Now explicitly overrides both, plus a higher
        contamination for the same underlying reason (see DEFAULT_PROFILE's
        docstring in device_profiles.py)."""
        profile = await get_profile('Smartphone')
        assert profile['high_upload_ratio_threshold'] < DEFAULT_PROFILE['high_upload_ratio_threshold']
        assert profile['volume_sustained_polls'] > DEFAULT_PROFILE['volume_sustained_polls']
        assert profile['contamination'] > DEFAULT_PROFILE['contamination']
