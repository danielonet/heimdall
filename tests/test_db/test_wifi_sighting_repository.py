"""Integration tests for WifiSightingRepository against the real migrated
schema — same per-test engine create/dispose pattern as
tests/test_db/test_alert_repository.py. Uses a distinctive MAC prefix and
deletes its own rows in teardown, rather than truncating any table — this
suite runs against the same shared dev DB other work in this repo also
depends on.
"""
import os

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.db.models import WifiSighting
from sentinel.db.repositories import WifiSightingRepository
from sentinel.db.session import get_engine, get_session, init_db

pytestmark = pytest.mark.asyncio

_MAC = 'de:ad:be:ef:00:01'  # locally-administered (U/L bit set) — always resolves to vendor_name=''


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(WifiSighting).where(WifiSighting.mac_address == _MAC))
    await get_engine().dispose()


class TestUpsert:
    async def test_first_call_inserts_a_new_row(self):
        repo = WifiSightingRepository()

        await repo.upsert(_MAC, signal=-70, probed_ssid='SomeNetwork')

        async with get_session() as session:
            row = await session.get(WifiSighting, _MAC)
        assert row is not None
        assert row.times_seen == 1
        assert row.strongest_signal_dbm == -70
        assert row.last_probed_ssid == 'SomeNetwork'
        assert row.vendor_name == ''  # locally-administered MAC — no real OUI to resolve

    async def test_second_call_touches_the_same_row_and_bumps_times_seen(self):
        repo = WifiSightingRepository()
        await repo.upsert(_MAC, signal=-70, probed_ssid='SomeNetwork')

        await repo.upsert(_MAC, signal=-65, probed_ssid='SomeNetwork')

        async with get_session() as session:
            row = await session.get(WifiSighting, _MAC)
        assert row.times_seen == 2

    async def test_keeps_the_strongest_signal_not_the_most_recent(self):
        repo = WifiSightingRepository()
        await repo.upsert(_MAC, signal=-80, probed_ssid=None)

        await repo.upsert(_MAC, signal=-40, probed_ssid=None)  # much closer — stronger signal
        await repo.upsert(_MAC, signal=-90, probed_ssid=None)  # now far away — weaker signal

        async with get_session() as session:
            row = await session.get(WifiSighting, _MAC)
        assert row.strongest_signal_dbm == -40

    async def test_a_touch_with_no_probed_ssid_does_not_clear_the_last_known_one(self):
        repo = WifiSightingRepository()
        await repo.upsert(_MAC, signal=-70, probed_ssid='SomeNetwork')

        await repo.upsert(_MAC, signal=-70, probed_ssid=None)

        async with get_session() as session:
            row = await session.get(WifiSighting, _MAC)
        assert row.last_probed_ssid == 'SomeNetwork'

    async def test_a_later_probed_ssid_overwrites_the_earlier_one(self):
        repo = WifiSightingRepository()
        await repo.upsert(_MAC, signal=-70, probed_ssid='SomeNetwork')

        await repo.upsert(_MAC, signal=-70, probed_ssid='DifferentNetwork')

        async with get_session() as session:
            row = await session.get(WifiSighting, _MAC)
        assert row.last_probed_ssid == 'DifferentNetwork'


class TestListRecent:
    async def test_includes_a_just_upserted_row(self):
        repo = WifiSightingRepository()
        await repo.upsert(_MAC, signal=-70, probed_ssid=None)

        rows = await repo.list_recent()

        assert any(r.mac_address == _MAC for r in rows)
