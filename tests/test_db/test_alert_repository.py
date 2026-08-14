"""Integration tests for AlertRepository against the real migrated schema —
same per-test engine create/dispose pattern as tests/test_db/test_repositories.py.
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.db.models import Alert
from sentinel.db.repositories import AlertRepository
from sentinel.db.session import get_engine, get_session, init_db

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'
_ALERT_TYPE = '__TEST_ALERT_TYPE__'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Alert).where(Alert.alert_type == _ALERT_TYPE))
    await get_engine().dispose()


class TestUpsert:
    async def test_first_call_inserts_a_new_row(self):
        alert, is_new = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='first',
        )
        assert is_new is True
        assert alert.id is not None
        assert alert.occurrence_count == 1
        assert alert.resolved is False

    async def test_second_call_touches_the_same_row_not_a_duplicate(self):
        first, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='first',
        )
        second, is_new = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='second',
        )
        assert is_new is False
        assert second.id == first.id
        assert second.occurrence_count == 2

        async with get_session() as session:
            result = await session.execute(
                delete(Alert).where(Alert.alert_type == _ALERT_TYPE).returning(Alert.id)
            )
            assert len(result.all()) == 1  # exactly one row exists

    async def test_touch_overwrites_description_raw_data_and_severity(self):
        """Not just last_seen/occurrence_count — the displayed content must
        never go stale while the count climbs (e.g. AccessPointCrossingDetector's
        previous_alias/ap_alias genuinely differs per occurrence)."""
        await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING',
            description='old description', raw_data={'n': 1},
        )
        touched, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='CRITICAL',
            description='new description', raw_data={'n': 2},
        )
        assert touched.description == 'new description'
        assert touched.raw_data == {'n': 2}
        assert touched.severity == 'CRITICAL'

    async def test_touch_bumps_last_seen(self):
        first, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='x',
        )
        async with get_session() as session:
            row = await session.get(Alert, first.id)
            row.last_seen = datetime.now(timezone.utc) - timedelta(hours=1)

        touched, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='x',
        )
        assert touched.last_seen > datetime.now(timezone.utc) - timedelta(minutes=1)

    async def test_null_device_mac_and_dedup_key_match_null_safely(self):
        """The one silent-failure mode this design specifically guards
        against: plain `==` never matches SQL NULL, which would defeat the
        upsert for e.g. WanBandwidthDetector's always-null device_mac."""
        first, is_new_1 = await AlertRepository().upsert(
            device_mac=None, alert_type=_ALERT_TYPE, severity='WARNING', description='x',
        )
        second, is_new_2 = await AlertRepository().upsert(
            device_mac=None, alert_type=_ALERT_TYPE, severity='WARNING', description='y',
        )
        assert is_new_1 is True
        assert is_new_2 is False
        assert second.id == first.id

    async def test_dedup_key_disambiguates_otherwise_identical_pairs(self):
        """Two different rules firing RULE_TRIGGERED on the same device must
        not wrongly coalesce into one row."""
        first, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='x', dedup_key='rule:1',
        )
        second, is_new = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='y', dedup_key='rule:2',
        )
        assert is_new is True
        assert second.id != first.id

    async def test_a_resolved_row_does_not_absorb_a_new_touch(self):
        """A closed incident and a brand-new occurrence of the same
        (mac, alert_type, dedup_key) must not be conflated — upsert only
        ever matches OPEN rows."""
        first, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='x',
        )
        await AlertRepository().resolve(device_mac=_MAC, alert_type=_ALERT_TYPE)

        second, is_new = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='y',
        )
        assert is_new is True
        assert second.id != first.id


class TestResolve:
    async def test_resolves_the_open_row(self):
        await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='x',
        )
        closed = await AlertRepository().resolve(device_mac=_MAC, alert_type=_ALERT_TYPE)
        assert closed is True

        async with get_session() as session:
            result = await session.execute(delete(Alert).where(Alert.alert_type == _ALERT_TYPE).returning(Alert))
            rows = result.scalars().all()
        assert len(rows) == 1
        assert rows[0].resolved is True
        assert rows[0].resolved_at is not None

    async def test_no_op_when_nothing_is_open(self):
        closed = await AlertRepository().resolve(device_mac=_MAC, alert_type=_ALERT_TYPE)
        assert closed is False

    async def test_no_op_when_already_resolved(self):
        await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='x',
        )
        await AlertRepository().resolve(device_mac=_MAC, alert_type=_ALERT_TYPE)
        closed_again = await AlertRepository().resolve(device_mac=_MAC, alert_type=_ALERT_TYPE)
        assert closed_again is False

    async def test_dedup_key_scoped_resolve_does_not_touch_other_keys(self):
        port_22, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='x', dedup_key='port:22',
        )
        port_80, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='y', dedup_key='port:80',
        )
        await AlertRepository().resolve(device_mac=_MAC, alert_type=_ALERT_TYPE, dedup_key='port:22')

        async with get_session() as session:
            refreshed_22 = await session.get(Alert, port_22.id)
            refreshed_80 = await session.get(Alert, port_80.id)
        assert refreshed_22.resolved is True
        assert refreshed_80.resolved is False

    async def test_null_device_mac_resolve_is_null_safe(self):
        await AlertRepository().upsert(
            device_mac=None, alert_type=_ALERT_TYPE, severity='WARNING', description='x',
        )
        closed = await AlertRepository().resolve(device_mac=None, alert_type=_ALERT_TYPE)
        assert closed is True


class TestResolveStaleOpen:
    async def test_closes_rows_past_the_cutoff(self):
        alert, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='x',
        )
        async with get_session() as session:
            row = await session.get(Alert, alert.id)
            row.last_seen = datetime.now(timezone.utc) - timedelta(hours=100)

        closed_count = await AlertRepository().resolve_stale_open(timedelta(hours=72))
        assert closed_count == 1

        async with get_session() as session:
            refreshed = await session.get(Alert, alert.id)
            assert refreshed.resolved is True

    async def test_leaves_recent_rows_open(self):
        await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='x',
        )
        closed_count = await AlertRepository().resolve_stale_open(timedelta(hours=72))
        assert closed_count == 0

    async def test_already_resolved_rows_are_not_recounted(self):
        alert, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='x',
        )
        async with get_session() as session:
            row = await session.get(Alert, alert.id)
            row.last_seen = datetime.now(timezone.utc) - timedelta(hours=100)
        await AlertRepository().resolve(device_mac=_MAC, alert_type=_ALERT_TYPE)

        closed_count = await AlertRepository().resolve_stale_open(timedelta(hours=72))
        assert closed_count == 0

    async def test_boundary_exactly_at_cutoff_is_not_closed(self):
        """last_seen strictly older than the cutoff is closed — a row right
        at the boundary is timing-flaky either way, so this asserts the
        conservative (not-yet-stale) side only."""
        alert, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type=_ALERT_TYPE, severity='WARNING', description='x',
        )
        async with get_session() as session:
            row = await session.get(Alert, alert.id)
            row.last_seen = datetime.now(timezone.utc) - timedelta(hours=71, minutes=59)

        closed_count = await AlertRepository().resolve_stale_open(timedelta(hours=72))
        assert closed_count == 0
