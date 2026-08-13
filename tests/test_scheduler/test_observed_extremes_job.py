"""Focused tests for SentinelScheduler._observed_extremes_job/
observed_extremes_snapshot — mirrors tests/test_scheduler/test_canary_job.py's
object.__new__(SentinelScheduler) pattern: this job only ever touches the DB
(via sentinel.detection.observed_extremes) and its own two instance attrs.
"""
import os

import pytest
import pytest_asyncio
from flask import Flask

from sentinel.db.session import get_engine, init_db
from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    await get_engine().dispose()


@pytest.fixture
def scheduler():
    sched = object.__new__(SentinelScheduler)
    sched._observed_extremes = None
    sched._observed_extremes_computed_at = None
    return sched


class TestObservedExtremesJob:
    async def test_populates_extremes_and_timestamp(self, scheduler):
        await scheduler._observed_extremes_job()

        # Keyed by device_type (see compute_observed_extremes) — assert the
        # shape of whatever entries exist, not a specific device_type, since
        # that depends on what's actually in the shared dev DB.
        assert scheduler._observed_extremes is not None
        for entry in scheduler._observed_extremes.values():
            assert set(entry.keys()) == {'high_upload_ratio_threshold', 'volume_sustained_polls', 'contamination'}
        assert scheduler._observed_extremes_computed_at is not None

    async def test_snapshot_reflects_the_computed_result(self, scheduler):
        await scheduler._observed_extremes_job()

        snapshot = scheduler.observed_extremes_snapshot()

        assert snapshot['extremes'] == scheduler._observed_extremes
        assert snapshot['computed_at'] is not None

    async def test_snapshot_before_any_run_reports_no_data_yet(self, scheduler):
        snapshot = scheduler.observed_extremes_snapshot()
        assert snapshot == {'extremes': None, 'computed_at': None}

    async def test_a_failed_run_leaves_the_previous_result_in_place(self, scheduler, monkeypatch):
        await scheduler._observed_extremes_job()
        first_result = scheduler._observed_extremes
        first_computed_at = scheduler._observed_extremes_computed_at
        assert first_result is not None

        async def _boom():
            raise RuntimeError('DB hiccup')

        monkeypatch.setattr('sentinel.scheduler.scheduler.compute_observed_extremes', _boom)
        await scheduler._observed_extremes_job()  # must not raise

        assert scheduler._observed_extremes == first_result
        assert scheduler._observed_extremes_computed_at == first_computed_at
