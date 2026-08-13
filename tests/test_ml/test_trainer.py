"""Integration test for ModelTrainer against the real migrated schema.

Same per-test engine create/dispose pattern as tests/test_scheduler (the
trainer goes through the module-level get_session() singleton).
"""
import os
from datetime import datetime, timedelta, timezone

import joblib
import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.adapter.models import TrafficGranularity
from sentinel.db.models import Device, TrafficSample
from sentinel.db.repositories import DeviceTypeProfileRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.ml.anomaly_engine import AnomalyEngine
from sentinel.ml.model_store import ModelStore
from sentinel.ml.trainer import ModelTrainer

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'
_MIN_SAMPLES = 5
# A dedicated test type, not a real seeded one (e.g. 'Smartphone') — that
# row is admin-editable in production and this dev environment's copy of it
# has in fact already been edited via the Rules page UI, so asserting
# against its seed-migration value would be asserting against a moving
# target. See TestDeviceTypeAwareContamination.
_TEST_DEVICE_TYPE = '__test_trainer_device_type__'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(TrafficSample).where(TrafficSample.mac_address == _MAC))
        await session.execute(delete(Device).where(Device.mac_address == _MAC))
    await DeviceTypeProfileRepository().delete_profile(_TEST_DEVICE_TYPE)
    await get_engine().dispose()


@pytest.fixture
def engine(tmp_path):
    return AnomalyEngine(ModelStore(str(tmp_path)), min_samples=_MIN_SAMPLES, contamination=0.1)


async def _seed_samples(count: int, granularity: str, days_ago: int = 0) -> None:
    # Throughput must vary across rows — AnomalyEngine skips training on
    # constant/flat volume data (see TestZeroVarianceGuard in
    # test_anomaly_engine.py), so a fixed 100/200 every row would never train.
    now = datetime.now(timezone.utc) - timedelta(days=days_ago)
    async with get_session() as session:
        for i in range(count):
            session.add(TrafficSample(
                time=now + timedelta(seconds=i),
                mac_address=_MAC,
                bytes_sent_delta=1000,
                bytes_recv_delta=2000,
                throughput_up_kbps=95 + (i % 11),
                throughput_dn_kbps=190 + (i % 23),
                granularity=granularity,
                poll_interval_s=15,
            ))


class TestRetrainAll:
    async def test_trains_a_model_from_recent_per_device_history(self, engine, tmp_path):
        await _seed_samples(_MIN_SAMPLES, TrafficGranularity.PER_DEVICE.value)

        await ModelTrainer(engine).retrain_all()

        assert (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()

    async def test_per_port_history_is_excluded(self, engine, tmp_path):
        await _seed_samples(_MIN_SAMPLES, TrafficGranularity.PER_PORT.value)

        await ModelTrainer(engine).retrain_all()

        assert not (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()

    async def test_samples_older_than_retrain_window_are_excluded(self, engine, tmp_path):
        await _seed_samples(_MIN_SAMPLES, TrafficGranularity.PER_DEVICE.value, days_ago=10)

        await ModelTrainer(engine).retrain_all()

        assert not (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()

    async def test_too_few_recent_samples_does_not_train(self, engine, tmp_path):
        await _seed_samples(_MIN_SAMPLES - 1, TrafficGranularity.PER_DEVICE.value)

        await ModelTrainer(engine).retrain_all()

        assert not (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()


class TestDeviceTypeAwareContamination:
    """See device_profiles.py's module docstring: contamination is a *rate*,
    not an absolute rarity cutoff — a device type prone to short, legitimate,
    recurring bursts needs a higher rate so that pattern stops being flagged
    as an outlier forever. ModelTrainer.retrain_all() resolves this per mac
    from its device_type profile (seeded by the device_type_profiles
    migration) instead of always using the engine's own global default."""

    async def test_uses_the_device_types_configured_contamination_for_the_fit(self, engine, tmp_path):
        await DeviceTypeProfileRepository().upsert_profile(
            _TEST_DEVICE_TYPE, high_upload_ratio_threshold=2.5, volume_sustained_polls=6, contamination=0.33,
        )
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-phone', device_type=_TEST_DEVICE_TYPE))
        await _seed_samples(_MIN_SAMPLES, TrafficGranularity.PER_DEVICE.value)

        await ModelTrainer(engine).retrain_all()

        models = joblib.load(tmp_path / 'aa-bb-cc-dd-ee-ff.joblib')
        assert models['iso'].get_params()['contamination'] == 0.33

    async def test_unrecognized_device_type_falls_back_to_default_profile_not_engine_default(self, engine, tmp_path):
        """engine fixture's own contamination is 0.1 — DEFAULT_PROFILE's is
        0.05. An unrecognized device_type must resolve to the latter, not
        silently keep using whatever the engine happened to be constructed
        with."""
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device', device_type='Toaster'))
        await _seed_samples(_MIN_SAMPLES, TrafficGranularity.PER_DEVICE.value)

        await ModelTrainer(engine).retrain_all()

        models = joblib.load(tmp_path / 'aa-bb-cc-dd-ee-ff.joblib')
        assert models['iso'].get_params()['contamination'] == 0.05

    async def test_no_device_row_falls_back_to_default_profile(self, engine, tmp_path):
        await _seed_samples(_MIN_SAMPLES, TrafficGranularity.PER_DEVICE.value)

        await ModelTrainer(engine).retrain_all()

        models = joblib.load(tmp_path / 'aa-bb-cc-dd-ee-ff.joblib')
        assert models['iso'].get_params()['contamination'] == 0.05
