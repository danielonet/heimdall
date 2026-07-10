from datetime import datetime, timedelta, timezone

import pytest

from sentinel.adapter.models import TrafficGranularity, TrafficSample
from sentinel.ml.anomaly_engine import AnomalyEngine
from sentinel.ml.model_store import ModelStore

MIN_SAMPLES = 20
_BASE_TIME = datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc)


def _sample(mac: str, up: int = 100, down: int = 200, offset_s: int = 0) -> TrafficSample:
    return TrafficSample(
        mac_address=mac,
        timestamp=_BASE_TIME + timedelta(seconds=offset_s),
        throughput_up_kbps=up,
        throughput_dn_kbps=down,
        granularity=TrafficGranularity.PER_DEVICE,
    )


@pytest.fixture
def engine(tmp_path):
    return AnomalyEngine(ModelStore(str(tmp_path)), min_samples=MIN_SAMPLES, contamination=0.1)


class TestBootstrap:
    def test_score_is_zero_before_min_samples(self, engine):
        for i in range(MIN_SAMPLES - 1):
            score = engine.score(_sample('aa:bb:cc:dd:ee:ff', offset_s=i))
            assert score == 0.0

    def test_is_anomalous_false_before_training(self, engine):
        for i in range(MIN_SAMPLES - 1):
            engine.score(_sample('aa:bb:cc:dd:ee:ff', offset_s=i))
        assert engine.is_anomalous(_sample('aa:bb:cc:dd:ee:ff', offset_s=999)) is False

    def test_training_triggers_automatically_at_threshold(self, engine, tmp_path):
        for i in range(MIN_SAMPLES):
            engine.score(_sample('aa:bb:cc:dd:ee:ff', offset_s=i))
        assert (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()

    def test_devices_buffer_independently(self, engine):
        for i in range(MIN_SAMPLES - 1):
            engine.score(_sample('aa:aa:aa:aa:aa:aa', offset_s=i))
        # A different device shouldn't inherit aa:aa's buffer progress.
        score = engine.score(_sample('bb:bb:bb:bb:bb:bb', offset_s=0))
        assert score == 0.0


class TestScoringAfterTraining:
    def _train(self, engine, mac='aa:bb:cc:dd:ee:ff'):
        for i in range(MIN_SAMPLES):
            engine.score(_sample(mac, up=100, down=200, offset_s=i))
        return mac

    def test_score_returns_real_float_once_trained(self, engine):
        mac = self._train(engine)
        score = engine.score(_sample(mac, up=100, down=200, offset_s=999))
        assert isinstance(score, float)
        assert score != 0.0

    def test_in_distribution_sample_not_anomalous(self, engine):
        mac = self._train(engine)
        assert engine.is_anomalous(_sample(mac, up=100, down=200, offset_s=999)) is False

    def test_extreme_outlier_is_anomalous(self, engine):
        mac = self._train(engine)
        outlier = _sample(mac, up=1_000_000, down=1, offset_s=999)
        assert engine.is_anomalous(outlier) is True

    def test_buffer_is_freed_after_training(self, engine):
        mac = self._train(engine)
        assert mac not in engine._buffers


class TestRetrainFromHistory:
    def test_too_few_samples_does_not_train(self, engine, tmp_path):
        vectors = [_vec() for _ in range(MIN_SAMPLES - 1)]
        engine.retrain_from_history('aa:bb:cc:dd:ee:ff', vectors)
        assert not (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()

    def test_enough_samples_trains_and_persists(self, engine, tmp_path):
        vectors = [_vec() for _ in range(MIN_SAMPLES)]
        engine.retrain_from_history('aa:bb:cc:dd:ee:ff', vectors)
        assert (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()

    def test_updates_the_in_memory_cache(self, engine):
        vectors = [_vec() for _ in range(MIN_SAMPLES)]
        engine.retrain_from_history('aa:bb:cc:dd:ee:ff', vectors)
        # A fresh score() call should use the retrained model, not re-buffer.
        score = engine.score(_sample('aa:bb:cc:dd:ee:ff', offset_s=999))
        assert score != 0.0


def _vec():
    import numpy as np
    return np.array([100.0, 200.0, 0.5, 12.0, 0.0, 0.0])
