from datetime import datetime, timedelta, timezone

import numpy as np
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


def _varying_sample(mac: str, offset_s: int) -> TrafficSample:
    """A sample with realistic jitter around 100/200 kbps — constant up/down
    would trip the zero-throughput-variance training guard (see TestZeroVarianceGuard)."""
    return _sample(mac, up=95 + (offset_s % 11), down=190 + (offset_s % 23), offset_s=offset_s)


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
            engine.score(_varying_sample('aa:bb:cc:dd:ee:ff', offset_s=i))
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
            engine.score(_varying_sample(mac, offset_s=i))
        return mac

    def test_score_returns_real_float_once_trained(self, engine):
        mac = self._train(engine)
        score = engine.score(_varying_sample(mac, offset_s=999))
        assert isinstance(score, float)
        assert score != 0.0

    def test_in_distribution_sample_not_anomalous(self, engine):
        mac = self._train(engine)
        assert engine.is_anomalous(_varying_sample(mac, offset_s=999)) is False

    def test_extreme_outlier_is_anomalous(self, engine):
        mac = self._train(engine)
        outlier = _sample(mac, up=1_000_000, down=1, offset_s=999)
        assert engine.is_anomalous(outlier) is True

    def test_buffer_is_freed_after_training(self, engine):
        mac = self._train(engine)
        assert mac not in engine._buffers


class TestZeroVarianceGuard:
    """Regression coverage for the bug where every device flooded ANOMALOUS_VOLUME
    alerts: a model fit on flat/constant throughput (e.g. a data source that always
    reads 0 kbps) has no real signal to learn from, and IsolationForest/LOF trained
    on it end up flagging every future sample — including identical repeats — as an
    outlier. Training must be skipped, not silently produce a broken model."""

    def test_constant_zero_throughput_does_not_persist_a_model(self, engine, tmp_path):
        mac = 'aa:bb:cc:dd:ee:ff'
        for i in range(MIN_SAMPLES):
            engine.score(_sample(mac, up=0, down=0, offset_s=i))
        assert not (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()

    def test_constant_nonzero_throughput_also_does_not_persist_a_model(self, engine, tmp_path):
        """Not just zero — any constant up/down (e.g. up=100, down=200 every time)
        is equally featureless and must be skipped too."""
        mac = 'aa:bb:cc:dd:ee:ff'
        for i in range(MIN_SAMPLES):
            engine.score(_sample(mac, up=100, down=200, offset_s=i))
        assert not (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()

    def test_buffer_is_cleared_so_it_does_not_grow_unbounded(self, engine):
        mac = 'aa:bb:cc:dd:ee:ff'
        for i in range(MIN_SAMPLES):
            engine.score(_sample(mac, up=0, down=0, offset_s=i))
        assert mac not in engine._buffers

    def test_repeated_identical_zero_sample_is_never_flagged(self, engine):
        """No model ever gets trained, so scoring stays in bootstrap mode —
        this must not flag the exact flood the user hit in production."""
        mac = 'aa:bb:cc:dd:ee:ff'
        for i in range(MIN_SAMPLES):
            engine.score(_sample(mac, up=0, down=0, offset_s=i))
        assert engine.is_anomalous(_sample(mac, up=0, down=0, offset_s=999)) is False

    def test_retrain_from_history_also_skips_flat_volume(self, engine, tmp_path):
        vectors = [np.array([0.0, 0.0, 0.0, 12.0, 0.0, 0.0]) for _ in range(MIN_SAMPLES)]
        engine.retrain_from_history('aa:bb:cc:dd:ee:ff', vectors)
        assert not (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()


class TestRetrainFromHistory:
    def test_too_few_samples_does_not_train(self, engine, tmp_path):
        vectors = _vecs(MIN_SAMPLES - 1)
        engine.retrain_from_history('aa:bb:cc:dd:ee:ff', vectors)
        assert not (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()

    def test_enough_samples_trains_and_persists(self, engine, tmp_path):
        vectors = _vecs(MIN_SAMPLES)
        engine.retrain_from_history('aa:bb:cc:dd:ee:ff', vectors)
        assert (tmp_path / 'aa-bb-cc-dd-ee-ff.joblib').exists()

    def test_updates_the_in_memory_cache(self, engine):
        vectors = _vecs(MIN_SAMPLES)
        engine.retrain_from_history('aa:bb:cc:dd:ee:ff', vectors)
        # A fresh score() call should use the retrained model, not re-buffer.
        score = engine.score(_sample('aa:bb:cc:dd:ee:ff', offset_s=999))
        assert score != 0.0


def _vecs(n: int) -> list:
    """n feature vectors with realistic jitter in the throughput columns —
    a constant vector would trip the zero-throughput-variance training guard."""
    return [np.array([95.0 + (i % 11), 190.0 + (i % 23), 0.5, 12.0, 0.0, 0.0]) for i in range(n)]


class _FakeIso:
    """Duck-typed IsolationForest stand-in — a fixed decision_function() score,
    so the magnitude-gate arithmetic in is_anomalous() can be tested precisely
    without depending on an actual fit's exact output."""

    def __init__(self, score: float) -> None:
        self._score = score

    def decision_function(self, vec):
        return np.array([self._score])


class _FakeLof:
    def __init__(self, outlier: bool = True) -> None:
        self._outlier = outlier

    def predict(self, vec):
        return np.array([1 if self._outlier else 0])


class TestFitStoresScoreStd:
    """See is_anomalous()'s magnitude_threshold — the spread it's computed
    against must actually get persisted at fit time."""

    def test_trained_model_has_a_nonnegative_score_std(self, engine):
        mac = 'aa:bb:cc:dd:ee:ff'
        for i in range(MIN_SAMPLES):
            engine.score(_varying_sample(mac, offset_s=i))
        model = engine._model_cache[mac]
        assert 'score_std' in model
        assert model['score_std'] >= 0.0

    def test_retrain_from_history_also_stores_score_std(self, engine):
        mac = 'aa:bb:cc:dd:ee:ff'
        engine.retrain_from_history(mac, _vecs(MIN_SAMPLES))
        assert 'score_std' in engine._model_cache[mac]


class TestMagnitudeGate:
    """AnomalyEngine.is_anomalous() requires the IsolationForest score to
    clear magnitude_multiplier * that device's own score_std beyond the bare
    calibrated 0.0 boundary — see the ML_ANOMALY_MAGNITUDE_MULTIPLIER config
    comment for why this is self-relative (per-device), not a fixed constant."""

    _MAC = 'aa:bb:cc:dd:ee:ff'

    def test_missing_score_std_falls_back_to_the_bare_boundary(self, engine):
        """A model persisted before this gate existed (no score_std key) —
        must reproduce exactly today's pre-Layer-2 behavior: any negative
        score past 0.0 counts, no extra magnitude required."""
        engine._model_cache[self._MAC] = {'iso': _FakeIso(-0.01), 'lof': _FakeLof()}
        assert engine.is_anomalous(_sample(self._MAC)) is True

    def test_mild_score_within_the_magnitude_band_is_not_flagged(self, engine):
        engine._magnitude_multiplier = 0.5
        engine._model_cache[self._MAC] = {'iso': _FakeIso(-0.01), 'lof': _FakeLof(), 'score_std': 1.0}
        # threshold = 0.0 - 0.5*1.0 = -0.5; -0.01 is past 0.0 but not past -0.5.
        assert engine.is_anomalous(_sample(self._MAC)) is False

    def test_extreme_score_beyond_the_magnitude_band_is_flagged(self, engine):
        engine._magnitude_multiplier = 0.5
        engine._model_cache[self._MAC] = {'iso': _FakeIso(-0.9), 'lof': _FakeLof(), 'score_std': 1.0}
        assert engine.is_anomalous(_sample(self._MAC)) is True

    def test_score_std_of_zero_reduces_to_the_bare_boundary(self, engine):
        """A device whose training scores had ~zero spread (e.g. very
        regular traffic) — the magnitude band collapses to nothing, same as
        the missing-score_std case, not to "never flags"."""
        engine._magnitude_multiplier = 0.5
        engine._model_cache[self._MAC] = {'iso': _FakeIso(-0.01), 'lof': _FakeLof(), 'score_std': 0.0}
        assert engine.is_anomalous(_sample(self._MAC)) is True

    def test_lof_disagreement_still_suppresses_even_with_an_extreme_iso_score(self, engine):
        """The magnitude gate is additive on top of the existing two-model
        AND, not a replacement for it."""
        engine._magnitude_multiplier = 0.5
        engine._model_cache[self._MAC] = {'iso': _FakeIso(-100.0), 'lof': _FakeLof(outlier=False), 'score_std': 1.0}
        assert engine.is_anomalous(_sample(self._MAC)) is False
