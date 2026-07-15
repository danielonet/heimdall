"""Per-device anomaly scoring: IsolationForest + LOF, trained independently for
each MAC address — see docs/architecture/05-ml-anomaly-engine.md for why
per-device rather than one global model.
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np
from pyod.models.lof import LOF
from sklearn.ensemble import IsolationForest

from sentinel.adapter.models import TrafficSample
from sentinel.ml.feature_builder import FEATURE_NAMES, build_feature_vector
from sentinel.ml.model_store import ModelStore

logger = logging.getLogger(__name__)

ANOMALY_THRESHOLD = -0.1  # IsolationForest: < 0 = anomaly, -1 = extreme

# Indices of the throughput columns in FEATURE_NAMES — the only ones that
# reflect actual traffic volume. hour_of_day/day_of_week/is_night are
# expected to have little variance early in a bootstrap window; that's fine.
_VOLUME_FEATURE_INDICES = [FEATURE_NAMES.index('throughput_up_kbps'), FEATURE_NAMES.index('throughput_dn_kbps')]


class AnomalyEngine:
    """Buffers samples per device until there's enough to train, then scores each new one."""

    def __init__(self, model_store: ModelStore, min_samples: int, contamination: float) -> None:
        self._store = model_store
        self._min_samples = min_samples
        self._contamination = contamination
        self._buffers: dict[str, list[np.ndarray]] = {}
        self._model_cache: dict[str, dict] = {}

    def score(self, sample: TrafficSample) -> float:
        """Anomaly score for this sample. Lower = more anomalous. 0.0 = no model yet.

        Has a side effect during bootstrap: buffers the sample, and triggers
        training once enough have accumulated — so this must be called exactly
        once per sample per poll (poll_cycle owns that call).
        """
        mac = sample.mac_address
        model = self._get_model(mac)
        if model is None:
            self._buffer(mac, build_feature_vector(sample).reshape(1, -1))
            return 0.0
        vec = build_feature_vector(sample).reshape(1, -1)
        return float(model['iso'].score_samples(vec)[0])

    def is_anomalous(self, sample: TrafficSample) -> bool:
        """True if both IsolationForest and LOF agree this sample is an outlier
        (per the design doc: two models must agree, to cut down false positives).
        Read-only — does not buffer or train; call score() for that.
        """
        model = self._get_model(sample.mac_address)
        if model is None:
            return False

        vec = build_feature_vector(sample).reshape(1, -1)
        iso_anomalous = model['iso'].score_samples(vec)[0] < ANOMALY_THRESHOLD
        lof_anomalous = bool(model['lof'].predict(vec)[0])  # PyOD: 1 = outlier
        return iso_anomalous and lof_anomalous

    def train(self, mac: str) -> None:
        """Fit fresh models from this device's buffered samples, if there are enough."""
        buf = self._buffers.get(mac, [])
        if len(buf) < self._min_samples:
            return
        self._fit_and_save(mac, np.vstack(buf))

    def retrain_from_history(self, mac: str, feature_vectors: list[np.ndarray]) -> None:
        """Refit this device's models from historical data (nightly retraining)."""
        if len(feature_vectors) < self._min_samples:
            logger.info(
                'Skipping retrain for %s — only %d samples (need %d)',
                mac, len(feature_vectors), self._min_samples,
            )
            return
        self._fit_and_save(mac, np.vstack(feature_vectors))

    def reset(self) -> None:
        """Clear all in-memory state — bootstrap buffers and the loaded-model
        cache. Used after an external purge of the devices/traffic_samples
        tables and the on-disk model store (see ModelStore.clear_all), so
        this already-running process doesn't keep scoring against models
        trained on data that no longer exists."""
        self._buffers.clear()
        self._model_cache.clear()

    def _get_model(self, mac: str) -> Optional[dict]:
        if mac not in self._model_cache:
            loaded = self._store.load(mac)
            if loaded is not None:
                self._model_cache[mac] = loaded
        return self._model_cache.get(mac)

    def _buffer(self, mac: str, vec: np.ndarray) -> None:
        self._buffers.setdefault(mac, []).append(vec)
        if len(self._buffers[mac]) >= self._min_samples:
            self.train(mac)

    def _fit_and_save(self, mac: str, X: np.ndarray) -> None:
        volume_std = X[:, _VOLUME_FEATURE_INDICES].std(axis=0)
        if np.allclose(volume_std, 0):
            # A model fit on flat up/down throughput (e.g. a data source that
            # always reads 0, or a genuinely idle device) has no real signal to
            # learn from — IsolationForest/LOF trained on it end up flagging
            # every future sample, including identical repeats, as an outlier.
            # Skip training and retry once traffic actually varies, rather than
            # persist a model that would flood alerts.
            logger.warning(
                'Skipping anomaly model training for %s — %d samples with no '
                'throughput variance (up/down constant at %s/%s kbps)',
                mac, len(X), X[0, _VOLUME_FEATURE_INDICES[0]], X[0, _VOLUME_FEATURE_INDICES[1]],
            )
            self._buffers.pop(mac, None)
            return

        iso = IsolationForest(n_estimators=100, contamination=self._contamination, random_state=42)
        iso.fit(X)

        lof = LOF(n_neighbors=min(20, max(len(X) // 5, 1)))
        lof.fit(X)

        models = {'iso': iso, 'lof': lof}
        self._store.save(mac, models)
        self._model_cache[mac] = models
        self._buffers.pop(mac, None)  # bootstrap buffer no longer needed once trained
        logger.info('Trained anomaly models for %s on %d samples', mac, len(X))
