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

# decision_function()'s calibrated boundary: negative = anomaly, positive =
# normal, per the contamination rate the model was fit with. NOT the same as
# score_samples() < some constant — score_samples() is IsolationForest's raw,
# uncalibrated path-length score, whose scale is specific to each fitted
# model's own training distribution and isn't comparable across devices or to
# a fixed threshold. Comparing it to -0.1 (an earlier version of this code)
# caused a real incident: a low-variance/idle device's typical, repeated
# samples scored well past that arbitrary cutoff, so it was flagged
# anomalous on essentially every poll — 68k ANOMALOUS_VOLUME alerts across
# 4 days. decision_function() = score_samples() - offset_, where offset_ is
# fit specifically so 0 represents the contamination-implied boundary — see
# https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
ANOMALY_THRESHOLD = 0.0

# Indices of the throughput columns in FEATURE_NAMES — the only ones that
# reflect actual traffic volume. hour_of_day/day_of_week/is_night are
# expected to have little variance early in a bootstrap window; that's fine.
_VOLUME_FEATURE_INDICES = [FEATURE_NAMES.index('throughput_up_kbps'), FEATURE_NAMES.index('throughput_dn_kbps')]


class AnomalyEngine:
    """Buffers samples per device until there's enough to train, then scores each new one."""

    def __init__(
        self, model_store: ModelStore, min_samples: int, contamination: float,
        magnitude_multiplier: float = 0.5, alert_magnitude_multiplier: float = 6.0,
    ) -> None:
        self._store = model_store
        self._min_samples = min_samples
        self._contamination = contamination
        # See is_anomalous()/_fit_and_save() — how far past the calibrated
        # 0.0 boundary (in units of that device's own fitted training-score
        # std) a sample must be before it counts as anomalous at all.
        self._magnitude_multiplier = magnitude_multiplier
        # A second, stricter multiplier — see anomaly_severity(). Clearing
        # magnitude_multiplier only means "anomalous at all"; escalating
        # from an informational data point to a WARNING requires clearing
        # this one too.
        self._alert_magnitude_multiplier = alert_magnitude_multiplier
        self._buffers: dict[str, list[np.ndarray]] = {}
        self._model_cache: dict[str, dict] = {}

    @property
    def buffered_device_count(self) -> int:
        """Number of MACs currently mid-bootstrap — bounded per-device
        (cleared on train or on a training skip, see _fit_and_save), so this
        should stay small and not climb indefinitely on its own."""
        return len(self._buffers)

    @property
    def trained_model_count(self) -> int:
        """Number of MACs with a model held in the in-memory cache — grows
        with every distinct device ever trained and is never evicted for a
        device that stops connecting, so persistent MAC-randomization churn
        (e.g. phones rotating a private MAC per network) is a plausible
        driver of unbounded growth here over a long uptime."""
        return len(self._model_cache)

    def score(self, sample: TrafficSample) -> float:
        """Anomaly score for this sample. Negative = anomalous, positive =
        normal, 0.0 = the calibrated boundary (or no model yet — bootstrap
        buffering also returns 0.0, so a dashboard can't tell "no model" from
        "exactly at the boundary" apart from context, which is fine — both
        read as "nothing to report").

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
        return float(model['iso'].decision_function(vec)[0])

    def is_anomalous(self, sample: TrafficSample) -> bool:
        """True if both IsolationForest and LOF agree this sample is an outlier
        (per the design doc: two models must agree, to cut down false positives)
        AND the IsolationForest score clears a magnitude bar beyond the bare
        calibrated boundary — see magnitude_threshold below. Read-only — does
        not buffer or train; call score() for that.
        """
        model = self._get_model(sample.mac_address)
        if model is None:
            return False

        vec = build_feature_vector(sample).reshape(1, -1)
        # Self-relative, not a fixed cross-device constant: model.get(...) with
        # a 0.0 default means a model persisted before this magnitude gate
        # existed (missing 'score_std') falls back to exactly today's
        # behavior — bare ANOMALY_THRESHOLD — until its next retrain
        # recomputes the stat. See ANOMALY_THRESHOLD's own comment for why a
        # *shared* constant across devices caused a real incident; comparing
        # each device's score against a spread derived from that same
        # device's own fitted distribution is a different, safer shape.
        score_std = model.get('score_std', 0.0)
        magnitude_threshold = ANOMALY_THRESHOLD - (self._magnitude_multiplier * score_std)
        # bool(...) on both sides, not just lof: `numpy_bool and python_bool`
        # short-circuits to the *numpy* bool when the left side is falsy, so
        # without this is_anomalous() could return np.False_ instead of
        # Python's False — a real value (`np.False_ == False`) but not the
        # same object (`np.False_ is False` is False), which breaks any
        # caller doing an identity check against this method's declared
        # `-> bool` return type.
        iso_anomalous = bool(model['iso'].decision_function(vec)[0] < magnitude_threshold)
        lof_anomalous = bool(model['lof'].predict(vec)[0])  # PyOD: 1 = outlier
        return iso_anomalous and lof_anomalous

    def anomaly_severity(self, sample: TrafficSample) -> Optional[str]:
        """None if this sample isn't anomalous at all (same two-model-
        agreement + magnitude_multiplier gate as is_anomalous()); otherwise
        'INFO' or 'WARNING' depending on how far past that gate the
        IsolationForest score actually is.

        Requested directly after a real pattern: clearing the base
        magnitude_multiplier gate only means "notably unusual for this
        device" — a family video call or a long social-media video binge
        clears it easily, but is perfectly ordinary heavy use, not
        something needing attention. Escalating to WARNING requires
        clearing a second, stricter gate (alert_magnitude_multiplier,
        default 3x the base one) — further out along this same device's
        own fitted score spread. A sample between the two gates is still
        surfaced (AnomalousVolumeDetector still raises an alert for it),
        just as background information rather than a threat.

        Both gates are self-relative (each device compared only to its own
        history), same reasoning as magnitude_threshold below — a fixed,
        cross-device constant here would have exactly the same failure
        mode ANOMALY_THRESHOLD's own comment describes.

        Read-only, same as is_anomalous() — does not buffer or train.
        """
        model = self._get_model(sample.mac_address)
        if model is None:
            return None

        vec = build_feature_vector(sample).reshape(1, -1)
        score_std = model.get('score_std', 0.0)
        magnitude_threshold = ANOMALY_THRESHOLD - (self._magnitude_multiplier * score_std)
        iso_score = float(model['iso'].decision_function(vec)[0])
        iso_anomalous = bool(iso_score < magnitude_threshold)
        lof_anomalous = bool(model['lof'].predict(vec)[0])  # PyOD: 1 = outlier
        if not (iso_anomalous and lof_anomalous):
            return None

        alert_threshold = ANOMALY_THRESHOLD - (self._alert_magnitude_multiplier * score_std)
        return 'WARNING' if iso_score < alert_threshold else 'INFO'

    def train(self, mac: str) -> None:
        """Fit fresh models from this device's buffered samples, if there are enough.

        Always uses the global default contamination — this is the bootstrap
        fit, triggered inline as a side effect of score() during the live
        15s poll loop, which has no async DB access to resolve a per-device-
        type override with (see retrain_from_history's docstring for why
        that's fine: this fit is short-lived, superseded by the next nightly
        retrain within at most 24h).
        """
        buf = self._buffers.get(mac, [])
        if len(buf) < self._min_samples:
            return
        self._fit_and_save(mac, np.vstack(buf), self._contamination)

    def retrain_from_history(
        self, mac: str, feature_vectors: list[np.ndarray], contamination: float | None = None,
    ) -> None:
        """Refit this device's models from historical data (nightly retraining).

        contamination overrides the engine's global default for just this
        fit — ModelTrainer.retrain_all() resolves it per-device-type via
        DeviceTypeProfileRepository before calling this, so a device type
        prone to short, legitimate, recurring bursts (e.g. a phone during a
        video call) can be fit with a higher rate than the default, instead
        of that pattern being flagged as an outlier forever regardless of
        how much history accumulates (contamination is a *rate*, not an
        absolute rarity cutoff — see device_profiles.py's module docstring).
        None (the default) keeps today's behavior for any caller that
        doesn't pass one, e.g. existing tests/callers.
        """
        if len(feature_vectors) < self._min_samples:
            logger.info(
                'Skipping retrain for %s — only %d samples (need %d)',
                mac, len(feature_vectors), self._min_samples,
            )
            return
        effective_contamination = contamination if contamination is not None else self._contamination
        self._fit_and_save(mac, np.vstack(feature_vectors), effective_contamination)

    def forget(self, mac: str) -> None:
        """Drops one device's bootstrap buffer, cached model, and persisted
        model file — used when a device is permanently purged (see
        DeviceRepository.purge_archived) so nothing keeps a purged MAC's
        model in memory or on disk. Same per-MAC teardown reset() does for
        every device at once. Safe to call for a MAC with no buffered/
        trained state (each step is independently a no-op)."""
        self._buffers.pop(mac, None)
        self._model_cache.pop(mac, None)
        self._store.delete(mac)

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

    def _fit_and_save(self, mac: str, X: np.ndarray, contamination: float) -> None:
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

        iso = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
        iso.fit(X)

        lof = LOF(n_neighbors=min(20, max(len(X) // 5, 1)))
        lof.fit(X)

        # This device's own fitted score spread — see is_anomalous()'s
        # magnitude_threshold. Computed from the training set itself, not a
        # held-out sample, so it reflects exactly the distribution
        # decision_function() was calibrated against.
        score_std = float(iso.decision_function(X).std())

        models = {'iso': iso, 'lof': lof, 'score_std': score_std}
        self._store.save(mac, models)
        self._model_cache[mac] = models
        self._buffers.pop(mac, None)  # bootstrap buffer no longer needed once trained
        logger.info('Trained anomaly models for %s on %d samples', mac, len(X))
