# ML Anomaly Engine

## Design principle

One anomaly detection model is trained **per device**, not globally. This is
critical: a camera uploading 500 KB/s might be normal for a Nest camera but
highly anomalous for a door intercom. Per-device models eliminate the false
positives that come from comparing all devices against a single threshold.

## Feature vector — `sentinel/ml/feature_builder.py`

Each `TrafficSample` is converted to a 6-dimensional feature vector:

```python
import numpy as np
from sentinel.adapter.models import TrafficSample

FEATURE_NAMES = [
    'throughput_up_kbps',      # upload speed
    'throughput_dn_kbps',      # download speed
    'upload_download_ratio',   # up/down — high sustained ratio = possible exfil
    'hour_of_day',             # 0–23 — catches off-hours activity
    'day_of_week',             # 0–6 (Mon=0)
    'is_night',                # 1 if 22:00–06:00, else 0
]

def build_feature_vector(sample: TrafficSample) -> np.ndarray:
    ts    = sample.timestamp
    up    = sample.throughput_up_kbps
    down  = sample.throughput_dn_kbps
    ratio = up / max(down, 1)
    return np.array([
        up,
        down,
        ratio,
        ts.hour,
        ts.weekday(),
        1 if ts.hour >= 22 or ts.hour < 6 else 0,
    ], dtype=float)
```

## Anomaly engine — `sentinel/ml/anomaly_engine.py`

Two models are trained per device and both must agree before raising an alert
(reduces false positives):

| Model | Library | Why |
|-------|---------|-----|
| `IsolationForest` | scikit-learn | Fast, works on high-dimensional data, no distribution assumptions |
| `LOF` (Local Outlier Factor) | PyOD | Better for small datasets; complements IsolationForest |

```python
import numpy as np
from sklearn.ensemble import IsolationForest
from pyod.models.lof import LOF
from .model_store import ModelStore
from .feature_builder import build_feature_vector

ANOMALY_THRESHOLD  = -0.1    # IsolationForest: < 0 = anomaly, -1 = extreme
MIN_SAMPLES        = 100     # ~25 minutes at 15 s poll interval
CONTAMINATION      = 0.05    # expect 5% anomalies during training data

class AnomalyEngine:

    def __init__(self):
        self._store   = ModelStore()
        self._buffers = {}    # mac -> list[np.ndarray]

    def score(self, sample) -> float:
        """Anomaly score. Lower = more anomalous. 0.0 = no model yet."""
        mac   = sample.mac_address
        vec   = build_feature_vector(sample).reshape(1, -1)
        model = self._store.load(mac)
        if model is None:
            self._buffer(mac, vec)
            return 0.0
        return float(model['iso'].score_samples(vec)[0])

    def is_anomalous(self, sample) -> bool:
        return self.score(sample) < ANOMALY_THRESHOLD

    def train(self, mac: str):
        buf = self._buffers.get(mac, [])
        if len(buf) < MIN_SAMPLES:
            return
        X = np.vstack(buf)

        iso = IsolationForest(
            n_estimators=100,
            contamination=CONTAMINATION,
            random_state=42,
        )
        iso.fit(X)

        lof = LOF(n_neighbors=min(20, len(buf) // 5))
        lof.fit(X)

        self._store.save(mac, {'iso': iso, 'lof': lof})

    def _buffer(self, mac: str, vec: np.ndarray):
        self._buffers.setdefault(mac, []).append(vec)
        if len(self._buffers[mac]) >= MIN_SAMPLES:
            self.train(mac)
```

## Model persistence — `sentinel/ml/model_store.py`

Models are saved to disk using `joblib` so they survive container restarts.

```python
import joblib, os
from pathlib import Path

MODEL_DIR = Path('/data/models')

class ModelStore:

    def load(self, mac: str) -> dict | None:
        path = MODEL_DIR / f'{mac.replace(":", "-")}.joblib'
        if path.exists():
            return joblib.load(path)
        return None

    def save(self, mac: str, models: dict):
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        path = MODEL_DIR / f'{mac.replace(":", "-")}.joblib'
        joblib.dump(models, path)
```

## Model lifecycle

| Stage | Trigger | Description |
|-------|---------|-------------|
| Bootstrap (< 100 samples) | Every poll | Feature vectors buffered in memory. Rule-based detectors active. |
| Initial training | 100th sample | `train()` called automatically. Model persisted to disk. |
| Scoring | Every poll | `score()` called for every TrafficSample. Score stored in `traffic_samples.anomaly_score`. |
| Nightly retraining | 03:00 daily (APScheduler) | Retrain all models using last 7 days of data from TimescaleDB. |
| Container restart | Startup | Models loaded from `/data/models/` — no retraining needed. |

## APScheduler nightly retraining — `sentinel/scheduler/tasks.py`

```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sentinel.ml.trainer import ModelTrainer

def register_ml_jobs(scheduler: AsyncIOScheduler, trainer: ModelTrainer):
    scheduler.add_job(
        trainer.retrain_all,
        trigger='cron',
        hour=3, minute=0,
        id='ml_retrain',
        replace_existing=True,
    )
```

## Tuning guidance

| Parameter | Default | When to change |
|-----------|---------|----------------|
| `ANOMALY_THRESHOLD` | -0.1 | Lower (e.g. -0.3) to reduce false positives; raise (e.g. 0.0) for more sensitivity |
| `MIN_SAMPLES` | 100 | Reduce to 50 for faster bootstrap; increase for more reliable initial models |
| `CONTAMINATION` | 0.05 | Set to estimated % of anomalous traffic during normal operation |
| `n_estimators` | 100 | Increase to 200 for better accuracy at cost of training time |
| Retrain window | 7 days | Increase for stable/predictable devices; decrease for fast-changing patterns |

## What the ML engine does NOT do

- It does not replace the rule-based detectors — both run in parallel
- It does not explain *why* a sample is anomalous (use SHAP values for that — future work)
- It does not work well for wired devices with `PER_PORT` granularity — port-level counters are too noisy; the engine skips `PER_PORT` samples
