"""Converts a TrafficSample into the feature vector the anomaly models train on."""
from __future__ import annotations

import numpy as np

from sentinel.adapter.models import TrafficSample

FEATURE_NAMES = [
    'throughput_up_kbps',      # upload speed
    'throughput_dn_kbps',      # download speed
    'upload_download_ratio',   # up/down — high sustained ratio = possible exfil
    'hour_of_day',              # 0-23 — catches off-hours activity
    'day_of_week',               # 0-6 (Mon=0)
    'is_night',                  # 1 if 22:00-06:00, else 0
]


def build_feature_vector(sample: TrafficSample) -> np.ndarray:
    """Build the 6-dimensional feature vector for one TrafficSample.

    Per docs/architecture/05-ml-anomaly-engine.md — models are trained per
    device, so absolute throughput values are meaningful only relative to
    that one device's own history.
    """
    ts = sample.timestamp
    up = sample.throughput_up_kbps
    down = sample.throughput_dn_kbps
    ratio = up / max(down, 1)
    return np.array([
        up,
        down,
        ratio,
        ts.hour,
        ts.weekday(),
        1 if ts.hour >= 22 or ts.hour < 6 else 0,
    ], dtype=float)
