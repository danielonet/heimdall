"""Per-device-type overrides for detector thresholds.

`Device.device_type` (`sentinel/adapter/models.py:DeviceSnapshot.device_type`)
is *not* a closed enum — it's whatever string the router's own DHCP-
fingerprint database returns (e.g. 'Smartphone', 'Network Attached
Storage'), blank when it can't classify a device at all.

Overrides themselves are admin-editable, DB-backed rows (see
sentinel.db.models.DeviceTypeProfile / sentinel.db.repositories.
DeviceTypeProfileRepository) — this module now only holds the fallback
DEFAULT_PROFILE and a thin async wrapper, kept here so detector call sites
don't need to know the DB is involved at all.

A NAS or IP camera legitimately sustains a high upload/download ratio
(backups, streaming out); a printer or smartphone doing the same is far
more suspicious. Same reasoning applies to how many consecutive polls of
ML-flagged traffic it takes before AnomalousVolumeDetector fires — a NAS's
traffic pattern is naturally more variable than a printer's. And a device
type prone to short, legitimate, recurring bursts (a phone doing a video
call) benefits from a higher IsolationForest `contamination` on its nightly
retrain — see sentinel/ml/trainer.py's ModelTrainer.retrain_all() — since a
burst that reliably makes up a roughly-fixed share of a device's samples
gets flagged forever at the global default rate, no matter how much history
accumulates.
"""
from __future__ import annotations

DEFAULT_PROFILE = {
    'high_upload_ratio_threshold': 3.0,  # HighUploadDetector's RATIO_THRESHOLD today
    'volume_sustained_polls': 3,  # AnomalousVolumeDetector's SUSTAINED_POLLS today
    'contamination': 0.05,  # matches Settings.ML_CONTAMINATION's global default
}


async def get_profile(device_type: str | None) -> dict:
    """Merges a device-type override onto DEFAULT_PROFILE. Unknown, blank,
    or unrecognized device_type values fall back to DEFAULT_PROFILE
    untouched — the same behavior every device got before the
    device_type_profiles table existed. Thin wrapper so detector call sites
    don't need to import the repository directly.
    """
    from sentinel.db.repositories import DeviceTypeProfileRepository
    return await DeviceTypeProfileRepository().get_profile(device_type)
