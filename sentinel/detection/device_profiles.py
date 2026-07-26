"""Per-device-type overrides for detector thresholds.

`Device.device_type` (`sentinel/adapter/models.py:DeviceSnapshot.device_type`)
is *not* a closed enum — it's whatever string the router's own DHCP-
fingerprint database returns (e.g. 'Smartphone', 'Network Attached
Storage'), blank when it can't classify a device at all. This table is
therefore a plain dict keyed by observed strings with a required default
bucket, not an exhaustive switch over a fixed set of values.

A NAS or IP camera legitimately sustains a high upload/download ratio
(backups, streaming out); a printer or smartphone doing the same is far
more suspicious. Same reasoning applies to how many consecutive polls of
ML-flagged traffic it takes before AnomalousVolumeDetector fires — a NAS's
traffic pattern is naturally more variable than a printer's.
"""
from __future__ import annotations

DEFAULT_PROFILE = {
    'high_upload_ratio_threshold': 3.0,  # HighUploadDetector's RATIO_THRESHOLD today
    'volume_sustained_polls': 3,  # AnomalousVolumeDetector's SUSTAINED_POLLS today
}

DEVICE_TYPE_PROFILES: dict[str, dict] = {
    'Network Attached Storage': {'high_upload_ratio_threshold': 8.0, 'volume_sustained_polls': 5},
    'IP Camera': {'high_upload_ratio_threshold': 10.0, 'volume_sustained_polls': 5},
    'Printer': {'high_upload_ratio_threshold': 2.0, 'volume_sustained_polls': 2},
    'Smartphone': {'high_upload_ratio_threshold': 2.5},
}


def get_profile(device_type: str | None) -> dict:
    """Merges a device-type override onto DEFAULT_PROFILE. Unknown, blank,
    or unrecognized device_type values fall back to DEFAULT_PROFILE
    untouched — the same behavior every device got before this table
    existed."""
    return {**DEFAULT_PROFILE, **DEVICE_TYPE_PROFILES.get(device_type or '', {})}
