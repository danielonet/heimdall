"""Device-type detector-threshold profile routes: list, upsert, revert-to-default.

See sentinel/db/models.py:DeviceTypeProfile and sentinel/db/repositories.py:
DeviceTypeProfileRepository — this is the admin-editable replacement for what
used to be sentinel/detection/device_profiles.py's hardcoded dict.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from sentinel.db.repositories import DeviceTypeProfileRepository
from sentinel.scheduler.scheduler import get_scheduler

bp = Blueprint('device_type_profiles', __name__)

MIN_RATIO_THRESHOLD = 0.1
MAX_RATIO_THRESHOLD = 1000.0
MIN_SUSTAINED_POLLS = 1
MAX_SUSTAINED_POLLS = 100
MIN_CONTAMINATION = 0.001
MAX_CONTAMINATION = 0.5  # IsolationForest itself rejects > 0.5


def _profile_to_dict(row) -> dict:
    return {
        'device_type': row.device_type,
        'high_upload_ratio_threshold': row.high_upload_ratio_threshold,
        'volume_sustained_polls': row.volume_sustained_polls,
        'contamination': row.contamination,
        'updated_at': row.updated_at.isoformat() if row.updated_at else None,
    }


@bp.route('', methods=['GET'])
async def list_profiles():
    """Every device-type override currently in the DB, plus the cached
    observed-extremes reference stats (see sentinel/detection/
    observed_extremes.py) — the highest RATIO/POLLS/CONTAM. actually ever
    measured on this network, refreshed hourly by the scheduler. A
    device_type with no override row here isn't "unsupported" — it just
    falls back to DEFAULT_PROFILE at lookup time (see
    device_profiles.get_profile()); this list only shows what's been
    explicitly tuned."""
    rows = await DeviceTypeProfileRepository().get_all_profiles()
    try:
        observed = get_scheduler().observed_extremes_snapshot()
    except RuntimeError:
        # Scheduler not running (e.g. tests, SCHEDULER_ENABLED=False) — no
        # stats to show yet, not an error.
        observed = {'extremes': None, 'computed_at': None}
    return jsonify(profiles=[_profile_to_dict(r) for r in rows], observed_extremes=observed)


@bp.route('/<device_type>', methods=['PUT'])
@jwt_required()
async def upsert_profile(device_type: str):
    """Create or update one device type's thresholds. Full replacement, not
    a partial patch — all three fields are required, same as the values
    every profile has always had (see DEFAULT_PROFILE)."""
    body = request.get_json(silent=True) or {}

    ratio = body.get('high_upload_ratio_threshold')
    if not isinstance(ratio, (int, float)) or isinstance(ratio, bool) or not (
        MIN_RATIO_THRESHOLD <= ratio <= MAX_RATIO_THRESHOLD
    ):
        return jsonify(
            error=f'high_upload_ratio_threshold must be a number between '
                  f'{MIN_RATIO_THRESHOLD} and {MAX_RATIO_THRESHOLD}'
        ), 400

    polls = body.get('volume_sustained_polls')
    if not isinstance(polls, int) or isinstance(polls, bool) or not (
        MIN_SUSTAINED_POLLS <= polls <= MAX_SUSTAINED_POLLS
    ):
        return jsonify(
            error=f'volume_sustained_polls must be an integer between '
                  f'{MIN_SUSTAINED_POLLS} and {MAX_SUSTAINED_POLLS}'
        ), 400

    contamination = body.get('contamination')
    if not isinstance(contamination, (int, float)) or isinstance(contamination, bool) or not (
        MIN_CONTAMINATION <= contamination <= MAX_CONTAMINATION
    ):
        return jsonify(
            error=f'contamination must be a number between {MIN_CONTAMINATION} and {MAX_CONTAMINATION}'
        ), 400

    row = await DeviceTypeProfileRepository().upsert_profile(
        device_type,
        high_upload_ratio_threshold=float(ratio),
        volume_sustained_polls=polls,
        contamination=float(contamination),
    )
    return jsonify(_profile_to_dict(row))


@bp.route('/<device_type>', methods=['DELETE'])
@jwt_required()
async def delete_profile(device_type: str):
    """Removes the override, reverting this device type to DEFAULT_PROFILE."""
    deleted = await DeviceTypeProfileRepository().delete_profile(device_type)
    if not deleted:
        return jsonify(error=f'No profile override for device_type {device_type!r}'), 404
    return '', 204
