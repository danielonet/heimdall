"""Reports route: the on-demand equivalent of the daily digest email,
scoped to whatever date range/device the user picks instead of always
[last_digest_sent_at, now) x every device. See sentinel/notifications/
digest_query.py, which both this route and the scheduled email job build
on — one shared query, two presentations (JSON here, rendered text/HTML
there).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from sentinel.api.serializers import digest_data_to_dict
from sentinel.db.session import get_session
from sentinel.notifications.digest_query import build_digest_data

bp = Blueprint('reports', __name__)


def _parse_timestamp(value: str | None) -> datetime | None:
    # Same permissive fromisoformat parse as alerts.py's own _parse_
    # timestamp — not shared/imported since that one's module-private and
    # this route's fallback-on-missing behavior below is its own thing.
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


@bp.route('', methods=['GET'])
async def get_report():
    """?start=<iso>&end=<iso>&device_mac=<mac> — start/end default to the
    last 24h (the Reports tab's own default view) when omitted or
    unparseable, matching this endpoint being safe to hit with no params
    at all for a quick check. No result caps (max_alert_types etc. all
    None) — unlike the email this feeds a scrollable page, not a fixed-
    width inbox, so nothing needs truncating the way MAX_ALERT_TYPES/
    MAX_TRAFFIC_DEVICES/MAX_BANDWIDTH_HOURS bound the email."""
    end = _parse_timestamp(request.args.get('end')) or datetime.now(timezone.utc)
    start = _parse_timestamp(request.args.get('start')) or (end - timedelta(hours=24))

    if start >= end:
        return jsonify(error='start must be before end'), 400

    device_mac = request.args.get('device_mac') or None

    async with get_session() as session:
        digest = await build_digest_data(
            session, start, end, device_mac=device_mac,
            max_alert_types=None, max_traffic_devices=None, max_bandwidth_hours=None,
        )

    return jsonify(**digest_data_to_dict(digest))
