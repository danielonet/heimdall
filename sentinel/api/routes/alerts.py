"""Alert routes: list, detail, acknowledge, delete, export."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import case, delete, func, select, update

from sentinel.api.serializers import alert_to_dict
from sentinel.db.models import Alert, Device
from sentinel.db.session import get_session

bp = Blueprint('alerts', __name__)

MAX_PER_PAGE = 200
MAX_EXPORT_ROWS = 50_000

# Ordinal so func.max() picks the worst severity present in a group — plain
# alphabetical order (CRITICAL < INFO < WARNING) would pick the wrong one.
_SEVERITY_RANK = case(
    (Alert.severity == 'CRITICAL', 3),
    (Alert.severity == 'WARNING', 2),
    (Alert.severity == 'INFO', 1),
    else_=0,
)
_RANK_TO_SEVERITY = {3: 'CRITICAL', 2: 'WARNING', 1: 'INFO'}


@bp.route('', methods=['GET'])
async def list_alerts():
    """Paginated alert list, filterable by severity, device_mac, acknowledged, from, to.

    from/to filter on last_seen, not created_at — the Dashboard's staleness
    cutoff (see frontend/src/lib/alertStaleness.js:staleBeforeIso) uses this
    same `from` param to hide alerts with no recent activity. Since
    AlertRepository.upsert() touches (rather than re-inserts) a still-
    recurring alert, created_at is set once at first occurrence and never
    advances — filtering on it would wrongly hide/exclude an alert that's
    still actively recurring today just because it first fired outside the
    window. Same reasoning as CrossAlertCorrelator's last_seen fix.
    """
    page = max(request.args.get('page', 1, type=int), 1)
    per_page = min(request.args.get('per_page', 50, type=int), MAX_PER_PAGE)

    query = select(Alert)
    count_query = select(func.count()).select_from(Alert)

    severity = request.args.get('severity')
    if severity:
        query = query.where(Alert.severity == severity)
        count_query = count_query.where(Alert.severity == severity)

    device_mac = request.args.get('device_mac')
    if device_mac:
        query = query.where(Alert.device_mac == device_mac)
        count_query = count_query.where(Alert.device_mac == device_mac)

    acknowledged = request.args.get('acknowledged')
    if acknowledged is not None:
        flag = acknowledged.lower() in ('true', '1')
        query = query.where(Alert.acknowledged.is_(flag))
        count_query = count_query.where(Alert.acknowledged.is_(flag))

    from_ts = _parse_timestamp(request.args.get('from'))
    if from_ts:
        query = query.where(Alert.last_seen >= from_ts)
        count_query = count_query.where(Alert.last_seen >= from_ts)

    to_ts = _parse_timestamp(request.args.get('to'))
    if to_ts:
        query = query.where(Alert.last_seen <= to_ts)
        count_query = count_query.where(Alert.last_seen <= to_ts)

    query = query.order_by(Alert.created_at.desc()).limit(per_page).offset((page - 1) * per_page)

    async with get_session() as session:
        alerts = (await session.execute(query)).scalars().all()
        total = (await session.execute(count_query)).scalar_one()

    return jsonify(
        alerts=[alert_to_dict(a) for a in alerts],
        page=page,
        per_page=per_page,
        total=total,
    )


@bp.route('', methods=['DELETE'])
@jwt_required()
async def delete_all_alerts():
    """Clears the entire alert feed. Devices, trust decisions, traffic
    history, and trained ML models are untouched — detectors keep running
    against the same data and simply start from an empty feed, no re-learning
    involved. The lighter sibling to POST /settings/purge, which resets the
    learned baseline too."""
    async with get_session() as session:
        result = await session.execute(delete(Alert))
    return jsonify(deleted=result.rowcount)


@bp.route('/grouped', methods=['GET'])
async def list_alerts_grouped():
    """Alerts collapsed into (device_mac, alert_type) groups with counts —
    for triaging a flood (e.g. a misfiring detector producing thousands of
    rows for the same device) without paging through every individual alert."""
    query = (
        select(
            Alert.device_mac,
            Device.hostname,
            Alert.alert_type,
            func.count().label('count'),
            func.sum(case((Alert.acknowledged.is_(False), 1), else_=0)).label('unacknowledged_count'),
            func.sum(case((Alert.resolved.is_(False), 1), else_=0)).label('unresolved_count'),
            func.max(_SEVERITY_RANK).label('severity_rank'),
            func.min(Alert.created_at).label('first_seen'),
            func.max(Alert.created_at).label('last_seen'),
        )
        .outerjoin(Device, Device.mac_address == Alert.device_mac)
        .group_by(Alert.device_mac, Device.hostname, Alert.alert_type)
    )

    severity = request.args.get('severity')
    if severity:
        query = query.where(Alert.severity == severity)

    acknowledged = request.args.get('acknowledged')
    if acknowledged is not None:
        flag = acknowledged.lower() in ('true', '1')
        query = query.where(Alert.acknowledged.is_(flag))

    resolved = request.args.get('resolved')
    if resolved is not None:
        flag = resolved.lower() in ('true', '1')
        query = query.where(Alert.resolved.is_(flag))

    from_ts = _parse_timestamp(request.args.get('from'))
    if from_ts:
        query = query.where(Alert.created_at >= from_ts)

    query = query.order_by(func.count().desc())

    async with get_session() as session:
        rows = (await session.execute(query)).all()

    groups = [
        {
            'device_mac': row.device_mac,
            'hostname': row.hostname,
            'alert_type': row.alert_type,
            'severity': _RANK_TO_SEVERITY.get(row.severity_rank, 'INFO'),
            'count': row.count,
            'unacknowledged_count': row.unacknowledged_count,
            'unresolved_count': row.unresolved_count,
            'first_seen': row.first_seen.isoformat() if row.first_seen else None,
            'last_seen': row.last_seen.isoformat() if row.last_seen else None,
        }
        for row in rows
    ]

    return jsonify(groups=groups)


@bp.route('/export', methods=['GET'])
async def export_alerts():
    """CSV export of alerts matching the same filters list_alerts() accepts
    (severity, device_mac, acknowledged, resolved, from, to) — no pagination,
    up to MAX_EXPORT_ROWS, for record-keeping/audit trail purposes (e.g.
    attaching to a pentest report) rather than incremental UI browsing.
    """
    query = select(Alert, Device.hostname).outerjoin(Device, Device.mac_address == Alert.device_mac)

    severity = request.args.get('severity')
    if severity:
        query = query.where(Alert.severity == severity)

    device_mac = request.args.get('device_mac')
    if device_mac:
        query = query.where(Alert.device_mac == device_mac)

    acknowledged = request.args.get('acknowledged')
    if acknowledged is not None:
        query = query.where(Alert.acknowledged.is_(acknowledged.lower() in ('true', '1')))

    resolved = request.args.get('resolved')
    if resolved is not None:
        query = query.where(Alert.resolved.is_(resolved.lower() in ('true', '1')))

    from_ts = _parse_timestamp(request.args.get('from'))
    if from_ts:
        query = query.where(Alert.last_seen >= from_ts)  # see list_alerts' docstring

    to_ts = _parse_timestamp(request.args.get('to'))
    if to_ts:
        query = query.where(Alert.last_seen <= to_ts)

    query = query.order_by(Alert.created_at.desc()).limit(MAX_EXPORT_ROWS)

    async with get_session() as session:
        rows = (await session.execute(query)).all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        'id', 'created_at', 'last_seen', 'occurrence_count', 'severity', 'alert_type', 'device_mac', 'hostname',
        'description', 'acknowledged', 'acknowledged_at', 'resolved', 'resolved_at',
    ])
    for alert, hostname in rows:
        writer.writerow([
            alert.id,
            alert.created_at.isoformat() if alert.created_at else '',
            alert.last_seen.isoformat() if alert.last_seen else '',
            alert.occurrence_count,
            alert.severity,
            alert.alert_type,
            alert.device_mac or '',
            hostname or '',
            alert.description or '',
            alert.acknowledged,
            alert.acknowledged_at.isoformat() if alert.acknowledged_at else '',
            alert.resolved,
            alert.resolved_at.isoformat() if alert.resolved_at else '',
        ])

    filename = f'heimdall-alerts-{datetime.now().strftime("%Y%m%d-%H%M%S")}.csv'
    return Response(
        buffer.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@bp.route('/bulk', methods=['PATCH'])
async def bulk_patch_alerts():
    """Acknowledge or resolve every alert matching a filter in one query —
    the group-triage counterpart to PATCH /alerts/<id>. Body must include
    device_mac and/or alert_type (refusing to touch the whole table by
    accident) plus acknowledged and/or resolved."""
    body = request.get_json(silent=True) or {}

    device_mac = body.get('device_mac')
    alert_type = body.get('alert_type')
    if not device_mac and not alert_type:
        return jsonify(error='device_mac or alert_type is required'), 400

    now = datetime.now(timezone.utc)
    values = {}
    if 'acknowledged' in body:
        acknowledged = bool(body['acknowledged'])
        values['acknowledged'] = acknowledged
        values['acknowledged_at'] = now if acknowledged else None
    if 'resolved' in body:
        resolved = bool(body['resolved'])
        values['resolved'] = resolved
        values['resolved_at'] = now if resolved else None
    if not values:
        return jsonify(error='acknowledged or resolved is required'), 400

    stmt = update(Alert).values(**values)
    if device_mac:
        stmt = stmt.where(Alert.device_mac == device_mac)
    if alert_type:
        stmt = stmt.where(Alert.alert_type == alert_type)

    async with get_session() as session:
        result = await session.execute(stmt)

    return jsonify(updated=result.rowcount)


@bp.route('/<int:alert_id>', methods=['GET'])
async def get_alert(alert_id: int):
    """Single alert detail."""
    async with get_session() as session:
        alert = await session.get(Alert, alert_id)
        if alert is None:
            return jsonify(error='Alert not found'), 404
        return jsonify(alert_to_dict(alert))


@bp.route('/<int:alert_id>', methods=['PATCH'])
async def patch_alert(alert_id: int):
    """Acknowledge or resolve an alert — body: {"acknowledged": true} or {"resolved": true}.

    Also the REOPEN path: {"resolved": false} on an already-resolved alert
    — needed now that `resolved` can flip automatically post-lifecycle-
    redesign (a detector's resolve() call, or the alert_auto_resolve sweep),
    not just via a deliberate human action, so there must be a way back
    from a wrong auto-resolve. No new endpoint needed — this already
    accepted the same body shape before the redesign.
    """
    body = request.get_json(silent=True) or {}
    now = datetime.now(timezone.utc)

    async with get_session() as session:
        alert = await session.get(Alert, alert_id)
        if alert is None:
            return jsonify(error='Alert not found'), 404

        if 'acknowledged' in body:
            alert.acknowledged = bool(body['acknowledged'])
            alert.acknowledged_at = now if alert.acknowledged else None
        if 'resolved' in body:
            alert.resolved = bool(body['resolved'])
            alert.resolved_at = now if alert.resolved else None

        payload = alert_to_dict(alert)

    return jsonify(payload)


@bp.route('/<int:alert_id>', methods=['DELETE'])
@jwt_required()
async def delete_alert(alert_id: int):
    async with get_session() as session:
        alert = await session.get(Alert, alert_id)
        if alert is None:
            return jsonify(error='Alert not found'), 404
        await session.delete(alert)

    return '', 204


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
