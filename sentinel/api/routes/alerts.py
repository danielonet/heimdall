"""Alert routes: list, detail, acknowledge, delete."""
from __future__ import annotations

from datetime import datetime

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import func, select

from sentinel.api.serializers import alert_to_dict
from sentinel.db.models import Alert
from sentinel.db.session import get_session

bp = Blueprint('alerts', __name__)

MAX_PER_PAGE = 200


@bp.route('', methods=['GET'])
async def list_alerts():
    """Paginated alert list, filterable by severity, device_mac, acknowledged, from, to."""
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
        query = query.where(Alert.created_at >= from_ts)
        count_query = count_query.where(Alert.created_at >= from_ts)

    to_ts = _parse_timestamp(request.args.get('to'))
    if to_ts:
        query = query.where(Alert.created_at <= to_ts)
        count_query = count_query.where(Alert.created_at <= to_ts)

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
    """Acknowledge or resolve an alert — body: {"acknowledged": true} or {"resolved": true}."""
    body = request.get_json(silent=True) or {}

    async with get_session() as session:
        alert = await session.get(Alert, alert_id)
        if alert is None:
            return jsonify(error='Alert not found'), 404

        if 'acknowledged' in body:
            alert.acknowledged = bool(body['acknowledged'])
        if 'resolved' in body:
            alert.resolved = bool(body['resolved'])

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
