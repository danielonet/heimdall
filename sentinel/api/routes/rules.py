"""Detection rule routes: CRUD + dry-run test."""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import select

from sentinel.api.serializers import rule_to_dict
from sentinel.db.models import Device, Rule, TrafficSample
from sentinel.db.session import get_session
from sentinel.detection.rules_engine import evaluate_condition

bp = Blueprint('rules', __name__)

_DRY_RUN_SAMPLE_SIZE = 100
_DRY_RUN_MAX_MATCHES_RETURNED = 20


@bp.route('', methods=['GET'])
async def list_rules():
    """All user-defined detection rules."""
    async with get_session() as session:
        rules = (await session.execute(select(Rule).order_by(Rule.created_at.desc()))).scalars().all()
    return jsonify(rules=[rule_to_dict(r) for r in rules])


@bp.route('', methods=['POST'])
@jwt_required()
async def create_rule():
    """Create a new rule."""
    body = request.get_json(silent=True) or {}

    for field in ('name', 'condition_json', 'action_json'):
        if field not in body:
            return jsonify(error=f'Missing required field: {field}'), 400

    async with get_session() as session:
        rule = Rule(
            name=body['name'],
            condition_json=body['condition_json'],
            action_json=body['action_json'],
            enabled=bool(body.get('enabled', True)),
        )
        session.add(rule)
        await session.flush()
        payload = rule_to_dict(rule)

    return jsonify(payload), 201


@bp.route('/<int:rule_id>', methods=['PUT'])
@jwt_required()
async def update_rule(rule_id: int):
    """Update a rule."""
    body = request.get_json(silent=True) or {}

    async with get_session() as session:
        rule = await session.get(Rule, rule_id)
        if rule is None:
            return jsonify(error='Rule not found'), 404

        if 'name' in body:
            rule.name = body['name']
        if 'condition_json' in body:
            rule.condition_json = body['condition_json']
        if 'action_json' in body:
            rule.action_json = body['action_json']
        if 'enabled' in body:
            rule.enabled = bool(body['enabled'])

        payload = rule_to_dict(rule)

    return jsonify(payload)


@bp.route('/<int:rule_id>', methods=['DELETE'])
@jwt_required()
async def delete_rule(rule_id: int):
    async with get_session() as session:
        rule = await session.get(Rule, rule_id)
        if rule is None:
            return jsonify(error='Rule not found'), 404
        await session.delete(rule)

    return '', 204


@bp.route('/<int:rule_id>/test', methods=['POST'])
@jwt_required()
async def test_rule(rule_id: int):
    """Dry-run a rule's condition against recent traffic/device data.

    Read-only: evaluates the condition only, never executes the rule's
    action, persists nothing. Field names in condition_json map directly to
    ORM column names, so rows can be passed straight into evaluate_condition().
    """
    async with get_session() as session:
        rule = await session.get(Rule, rule_id)
        if rule is None:
            return jsonify(error='Rule not found'), 404

        trigger = rule.condition_json.get('trigger', 'TRAFFIC_SAMPLE')
        if trigger == 'DEVICE_SNAPSHOT':
            rows = (await session.execute(
                select(Device).order_by(Device.last_seen.desc()).limit(_DRY_RUN_SAMPLE_SIZE)
            )).scalars().all()
        else:
            # PER_PORT rows aren't attributable to one device — the live RuleEngine
            # skips them for TRAFFIC_SAMPLE rules (see rules_engine.process_traffic),
            # so the dry run must match that or it'll "find" matches on port aliases.
            rows = (await session.execute(
                select(TrafficSample)
                .where(TrafficSample.granularity == 'per_device')
                .order_by(TrafficSample.time.desc())
                .limit(_DRY_RUN_SAMPLE_SIZE)
            )).scalars().all()

    matches = []
    for row in rows:
        matched, actual = evaluate_condition(rule.condition_json, row)
        if matched:
            matches.append({
                'mac_address': row.mac_address,
                'actual_value': actual,
                'time': row.time.isoformat() if trigger != 'DEVICE_SNAPSHOT' else None,
            })

    return jsonify(
        rule_id=rule_id,
        trigger=trigger,
        evaluated=len(rows),
        matched=len(matches),
        matches=matches[:_DRY_RUN_MAX_MATCHES_RETURNED],
    )
