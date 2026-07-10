"""Detection rule routes: CRUD + dry-run test.

The dry-run test endpoint (POST /<id>/test) needs sentinel/detection/rules_engine.py
to actually evaluate a rule against recent traffic — that engine doesn't exist
yet (see docs/architecture/04-detection-pipeline.md), so it returns 501 for now.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import select

from sentinel.api.serializers import rule_to_dict
from sentinel.db.models import Rule
from sentinel.db.session import get_session

bp = Blueprint('rules', __name__)


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
    """Dry-run a rule against recent traffic. Not implemented — needs the rules engine."""
    async with get_session() as session:
        rule = await session.get(Rule, rule_id)
        if rule is None:
            return jsonify(error='Rule not found'), 404

    return jsonify(error='Rule dry-run testing is not implemented yet'), 501
