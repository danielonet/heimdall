"""Port stats routes: PHY1-PHY5 current + history."""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from sqlalchemy import select

from sentinel.api.serializers import port_stats_to_dict
from sentinel.db.models import PortStats
from sentinel.db.session import get_session

bp = Blueprint('ports', __name__)

DEFAULT_HISTORY_LIMIT = 100
MAX_HISTORY_LIMIT = 1000


@bp.route('', methods=['GET'])
async def list_ports():
    """Current PHY1-PHY5 stats with throughput deltas and status (latest row per port)."""
    async with get_session() as session:
        ports = (await session.execute(
            select(PortStats)
            .distinct(PortStats.port_alias)
            .order_by(PortStats.port_alias, PortStats.time.desc())
        )).scalars().all()

    return jsonify(ports=[port_stats_to_dict(p) for p in ports])


@bp.route('/<alias>', methods=['GET'])
async def get_port_history(alias: str):
    """History for a specific port (e.g. PHY5)."""
    limit = min(request.args.get('limit', DEFAULT_HISTORY_LIMIT, type=int), MAX_HISTORY_LIMIT)

    async with get_session() as session:
        history = (await session.execute(
            select(PortStats)
            .where(PortStats.port_alias == alias)
            .order_by(PortStats.time.desc())
            .limit(limit)
        )).scalars().all()

    if not history:
        return jsonify(error='Port not found or has no history'), 404

    return jsonify(port_alias=alias, history=[port_stats_to_dict(p) for p in history])
