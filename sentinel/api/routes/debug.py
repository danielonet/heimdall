"""Debug routes: memory introspection for tracking down a suspected leak.

Requires MEMORY_DEBUG_ENABLED (see sentinel/config.py) — tracemalloc adds
real overhead, so it's opt-in and only active while someone is actually
hunting a leak, not on every deployment.
"""
from __future__ import annotations

import gc
import logging
import tracemalloc
from collections import Counter

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required

from sentinel.scheduler.scheduler import get_scheduler

logger = logging.getLogger(__name__)

bp = Blueprint('debug', __name__)

_TOP_N = 20


@bp.route('/memory', methods=['GET'])
@jwt_required()
async def memory_diagnostics():
    """Snapshot of process memory right now: RSS, top Python object types by
    count, top allocation sites by size (if tracemalloc is running), and the
    sizes of this app's known-unbounded in-memory collections (see
    SentinelScheduler.memory_diagnostics_snapshot).

    A single snapshot can't tell you much on its own — call this a few times
    spaced minutes apart (or before/after a suspected trigger, e.g. an
    ARP-spoof test) and compare. A count that keeps climbing indefinitely,
    rather than plateauing once the LAN's device population stabilizes, is
    the signal to chase; steady churn as devices come and go is expected.
    """
    top_allocations = []
    tracing = tracemalloc.is_tracing()
    if tracing:
        snapshot = tracemalloc.take_snapshot()
        top_allocations = [
            {
                'location': str(stat.traceback[0]),
                'size_kb': round(stat.size / 1024, 1),
                'count': stat.count,
            }
            for stat in snapshot.statistics('lineno')[:_TOP_N]
        ]

    gc.collect()
    all_objects = gc.get_objects()
    top_object_types = [
        {'type': name, 'count': count}
        for name, count in Counter(type(o).__name__ for o in all_objects).most_common(_TOP_N)
    ]

    try:
        collections = get_scheduler().memory_diagnostics_snapshot()
    except RuntimeError:
        collections = {}

    return jsonify(
        tracemalloc_active=tracing,
        rss_mb=_rss_mb(),
        gc_object_count=len(all_objects),
        top_object_types=top_object_types,
        top_allocations=top_allocations,
        suspect_collections=collections,
    )


def _rss_mb() -> float | None:
    """Current resident set size in MB, read from /proc — this app only
    ever runs in a Linux container/host, so no cross-platform fallback."""
    try:
        with open('/proc/self/status') as f:
            for line in f:
                if line.startswith('VmRSS:'):
                    return round(int(line.split()[1]) / 1024, 1)
    except (OSError, ValueError, IndexError):
        pass
    return None
