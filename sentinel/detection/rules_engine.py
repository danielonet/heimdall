"""Evaluates user-defined rules (the `rules` table) against every device/traffic
event, alongside the detector pipeline. See docs/architecture/04-detection-pipeline.md
for the rule schema.

Rule JSON shape (condition_json / action_json columns):

    condition_json = {
        "trigger": "TRAFFIC_SAMPLE",   # or "DEVICE_SNAPSHOT" — which event this rule watches
        "field": "throughput_up_kbps", # attribute name on the TrafficSample/DeviceSnapshot
        "op": "GT",                    # GT | LT | GTE | LTE | EQ | NEQ | CONTAINS | IN
        "value": 5120,
        "window_polls": 3              # optional: must match this many consecutive polls (default 1)
    }
    action_json = {
        "type": "BLOCK_DEVICE",        # ALERT | BLOCK_DEVICE | NOTIFY | TAG_DEVICE | RATE_LIMIT
        "notify": true,                # optional: also send a notification regardless of type
        "severity": "CRITICAL",        # optional, default WARNING
        "tag": "flagged",              # TAG_DEVICE only
        "minutes": 30                  # RATE_LIMIT only — how long to go quiet after firing
    }

The doc's own rule example nests "trigger" at the top level of the rule, but
the rules table only has condition_json/action_json columns (no separate
trigger column) — so it lives inside condition_json instead.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity, TrafficSample
from sentinel.api.serializers import alert_to_dict
from sentinel.api.websocket import emit_alert
from sentinel.db.models import Alert, Device, Rule
from sentinel.db.session import get_session
from sentinel.notifications.service import NotificationService

logger = logging.getLogger(__name__)

_OPERATORS = {
    'GT': lambda a, b: a is not None and a > b,
    'LT': lambda a, b: a is not None and a < b,
    'GTE': lambda a, b: a is not None and a >= b,
    'LTE': lambda a, b: a is not None and a <= b,
    'EQ': lambda a, b: a == b,
    'NEQ': lambda a, b: a != b,
    'CONTAINS': lambda a, b: a is not None and b in a,
    'IN': lambda a, b: bool(b) and a in b,
}


def evaluate_condition(condition: dict, obj: Any) -> tuple[bool, Any]:
    """Pure condition check: does obj.<field> <op> value? Returns (matched, actual_value).

    Used both by the live RuleEngine and the read-only dry-run test endpoint —
    neither needs to touch DB/network state to answer this question.
    """
    field = condition.get('field')
    op = condition.get('op')
    value = condition.get('value')

    actual = getattr(obj, field, None)
    comparator = _OPERATORS.get(op)
    if comparator is None:
        logger.warning('Unknown rule operator: %s', op)
        return False, actual

    try:
        return bool(comparator(actual, value)), actual
    except TypeError:
        # e.g. comparing incompatible types (GT on a string) — not a match, not a crash.
        return False, actual


class RuleEngine:
    """Loads enabled rules once per poll cycle and evaluates them against each event."""

    def __init__(self, adapter: RouterAdapter, notifier: NotificationService) -> None:
        self._adapter = adapter
        self._notifier = notifier
        self._rules: list[Rule] = []
        self._streaks: dict[tuple[int, str], int] = {}           # (rule_id, mac) -> consecutive matches
        self._rate_limited_until: dict[tuple[int, str], datetime] = {}

    async def load_active_rules(self) -> None:
        """Refresh the rule list. Call once per poll cycle — not once per device/sample."""
        async with get_session() as session:
            result = await session.execute(select(Rule).where(Rule.enabled.is_(True)))
            self._rules = list(result.scalars().all())

    async def process_device(self, snapshot: DeviceSnapshot) -> None:
        for rule in self._rules:
            if rule.condition_json.get('trigger', 'DEVICE_SNAPSHOT') != 'DEVICE_SNAPSHOT':
                continue
            await self._evaluate(rule, snapshot.mac_address, snapshot, snapshot)

    async def process_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> None:
        if sample.granularity != TrafficGranularity.PER_DEVICE:
            return  # port aggregates aren't attributable to one device — same rule as detectors
        for rule in self._rules:
            if rule.condition_json.get('trigger', 'TRAFFIC_SAMPLE') != 'TRAFFIC_SAMPLE':
                continue
            await self._evaluate(rule, sample.mac_address, sample, snapshot)

    async def _evaluate(
        self, rule: Rule, mac: str, obj: Any, snapshot: Optional[DeviceSnapshot]
    ) -> None:
        key = (rule.id, mac)

        now = datetime.now(timezone.utc)
        if self._rate_limited_until.get(key, now) > now:
            return  # still quiet from a previous RATE_LIMIT fire

        matched, actual = evaluate_condition(rule.condition_json, obj)
        if not matched:
            self._streaks[key] = 0
            return

        window_polls = rule.condition_json.get('window_polls', 1)
        streak = self._streaks.get(key, 0) + 1
        self._streaks[key] = streak
        if streak < window_polls:
            return  # matched, but not sustained long enough yet

        self._streaks[key] = 0  # reset so the next fire needs its own fresh streak
        await self._fire(rule, mac, snapshot, actual)

    async def _fire(
        self, rule: Rule, mac: str, snapshot: Optional[DeviceSnapshot], actual_value: Any
    ) -> None:
        action = rule.action_json
        action_type = action.get('type')
        severity = action.get('severity', 'WARNING')
        hostname = snapshot.hostname if snapshot else None
        field = rule.condition_json.get('field')
        description = f'Rule "{rule.name}" triggered for {hostname or mac} ({field} = {actual_value})'

        if action_type == 'ALERT':
            await self._create_alert(rule, mac, severity, description)
        elif action_type == 'BLOCK_DEVICE':
            await self._block_device(mac)
            await self._create_alert(rule, mac, severity, description + ' — device blocked')
        elif action_type == 'TAG_DEVICE':
            await self._tag_device(mac, action.get('tag', 'flagged'))
        elif action_type == 'NOTIFY':
            await self._create_alert(rule, mac, severity, description)
            await self._notifier.notify(title=rule.name, message=description, severity=severity)
        elif action_type == 'RATE_LIMIT':
            minutes = action.get('minutes', 30)
            self._rate_limited_until[(rule.id, mac)] = datetime.now(timezone.utc) + timedelta(minutes=minutes)
            await self._create_alert(rule, mac, severity, description)
        else:
            logger.warning('Rule %s has unknown action type %r', rule.name, action_type)
            return

        # The "notify" modifier can ride along with any action type (matches the
        # docs' own example: {"type": "BLOCK_DEVICE", "notify": true, ...}).
        if action.get('notify') and action_type != 'NOTIFY':
            await self._notifier.notify(title=rule.name, message=description, severity=severity)

        await self._mark_triggered(rule.id)

    async def _create_alert(self, rule: Rule, mac: str, severity: str, description: str) -> None:
        async with get_session() as session:
            alert = Alert(
                device_mac=mac,
                alert_type='RULE_TRIGGERED',
                severity=severity,
                description=description,
                raw_data={'rule_id': rule.id, 'rule_name': rule.name},
            )
            session.add(alert)
        emit_alert(alert_to_dict(alert))

    async def _block_device(self, mac: str) -> None:
        try:
            await self._adapter.block_device(mac)
            async with get_session() as session:
                device = await session.get(Device, mac)
                if device is not None:
                    device.is_blocked = True
        except Exception:
            logger.exception('Rule action BLOCK_DEVICE failed for %s', mac)

    async def _tag_device(self, mac: str, tag: str) -> None:
        async with get_session() as session:
            device = await session.get(Device, mac)
            if device is not None:
                tags = set(device.tags or [])
                tags.add(tag)
                device.tags = list(tags)

    async def _mark_triggered(self, rule_id: int) -> None:
        async with get_session() as session:
            rule = await session.get(Rule, rule_id)
            if rule is not None:
                rule.last_triggered = datetime.now(timezone.utc)
