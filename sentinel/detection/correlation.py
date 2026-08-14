"""Cross-alert correlation — recognizes a small, curated set of "alert X
followed by alert Y for the same device" patterns and escalates them to a
single higher-severity incident.

`RuleEngine` (sentinel/detection/rules_engine.py) can't express this: its
condition model evaluates one live DeviceSnapshot/TrafficSample per poll,
with no concept of the alerts table at all. This is a genuinely different
shape of check — a windowed lookback over *persisted* Alert rows — so it's
a standalone component, not an extension of RuleEngine.

Also deliberately NOT hooked into _raise_threat_alert: that's only one of
several alert-creation paths (NEW_DEVICE and five other types come from
DetectionPipeline/poll_cycle directly, RULE_TRIGGERED from RuleEngine,
HONEYPOT_ACCESS from OpenCanaryIngester — none of which route through
_raise_threat_alert). A correlator that only watched _raise_threat_alert
would miss NEW_DEVICE entirely, so it instead queries the alerts table
directly on its own schedule (see SentinelScheduler._correlation_job).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TypedDict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.db.models import Alert

# Curated, not an open-ended pattern language — same "small data-driven set"
# style as HIGH_RISK_PORTS (sentinel/security/scanner.py) or
# _ACCESS_POINT_ALIASES (xmo_adapter.py). Add a new pattern here rather than
# building a rule-authoring UI for this; the value is in catching the few
# chains that are unambiguously worse together than apart.
CORRELATION_PATTERNS = [
    {
        'name': 'NEW_DEVICE_THEN_SPOOFING',
        'trigger_types': {'NEW_DEVICE'},
        'follow_types': {'ARP_SPOOF', 'FINGERPRINT_MISMATCH', 'OS_FINGERPRINT_CONFLICT'},
        'window_minutes': 60,
        'description': (
            'connected as a new device and then showed signs of spoofing or '
            'identity mismatch within the hour'
        ),
    },
    {
        'name': 'EXPOSURE_THEN_COMPROMISE',
        'trigger_types': {'VULNERABILITY_DETECTED', 'CREDENTIAL_EXPOSURE_DETECTED', 'HIGH_RISK_PORT_OPENED'},
        'follow_types': {'MALWARE_DETECTED', 'C2_BEACONING'},
        'window_minutes': 1440,  # 24h — a known weakness followed by real compromise signs
        'description': (
            'had a known vulnerability/exposed credential/high-risk port and then '
            'showed signs of active compromise'
        ),
    },
]

# How far back to look for trigger alerts at all — bounds the query
# regardless of any single pattern's window_minutes (the longest window
# above is 24h; this gives a little headroom without scanning the whole
# table on every scan).
_LOOKBACK_HOURS = 48


class Incident(TypedDict):
    mac: str
    pattern_name: str
    description: str
    trigger_alert_id: int
    follow_alert_id: int


class CrossAlertCorrelator:
    """Stateless between calls — every check re-derives "already correlated"
    from the alerts table itself (see _already_correlated), so nothing needs
    to survive a process restart."""

    async def find_new_incidents(self, session: AsyncSession) -> list[Incident]:
        lookback_cutoff = datetime.now(timezone.utc) - timedelta(hours=_LOOKBACK_HOURS)
        incidents: list[Incident] = []

        for pattern in CORRELATION_PATTERNS:
            triggers = (await session.execute(
                select(Alert)
                .where(
                    Alert.alert_type.in_(pattern['trigger_types']),
                    Alert.device_mac.isnot(None),
                    # last_seen, not created_at — AlertRepository.upsert()
                    # touches (rather than re-inserts) a still-recurring
                    # trigger alert, so created_at is set once at first
                    # occurrence and never advances. Filtering on created_at
                    # here would let a still-active trigger silently fall
                    # out of the lookback window the moment it's more than
                    # _LOOKBACK_HOURS old, even though it's still recurring.
                    Alert.last_seen >= lookback_cutoff,
                )
                .order_by(Alert.created_at)
            )).scalars().all()

            for trigger in triggers:
                window_end = trigger.created_at + timedelta(minutes=pattern['window_minutes'])
                candidates = (await session.execute(
                    select(Alert)
                    .where(
                        Alert.alert_type.in_(pattern['follow_types']),
                        Alert.device_mac == trigger.device_mac,
                        Alert.created_at >= trigger.created_at,
                        Alert.created_at <= window_end,
                    )
                    .order_by(Alert.created_at)
                )).scalars().all()

                # Walk candidates oldest-first and take the first one that
                # hasn't already produced an incident — an already-correlated
                # earlier candidate must not block a later, fresh one from
                # the same trigger (see _already_correlated's docstring).
                follow = None
                for candidate in candidates:
                    if not await self._already_correlated(session, candidate.id):
                        follow = candidate
                        break
                if follow is None:
                    continue

                incidents.append({
                    'mac': trigger.device_mac,
                    'pattern_name': pattern['name'],
                    'description': pattern['description'],
                    'trigger_alert_id': trigger.id,
                    'follow_alert_id': follow.id,
                })

        return incidents

    async def _already_correlated(self, session: AsyncSession, follow_alert_id: int) -> bool:
        """True if this specific follow-alert has already produced a
        COMPROMISE_CHAIN_DETECTED incident — prevents the same pair from
        re-firing on every scan, while still allowing a *different*, later
        follow-alert on the same device to produce a fresh incident."""
        existing = (await session.execute(
            select(Alert.id).where(
                Alert.alert_type == 'COMPROMISE_CHAIN_DETECTED',
                Alert.raw_data['follow_alert_id'].astext == str(follow_alert_id),
            )
        )).first()
        return existing is not None
