"""Prometheus-style /metrics endpoint: device counts, alert rates, and poll
latency in the plain-text exposition format Prometheus scrapes directly
(https://prometheus.io/docs/instrumenting/exposition_formats/).

Deliberately unauthenticated, same posture as /api/health — a standard
Prometheus static scrape config has no way to refresh this app's short-lived
JWT access tokens (see auth.py), and everything exposed here is an aggregate
count, never a per-device identifying detail (no MACs, hostnames, or IPs).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, Response
from sqlalchemy import case, func, select

from sentinel.db.models import Alert, Device
from sentinel.db.session import get_session
from sentinel.scheduler.scheduler import get_scheduler

bp = Blueprint('metrics', __name__)

_SEVERITIES = ('CRITICAL', 'WARNING', 'INFO')


@bp.route('', methods=['GET'])
async def metrics():
    async with get_session() as session:
        device_row = (await session.execute(
            select(
                func.count().label('total'),
                func.sum(case((Device.is_online.is_(True), 1), else_=0)).label('online'),
                func.sum(case((Device.is_blocked.is_(True), 1), else_=0)).label('blocked'),
                func.sum(case((Device.is_quarantined.is_(True), 1), else_=0)).label('quarantined'),
                func.sum(case((Device.is_trusted.is_(True), 1), else_=0)).label('trusted'),
            )
            # Excludes devices linked away as a stale duplicate of another
            # device (see DeviceRepository.link()) — same filter
            # list_devices() applies, so these counts match what the UI shows.
            .where(Device.linked_to_mac.is_(None))
        )).one()

        now = datetime.now(timezone.utc)
        one_hour_ago = now - timedelta(hours=1)
        one_day_ago = now - timedelta(hours=24)
        alert_rows = (await session.execute(
            select(
                Alert.severity,
                func.count().label('total'),
                func.sum(case((Alert.acknowledged.is_(False), 1), else_=0)).label('unacknowledged'),
                func.sum(case((Alert.created_at >= one_hour_ago, 1), else_=0)).label('last_1h'),
                func.sum(case((Alert.created_at >= one_day_ago, 1), else_=0)).label('last_24h'),
            )
            .group_by(Alert.severity)
        )).all()
    alert_stats = {row.severity: row for row in alert_rows}

    try:
        poll_metrics = get_scheduler().metrics_snapshot()
    except RuntimeError:
        poll_metrics = {'scheduler_running': False, 'last_poll_duration_s': None, 'last_poll_age_s': None}

    body = _render(device_row, alert_stats, poll_metrics)
    return Response(body, mimetype='text/plain; version=0.0.4; charset=utf-8')


def _alert_field(alert_stats: dict[str, Any], severity: str, field: str) -> int:
    row = alert_stats.get(severity)
    return (getattr(row, field) or 0) if row else 0


def _render(device_row: Any, alert_stats: dict[str, Any], poll_metrics: dict[str, Any]) -> str:
    # (metric name, help text, [(labels, value), ...])
    metric_defs: list[tuple[str, str, list[tuple[dict[str, str], float]]]] = [
        ('heimdall_devices_total', 'Total devices ever seen', [({}, device_row.total or 0)]),
        ('heimdall_devices_online', 'Devices currently online', [({}, device_row.online or 0)]),
        ('heimdall_devices_blocked', 'Devices currently blocked', [({}, device_row.blocked or 0)]),
        ('heimdall_devices_quarantined', 'Devices currently quarantined', [({}, device_row.quarantined or 0)]),
        ('heimdall_devices_trusted', 'Devices marked trusted', [({}, device_row.trusted or 0)]),
        ('heimdall_alerts_total', 'Total alerts recorded, by severity', [
            ({'severity': sev}, _alert_field(alert_stats, sev, 'total')) for sev in _SEVERITIES
        ]),
        ('heimdall_alerts_unacknowledged', 'Unacknowledged alerts, by severity', [
            ({'severity': sev}, _alert_field(alert_stats, sev, 'unacknowledged')) for sev in _SEVERITIES
        ]),
        ('heimdall_alerts_last_1h', 'Alerts raised in the last hour, by severity', [
            ({'severity': sev}, _alert_field(alert_stats, sev, 'last_1h')) for sev in _SEVERITIES
        ]),
        ('heimdall_alerts_last_24h', 'Alerts raised in the last 24 hours, by severity', [
            ({'severity': sev}, _alert_field(alert_stats, sev, 'last_24h')) for sev in _SEVERITIES
        ]),
        ('heimdall_scheduler_up', 'Whether the background scheduler thread is running (1) or not (0)', [
            ({}, 1 if poll_metrics['scheduler_running'] else 0)
        ]),
    ]
    if poll_metrics['last_poll_duration_s'] is not None:
        metric_defs.append((
            'heimdall_poll_last_duration_seconds', 'Duration of the most recent successful router poll cycle',
            [({}, round(poll_metrics['last_poll_duration_s'], 3))],
        ))
    if poll_metrics['last_poll_age_s'] is not None:
        metric_defs.append((
            'heimdall_poll_last_success_age_seconds', 'Seconds since the last successful poll cycle completed',
            [({}, round(poll_metrics['last_poll_age_s'], 3))],
        ))

    lines: list[str] = []
    for name, help_text, samples in metric_defs:
        lines.append(f'# HELP {name} {help_text}')
        lines.append(f'# TYPE {name} gauge')
        for labels, value in samples:
            label_str = '{' + ','.join(f'{k}="{v}"' for k, v in labels.items()) + '}' if labels else ''
            lines.append(f'{name}{label_str} {value}')
    return '\n'.join(lines) + '\n'
