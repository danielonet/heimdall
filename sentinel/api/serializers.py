"""JSON-safe serializers for ORM models, shared across API routes and the
scheduler's WebSocket emits — one source of truth for each model's wire shape.
"""
from __future__ import annotations

from typing import Any

from sentinel.db.models import Alert, Device, PortStats, Rule, TrafficSample, WanStats


def device_to_dict(device: Device) -> dict[str, Any]:
    return {
        'mac_address': device.mac_address,
        'ip_address': device.ip_address,
        'hostname': device.hostname,
        'nickname': device.nickname,
        'vendor_name': device.vendor_name,
        'interface_name': device.interface_name,
        'traffic_granularity': device.traffic_granularity,
        'port_alias': device.port_alias,
        'signal_strength_dbm': device.signal_strength_dbm,
        'signal_rate_mbps': device.signal_rate_mbps,
        'device_type': device.device_type,
        'ap_alias': device.ap_alias,
        'os_fingerprint': device.os_fingerprint,
        'nmap_profile': device.nmap_profile,
        'tags': device.tags or [],
        'is_blocked': device.is_blocked,
        'blocked_at': device.blocked_at.isoformat() if device.blocked_at else None,
        'blocked_until': device.blocked_until.isoformat() if device.blocked_until else None,
        'is_quarantined': device.is_quarantined,
        'is_trusted': device.is_trusted,
        'is_online': device.is_online,
        'ever_connected': device.ever_connected,
        'first_seen': device.first_seen.isoformat() if device.first_seen else None,
        'last_seen': device.last_seen.isoformat() if device.last_seen else None,
        # Device-identity linking — see sentinel/db/repositories.py:DeviceRepository.
        'linked_to_mac': device.linked_to_mac,
        'linked_at': device.linked_at.isoformat() if device.linked_at else None,
        'link_reason': device.link_reason,
        # Stale device cleanup — see sentinel/db/repositories.py:DeviceRepository.
        'is_archived': device.is_archived,
        'archived_at': device.archived_at.isoformat() if device.archived_at else None,
        'archive_reason': device.archive_reason,
    }


def traffic_sample_to_dict(sample: TrafficSample) -> dict[str, Any]:
    return {
        'time': sample.time.isoformat() if sample.time else None,
        'mac_address': sample.mac_address,
        'bytes_sent_delta': sample.bytes_sent_delta,
        'bytes_recv_delta': sample.bytes_recv_delta,
        'throughput_up_kbps': sample.throughput_up_kbps,
        'throughput_dn_kbps': sample.throughput_dn_kbps,
        'anomaly_score': sample.anomaly_score,
        'granularity': sample.granularity,
        'poll_interval_s': sample.poll_interval_s,
    }


def alert_to_dict(alert: Alert) -> dict[str, Any]:
    return {
        'id': alert.id,
        'device_mac': alert.device_mac,
        'alert_type': alert.alert_type,
        'severity': alert.severity,
        'description': alert.description,
        'raw_data': alert.raw_data,
        'mitigation': alert.mitigation,
        'acknowledged': alert.acknowledged,
        'resolved': alert.resolved,
        'created_at': alert.created_at.isoformat() if alert.created_at else None,
        # Lifecycle fields — see sentinel/db/repositories.py:AlertRepository.
        'last_seen': alert.last_seen.isoformat() if alert.last_seen else None,
        'occurrence_count': alert.occurrence_count,
        'resolved_at': alert.resolved_at.isoformat() if alert.resolved_at else None,
        'acknowledged_at': alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
    }


def port_stats_to_dict(port: PortStats) -> dict[str, Any]:
    return {
        'time': port.time.isoformat() if port.time else None,
        'port_alias': port.port_alias,
        'status': port.status,
        'link_speed_mbps': port.link_speed_mbps,
        'bytes_sent_delta': port.bytes_sent_delta,
        'bytes_recv_delta': port.bytes_recv_delta,
        'errors_recv': port.errors_recv,
        'discards_recv': port.discards_recv,
        'broadcast_recv': port.broadcast_recv,
        'last_change_secs': port.last_change_secs,
    }


def wan_stats_to_dict(wan: WanStats) -> dict[str, Any]:
    return {
        'time': wan.time.isoformat() if wan.time else None,
        'bytes_sent_delta': wan.bytes_sent_delta,
        'bytes_recv_delta': wan.bytes_recv_delta,
        'throughput_up_kbps': wan.throughput_up_kbps,
        'throughput_dn_kbps': wan.throughput_dn_kbps,
    }


def rule_to_dict(rule: Rule) -> dict[str, Any]:
    return {
        'id': rule.id,
        'name': rule.name,
        'condition_json': rule.condition_json,
        'action_json': rule.action_json,
        'enabled': rule.enabled,
        'created_at': rule.created_at.isoformat() if rule.created_at else None,
        'last_triggered': rule.last_triggered.isoformat() if rule.last_triggered else None,
    }
