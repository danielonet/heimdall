"""SQLAlchemy 2 declarative models mirroring docs/architecture/07-database-schema.md.

Table DDL (including TimescaleDB hypertable conversion) lives in the Alembic
migrations under sentinel/db/migrations/versions/ — these classes are the
Python-side read/write mapping onto that schema, not the source of truth for it.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ARRAY, TIMESTAMP, BigInteger, Boolean, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all Heimdall ORM models."""


class Device(Base):
    """A LAN device tracked by the sentinel, keyed by its MAC address."""

    __tablename__ = 'devices'

    mac_address: Mapped[str] = mapped_column(String(17), primary_key=True)
    ip_address: Mapped[str | None] = mapped_column(String(15))
    hostname: Mapped[str | None] = mapped_column(String(255))
    vendor_name: Mapped[str | None] = mapped_column(String(255))
    interface_name: Mapped[str | None] = mapped_column(String(20))
    traffic_granularity: Mapped[str] = mapped_column(String(12), server_default='per_device')
    port_alias: Mapped[str | None] = mapped_column(String(10))
    os_fingerprint: Mapped[str | None] = mapped_column(String(100))
    nmap_profile: Mapped[dict | None] = mapped_column(JSONB)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    is_blocked: Mapped[bool] = mapped_column(Boolean, server_default='false')
    is_trusted: Mapped[bool] = mapped_column(Boolean, server_default='false')
    is_online: Mapped[bool] = mapped_column(Boolean, server_default='false')
    first_seen: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())


class TrustedMac(Base):
    """A permanently-trusted MAC address, independent of the devices table's
    lifecycle — so a device already established as trusted doesn't re-trigger
    NewDeviceDetector if `devices` is ever cleared/reset (see NewDeviceDetector
    and scripts/seed_baseline.py)."""

    __tablename__ = 'trusted_macs'

    mac_address: Mapped[str] = mapped_column(String(17), primary_key=True)
    trusted_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())


class TrafficSample(Base):
    """Per-device traffic delta for a single poll interval (TimescaleDB hypertable).

    time + mac_address are marked as the ORM primary key so SQLAlchemy can
    identity-map rows; the underlying hypertable has no PRIMARY KEY constraint
    (see the migration), matching the docs' indexed-but-unconstrained schema.
    """

    __tablename__ = 'traffic_samples'

    time: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), primary_key=True)
    mac_address: Mapped[str] = mapped_column(String(17), primary_key=True)
    bytes_sent_delta: Mapped[int | None] = mapped_column(BigInteger)
    bytes_recv_delta: Mapped[int | None] = mapped_column(BigInteger)
    throughput_up_kbps: Mapped[int | None] = mapped_column(BigInteger)
    throughput_dn_kbps: Mapped[int | None] = mapped_column(BigInteger)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    granularity: Mapped[str | None] = mapped_column(String(12))
    poll_interval_s: Mapped[int | None] = mapped_column(Integer)


class PortStats(Base):
    """Per-port Ethernet counters for a single poll interval (TimescaleDB hypertable)."""

    __tablename__ = 'port_stats'

    time: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), primary_key=True)
    port_alias: Mapped[str] = mapped_column(String(10), primary_key=True)
    status: Mapped[str | None] = mapped_column(String(10))
    link_speed_mbps: Mapped[int | None] = mapped_column(Integer)
    bytes_sent_delta: Mapped[int | None] = mapped_column(BigInteger)
    bytes_recv_delta: Mapped[int | None] = mapped_column(BigInteger)
    errors_recv: Mapped[int | None] = mapped_column(Integer)
    discards_recv: Mapped[int | None] = mapped_column(Integer)
    broadcast_recv: Mapped[int | None] = mapped_column(BigInteger)
    last_change_secs: Mapped[int | None] = mapped_column(BigInteger)


class DnsQuery(Base):
    """A single DNS query observed for a device (TimescaleDB hypertable)."""

    __tablename__ = 'dns_queries'

    time: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), primary_key=True)
    device_mac: Mapped[str | None] = mapped_column(String(17), primary_key=True)
    query: Mapped[str | None] = mapped_column(String(500), primary_key=True)
    blocked: Mapped[bool | None] = mapped_column(Boolean)
    list_name: Mapped[str | None] = mapped_column(String(100))


class Alert(Base):
    """A threat detector finding surfaced to the dashboard."""

    __tablename__ = 'alerts'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    device_mac: Mapped[str | None] = mapped_column(String(17))
    alert_type: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(10))  # INFO | WARNING | CRITICAL
    description: Mapped[str | None] = mapped_column(Text)
    raw_data: Mapped[dict | None] = mapped_column(JSONB)
    acknowledged: Mapped[bool] = mapped_column(Boolean, server_default='false')
    resolved: Mapped[bool] = mapped_column(Boolean, server_default='false')
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())


class Rule(Base):
    """A user-defined detection rule (condition + action)."""

    __tablename__ = 'rules'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100))
    condition_json: Mapped[dict] = mapped_column(JSONB)
    action_json: Mapped[dict] = mapped_column(JSONB)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default='true')
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    last_triggered: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class ThreatIntelCache(Base):
    """Cached verdict for an IP or domain, avoiding repeated feed/API lookups."""

    __tablename__ = 'threat_intel_cache'

    ip_or_domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    is_malicious: Mapped[bool | None] = mapped_column(Boolean)
    threat_type: Mapped[str | None] = mapped_column(String(100))
    source_feed: Mapped[str | None] = mapped_column(String(50))
    score: Mapped[int | None] = mapped_column(Integer)
    cached_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class WanStatusHistory(Base):
    """A WAN up/down transition recorded by the scheduler."""

    __tablename__ = 'wan_status_history'

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    changed_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    status: Mapped[str] = mapped_column(String(10))  # 'UP' | 'DOWN'
    wan_mode: Mapped[str | None] = mapped_column(String(30))
    duration_s: Mapped[int | None] = mapped_column(BigInteger)
