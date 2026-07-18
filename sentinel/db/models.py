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
    signal_strength_dbm: Mapped[int] = mapped_column(Integer, server_default='0')
    signal_rate_mbps: Mapped[int] = mapped_column(Integer, server_default='0')
    os_fingerprint: Mapped[str | None] = mapped_column(String(100))
    nmap_profile: Mapped[dict | None] = mapped_column(JSONB)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    is_blocked: Mapped[bool] = mapped_column(Boolean, server_default='false')
    is_trusted: Mapped[bool] = mapped_column(Boolean, server_default='false')
    is_online: Mapped[bool] = mapped_column(Boolean, server_default='false')
    # True once this MAC has ever been seen with is_online=True — distinct
    # from the row simply existing, which happens for any Hosts/
    # AssociatedDevices sighting regardless of actual connection. See
    # NewDeviceDetector, which alerts on this rather than plain row existence.
    ever_connected: Mapped[bool] = mapped_column(Boolean, server_default='false')
    first_seen: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())


class AppSettings(Base):
    """Singleton row (id always 1) for runtime-configurable settings that must
    take effect without restarting the process — the ML learning-period
    window and the data-retention window, both adjustable from the frontend
    Settings tab. Falls back to the matching Settings.* env-config default
    until an admin sets an override here — see SettingsRepository.
    """

    __tablename__ = 'app_settings'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    ml_learning_period_hours: Mapped[int] = mapped_column(Integer, server_default='72')
    data_retention_days: Mapped[int] = mapped_column(Integer, server_default='90')
    # When the current learning clock started — stamped by
    # _auto_trust_new_connections_during_learning (jobs.py) and cleared back to NULL
    # by a purge (POST /api/settings/purge), so the frontend's LEARNING/ARMED
    # status badge tracks the *current* baseline, not the original install.
    baseline_established_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    # False until _retrain_once_armed (jobs.py) has refit every device's ML
    # model from the *complete* learning-window history, exactly once per
    # learning cycle. Without this, each device keeps whatever bootstrap
    # model it got after its first ML_MIN_SAMPLES_TO_TRAIN samples (~25min
    # at the default poll interval) — a narrow early slice of its behaviour
    # — right up until alerts unlock, which floods ANOMALOUS_VOLUME for
    # everything. Reset to False alongside every baseline_established_at
    # write (see set_baseline_established_at) so a new learning cycle (fresh
    # install or a purge) retrains again once it re-arms.
    armed_retrain_done: Mapped[bool] = mapped_column(Boolean, server_default='false')
    # NULL = use Settings.SNIFF_IFACE (the env default) — overridden once an
    # admin picks a NIC from the Settings tab dropdown (see
    # sentinel/security/interfaces.py). Applied live via
    # SentinelScheduler.restart_sniffers(), not just on the next process
    # restart — see POST /api/settings.
    sniff_iface: Mapped[str | None] = mapped_column(String(20))

    # Router credentials (Settings tab "ROUTER" section). Only the username
    # lives here — the password is deliberately NOT stored in the database;
    # it's written straight to Settings.ROUTER_PASSWORD_FILE on disk instead,
    # keeping CLAUDE.md's "secrets via Docker secrets only" rule intact. See
    # sentinel/adapter/factory.py and SentinelScheduler.reload_router_credentials().
    router_username: Mapped[str | None] = mapped_column(String(100))

    # Notifications tab. smtp_password is likewise never stored here — see
    # Settings.SMTP_PASSWORD_FILE.
    ntfy_url: Mapped[str | None] = mapped_column(String(500))
    smtp_host: Mapped[str | None] = mapped_column(String(255))
    smtp_port: Mapped[int | None] = mapped_column(Integer)
    smtp_from: Mapped[str | None] = mapped_column(String(255))
    smtp_to: Mapped[str | None] = mapped_column(String(255))
    smtp_username: Mapped[str | None] = mapped_column(String(255))
    smtp_use_tls: Mapped[bool | None] = mapped_column(Boolean)


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
