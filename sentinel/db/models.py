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
    # Router's own DHCP-fingerprint device classification (e.g. 'Smartphone',
    # 'Multimedia device') — blank when the router couldn't classify it. See
    # SagemcomXmoAdapter._to_device_snapshot.
    device_type: Mapped[str | None] = mapped_column(String(50))
    # Which AP this WiFi client is associated with — 'PRIV0'|'VID1'|
    # 'GUEST2G'|'GUEST5G'|'AP_BACKHAUL', NULL for wired devices (no AP at
    # all). See SagemcomXmoAdapter._get_associated_devices.
    ap_alias: Mapped[str | None] = mapped_column(String(20))
    os_fingerprint: Mapped[str | None] = mapped_column(String(100))
    nmap_profile: Mapped[dict | None] = mapped_column(JSONB)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    is_blocked: Mapped[bool] = mapped_column(Boolean, server_default='false')
    # Set/refreshed by _raise_threat_alert on every successful auto-block —
    # NULL for a manual admin block (via POST /devices/<mac>/block), which
    # stays indefinite by design. blocked_until NULL also means "no expiry"
    # (either never blocked, or AppSettings.auto_block_expiry_hours was 0
    # when this block was applied). See SentinelScheduler._block_expiry_job.
    blocked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    blocked_until: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    # WAN-only "cut internet, allow LAN" tier — a softer response than
    # is_blocked's full BlacklistedSchedule removal. See
    # SagemcomXmoAdapter.quarantine_device.
    is_quarantined: Mapped[bool] = mapped_column(Boolean, server_default='false')
    is_trusted: Mapped[bool] = mapped_column(Boolean, server_default='false')
    is_online: Mapped[bool] = mapped_column(Boolean, server_default='false')
    # True once this MAC has ever been seen with is_online=True — distinct
    # from the row simply existing, which happens for any Hosts/
    # AssociatedDevices sighting regardless of actual connection. See
    # NewDeviceDetector, which alerts on this rather than plain row existence.
    ever_connected: Mapped[bool] = mapped_column(Boolean, server_default='false')
    first_seen: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    # Device-identity linking — see sentinel/detection/device_identity.py:
    # DeviceIdentityLinker and sentinel/db/repositories.py:DeviceRepository.
    # link(). Set when this row is a stale duplicate of another device (a
    # phone's randomized/rotating WiFi MAC creating a new row on reconnect)
    # — points at the CURRENT live canonical MAC, never a multi-hop chain.
    # All three columns are set/cleared together; NULL = this row is its own
    # identity. A linked row is hidden from "connected" counts/lists (see
    # list_devices()/metrics.py) but its history is never deleted — see
    # unlink() for the manual-undo path.
    linked_to_mac: Mapped[str | None] = mapped_column(String(17))
    linked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    link_reason: Mapped[str | None] = mapped_column(Text)


class DeviceTypeProfile(Base):
    """Admin-editable detector-threshold overrides keyed by Device.device_type.

    device_type is not a closed enum — it's whatever free-text string the
    router's own DHCP-fingerprint database returns (e.g. 'Smartphone',
    'Network Attached Storage'), blank/None when it can't classify a device
    at all. This table is therefore an open-ended, admin-growable collection
    (rows only exist for types someone has actually tuned), not a fixed
    lookup — see sentinel/detection/device_profiles.py's DEFAULT_PROFILE for
    the fallback used when no row matches. Was a hardcoded Python dict until
    this table replaced it, specifically to let an admin fix the case where a
    device type's defaults are wrong for their network (e.g. a phone that
    legitimately bursts data and shouldn't alert every time) without a code
    change/redeploy.
    """

    __tablename__ = 'device_type_profiles'

    device_type: Mapped[str] = mapped_column(String(50), primary_key=True)
    # HighUploadDetector's ratio threshold — see sentinel/detection/detectors/high_upload.py.
    high_upload_ratio_threshold: Mapped[float] = mapped_column(Float)
    # AnomalousVolumeDetector's consecutive-poll requirement — see
    # sentinel/detection/detectors/anomalous_volume.py.
    volume_sustained_polls: Mapped[int] = mapped_column(Integer)
    # IsolationForest's contamination rate for this device type's nightly
    # retrain — see sentinel/ml/trainer.py:ModelTrainer.retrain_all() and
    # sentinel/ml/anomaly_engine.py. Not applied to the very first (bootstrap)
    # fit, which keeps using the global Settings.ML_CONTAMINATION default —
    # see AnomalyEngine.retrain_from_history()'s docstring for why.
    contamination: Mapped[float] = mapped_column(Float)
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )


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

    # Security tab. When True, SentinelScheduler._raise_threat_alert() calls
    # adapter.block_device() the instant ArpWatcher/PassiveFingerprinter/
    # NetworkScanner identify an attack (ARP spoof, fingerprint mismatch,
    # newly-opened high-risk port, nmap vuln finding), instead of only
    # raising an alert. See docs/architecture/06-security-services.md.
    auto_block_on_threat: Mapped[bool] = mapped_column(Boolean, server_default='true')
    # Hours an auto-block (not a manual one) stays in effect before
    # SentinelScheduler._block_expiry_job auto-unblocks and notifies for
    # review — 0 means auto-blocks never expire. See Device.blocked_until.
    auto_block_expiry_hours: Mapped[int] = mapped_column(Integer, server_default='24')

    # When the last security digest notification was sent — NULL means
    # never sent yet. See SentinelScheduler._security_digest_job.
    last_digest_sent_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))

    # Alerts tab. An alert older than this is still kept forever (nothing
    # deletes it), but is excluded from the Dashboard's OPEN ALERTS
    # feed/threat score and from the Network Map's urgency layout — see
    # frontend/src/lib/alertStaleness.js — and shown with a STALE badge on
    # the full Alerts page instead of the usual OPEN styling, so a months-old
    # unresolved alert doesn't keep pulling a device toward the map's center
    # or reading as an active, alarming threat every time the page is opened.
    alert_stale_hours: Mapped[int] = mapped_column(Integer, server_default='24')
    # Hours of no recurrence before the alert_auto_resolve sweep job closes
    # an open alert with no natural "this stopped" signal of its own.
    # Deliberately separate from alert_stale_hours — see the
    # a4e19d6b3c72_app_settings_alert_auto_resolve migration docstring.
    alert_auto_resolve_hours: Mapped[int] = mapped_column(Integer, server_default='72')


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


class WanStats(Base):
    """Household-total WAN traffic delta for a single poll interval
    (TimescaleDB hypertable). No device/port dimension — `time` alone
    identifies a row, unlike TrafficSample/PortStats. Populated from
    SagemcomXmoAdapter.get_wan_stats(), which reads an unverified xpath
    (Device/IP/Interfaces/Interface[Alias='IP_DATA']/Stats — see
    docs/router/sagemcom-xmo-api.md) and returns None if it doesn't
    resolve, in which case no row is inserted that poll.
    """

    __tablename__ = 'wan_stats'

    time: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), primary_key=True)
    bytes_sent_delta: Mapped[int | None] = mapped_column(BigInteger)
    bytes_recv_delta: Mapped[int | None] = mapped_column(BigInteger)
    throughput_up_kbps: Mapped[int | None] = mapped_column(BigInteger)
    throughput_dn_kbps: Mapped[int | None] = mapped_column(BigInteger)


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
    # Canned "what to do about this" guidance — see
    # sentinel/security/remediation.py:build_mitigation(). Only ever set by
    # SentinelScheduler._raise_threat_alert (confirmed-attack alert types);
    # NULL for RuleEngine/detector-pipeline alerts, which have no fixed
    # alert_type to key remediation copy off of.
    mitigation: Mapped[str | None] = mapped_column(Text)
    acknowledged: Mapped[bool] = mapped_column(Boolean, server_default='false')
    resolved: Mapped[bool] = mapped_column(Boolean, server_default='false')
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    # Lifecycle fields — see sentinel/db/repositories.py:AlertRepository.
    # A still-true condition touches this same row (bumping last_seen/
    # occurrence_count, overwriting description/raw_data/severity with the
    # latest values) instead of inserting a fresh row every poll.
    last_seen: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    occurrence_count: Mapped[int] = mapped_column(Integer, server_default='1')
    resolved_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    # Disambiguates cases where (device_mac, alert_type) alone would wrongly
    # merge distinct incidents — e.g. RuleEngine's f'rule:{rule.id}', nmap's
    # f'port:{port}'. NULL (the common case) matched NULL-safely via
    # isnot_distinct_from() in AlertRepository.
    dedup_key: Mapped[str | None] = mapped_column(String(100))


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
