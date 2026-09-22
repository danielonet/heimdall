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
    # A user-set label, independent of the router-reported hostname above —
    # unlike hostname, _upsert_devices (sentinel/scheduler/jobs.py) never
    # touches this, so it survives every poll instead of being silently
    # reverted within ~15s. Kept separate rather than repurposing hostname
    # itself so DeviceIdentityLinker's hostname-match heuristic keeps
    # comparing what the router actually reports.
    nickname: Mapped[str | None] = mapped_column(Text)
    vendor_name: Mapped[str | None] = mapped_column(String(255))
    interface_name: Mapped[str | None] = mapped_column(String(20))
    # Which configured router adapter most recently reported this device —
    # 'sagemcom' | 'miwifi'. Set by _upsert_devices (sentinel/scheduler/
    # jobs.py) from DeviceSnapshot.source_router on every poll (last-write-
    # wins if the same MAC is somehow seen from both, e.g. a bridged/AP-mode
    # Redmi on the same subnet as the Sagemcom — informational, not
    # identity-critical). Used by SentinelScheduler._adapter_for_mac to route
    # block/unblock/quarantine actions to the router that actually owns this
    # MAC. See docs/router/network-topology.md.
    source_router: Mapped[str] = mapped_column(String(20), server_default='sagemcom')
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
    # Stale device cleanup — see sentinel/db/repositories.py:DeviceRepository.
    # archive_stale()/unarchive() and SentinelScheduler._device_archive_sweep_job.
    # Set when this device hasn't been seen in AppSettings.
    # device_archive_after_days (default 90) — distinct from linked_to_mac:
    # this is "just hasn't been active in a long time", not "a stale
    # duplicate of another live device". Hidden from "connected" counts/
    # lists (see list_devices()) but nothing is deleted — fully reversible.
    is_archived: Mapped[bool] = mapped_column(Boolean, server_default='false')
    archived_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    archive_reason: Mapped[str | None] = mapped_column(Text)


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

    # Second router (Settings tab "REDMI ROUTER" section). Only the IP lives
    # here — like router_username above, the password is never stored in the
    # database; it's written straight to Settings.MIWIFI_PASSWORD_FILE on
    # disk instead. See sentinel/adapter/factory.py and
    # SentinelScheduler.reload_secondary_router_credentials().
    miwifi_ip: Mapped[str | None] = mapped_column(String(45))
    # Which configured router feeds the detection pipeline / WAN bandwidth
    # tracking / RuleEngine auto-block / ARP-DHCP reconciliation — 'sagemcom'
    # | 'miwifi'. The other configured router (if any) is still polled for
    # device/traffic visibility, just without those — see
    # SentinelScheduler._ensure_adapter vs. _ensure_secondary_adapter.
    active_router: Mapped[str] = mapped_column(String(20), server_default='sagemcom')

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
    # Days of no activity before the device-archive sweep job soft-archives
    # a device. Deliberately separate from data_retention_days — see the
    # d2b6c94a1f83_app_settings_device_archive_after_days migration docstring.
    device_archive_after_days: Mapped[int] = mapped_column(Integer, server_default='90')
    # Days an already-archived device may sit archived before the same
    # sweep job permanently deletes it (row, alerts, DNS/traffic history,
    # persisted ML model) — see DeviceRepository.purge_archived() and the
    # f2c8b53e947a_app_settings_device_purge_after_days migration docstring.
    # Measured from archived_at, additive on top of device_archive_after_days.
    device_purge_after_days: Mapped[int] = mapped_column(Integer, server_default='90')

    # WiFi Monitor tab (see sentinel/security/wifi_monitor.py). NULL/empty =
    # feature disabled — no monitor-capable adapter configured. Unlike
    # sniff_iface, there is no env-config fallback for this one: no
    # deployment can assume a second, monitor-mode-capable WiFi adapter is
    # physically present, so "unset" must mean "off", never a guessed
    # default. See the c7e5b3a92f14_app_settings_wifi_monitor migration.
    wifi_monitor_iface: Mapped[str | None] = mapped_column(String(20))
    # SSIDs the watcher alarms on if seen from a BSSID not in
    # wifi_trusted_bssids below — normally just your own network name(s).
    # Empty list = watcher runs (if wifi_monitor_iface is set) but can never
    # alert, since nothing is protected yet.
    wifi_protected_ssids: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    # The real BSSIDs of your own access points broadcasting the SSIDs
    # above — a beacon for a protected SSID from any OTHER BSSID is the
    # rogue-AP signal. See WifiMonitorWatcher._process.
    wifi_trusted_bssids: Mapped[list[str] | None] = mapped_column(ARRAY(Text))


class WifiSighting(Base):
    """A WiFi MAC seen nearby via a passively-sniffed 802.11 probe request —
    not necessarily ever associated with our network, and not a `Device`
    (no IP, no router-reported ap_alias/traffic granularity; see
    sentinel/security/wifi_monitor.py's module docstring for why this is a
    separate, much smaller model rather than folded into Device). Purely
    passive inventory, not a threat finding — see WifiMonitorWatcher._process
    and SentinelScheduler._persist_wifi_sighting. Pruned by the existing
    _data_retention_job alongside alerts/wan_status_history, keyed off the
    same data_retention_days setting (no dedicated retention knob needed).
    """

    __tablename__ = 'wifi_sightings'

    mac_address: Mapped[str] = mapped_column(String(17), primary_key=True)
    # '' (not NULL) for a randomized/locally-administered MAC — see
    # sentinel/security/mac_vendor.py:lookup_vendor(), reused here verbatim.
    # Most sightings will have this blank; that's an honest answer, not a
    # missing lookup.
    vendor_name: Mapped[str] = mapped_column(String(255), server_default='')
    first_seen: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())
    # Strongest (least negative) signal ever observed for this MAC, not the
    # most recent — a device that was once close but is now far away should
    # still show how close it's actually gotten, e.g. for judging "was this
    # briefly inside my house."
    strongest_signal_dbm: Mapped[int | None] = mapped_column(Integer)
    times_seen: Mapped[int] = mapped_column(Integer, server_default='1')
    last_probed_ssid: Mapped[str | None] = mapped_column(String(32))
    # Admin-set: "this overheard MAC is mine" — a device Heimdall has no
    # other way to recognize (e.g. a spare phone, watch, or anything whose
    # MAC is randomized so it can't even OUI-match a known device — see
    # routes/wifi.py:_match_known_device). Purely a display label; unlike
    # wifi_trusted_bssids (which actually feeds rogue-AP detection), marking
    # a *client* sighting as mine has no detection-side effect — a client
    # device was never a threat signal to begin with.
    is_mine: Mapped[bool] = mapped_column(Boolean, server_default='false')


class WifiNetwork(Base):
    """A nearby WiFi network (access point radio) seen via a passively-
    sniffed beacon frame — one row per BSSID, since one SSID is often
    several radios (2.4GHz, 5GHz, guest, mesh nodes). Unlike WifiSighting
    (a *client* device overheard probing), this is infrastructure. Pruned by
    _data_retention_job like wifi_sightings. See WifiMonitorWatcher."""

    __tablename__ = 'wifi_networks'

    bssid: Mapped[str] = mapped_column(String(17), primary_key=True)
    # '' for a hidden-SSID network (empty SSID element in the beacon).
    ssid: Mapped[str] = mapped_column(String(32), server_default='')
    vendor_name: Mapped[str] = mapped_column(String(255), server_default='')
    channel: Mapped[int | None] = mapped_column(Integer)
    # Strongest signal ever seen, same reasoning as WifiSighting.
    strongest_signal_dbm: Mapped[int | None] = mapped_column(Integer)
    # Beacon's capability 'privacy' bit — encrypted vs open.
    secured: Mapped[bool] = mapped_column(Boolean, server_default='true')
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


class AlertSnooze(Base):
    """Suppresses a specific (device, alert_type) pair from producing new
    alerts until snoozed_until — see AlertRepository.upsert()'s snooze
    check, the single choke point every alert-creation path (detection
    pipeline, RuleEngine, SentinelScheduler's confirmed-attack sources)
    already routes through, so snoozing here covers all of them uniformly
    with no per-source special-casing needed.

    No FK to devices, same reasoning as TrustedMac: must survive a
    devices-table purge/reset rather than cascade-deleting with it. PK is
    (device_mac, alert_type) rather than a surrogate id — at most one
    active snooze per pair; re-snoozing replaces it rather than
    accumulating rows."""

    __tablename__ = 'alert_snoozes'

    device_mac: Mapped[str] = mapped_column(String(17), primary_key=True)
    alert_type: Mapped[str] = mapped_column(String(50), primary_key=True)
    snoozed_until: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())


class PortAllowlistEntry(Base):
    """A (device, port) pair explicitly vouched for as expected/legitimate —
    excludes it from NetworkScanner's HIGH_RISK_PORTS check going forward
    (see SentinelScheduler._nmap_scan_job), rather than just muting the
    alert or the auto-block reaction: an allowlisted port is meant to never
    be flagged as a finding again, the same way an admin would expect a
    conventional network-security allowlist to behave.

    No FK to devices, same reasoning as TrustedMac/AlertSnooze: must
    survive a devices-table purge/reset rather than cascade-deleting with
    it. PK is (device_mac, port) — at most one entry per pair; re-adding
    replaces it (e.g. an updated note) rather than accumulating rows.
    `service` is captured at creation time from HIGH_RISK_PORTS rather than
    looked up live at display time, so the label stays stable even if that
    dict's contents are ever edited later."""

    __tablename__ = 'port_allowlist'

    device_mac: Mapped[str] = mapped_column(String(17), primary_key=True)
    port: Mapped[int] = mapped_column(Integer, primary_key=True)
    service: Mapped[str] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now())


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
