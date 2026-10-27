"""APScheduler wrapper: owns a dedicated background event loop for async poll jobs.

Flask (Werkzeug dev server / gunicorn sync workers) doesn't run its own asyncio
event loop, so the scheduler gets its own thread + loop rather than sharing Flask's.
"""
from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import logging
import threading
import time
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import datetime, timedelta, timezone
from typing import Any, Coroutine

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import Flask
from redis.asyncio import Redis, from_url
from sqlalchemy import delete, select, text

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.discovery import discover_gateway_ip, discover_local_ips
from sentinel.adapter.factory import create_router_adapter, create_secondary_router_adapter
from sentinel.adapter.models import RouterInfo
from sentinel.api.serializers import alert_to_dict
from sentinel.api.websocket import emit_alert
from sentinel.config import settings
from sentinel.db.models import Alert, Device, DnsQuery, WanStatusHistory, WifiNetwork, WifiSighting
from sentinel.db.repositories import (
    AlertRepository, DeviceRepository, PortAllowlistRepository, SettingsRepository, TrustedMacRepository,
    WifiNetworkRepository, WifiSightingRepository,
)
from sentinel.db.session import get_session
from sentinel.deployment_tiers import active_service_keys, services_for_tier
from sentinel.detection.correlation import CrossAlertCorrelator
from sentinel.detection.device_identity import DeviceIdentityLinker
from sentinel.detection.observed_extremes import compute_observed_extremes
from sentinel.detection.pipeline import DetectionPipeline, create_default_pipeline
from sentinel.detection.rules_engine import RuleEngine
from sentinel.detection.wan_bandwidth import WanBandwidthDetector
from sentinel.ml.anomaly_engine import AnomalyEngine
from sentinel.ml.model_store import ModelStore
from sentinel.ml.trainer import ModelTrainer
from sentinel.notifications.digest import render_digest_html, render_digest_text
from sentinel.notifications.digest_query import build_digest_data
from sentinel.notifications.service import NotificationConfig, NotificationService
from sentinel.scheduler.jobs import poll_cycle, poll_secondary_router
from sentinel.security.arp_watch import ArpWatcher
from sentinel.security.canary import OpenCanaryIngester, OpenCanaryLogReader
from sentinel.security.clamav_scanner import ClamAvScanner
from sentinel.security.dhcp_watch import DhcpWatcher
from sentinel.security.fingerprint import PassiveFingerprinter
from sentinel.security.liveness import ArpLivenessProbe, LivenessProbeError
from sentinel.security.os_classification import os_family
from sentinel.security.remediation import build_mitigation
from sentinel.security.scanner import HIGH_RISK_PORTS, NetworkScanner
from sentinel.security.suricata_parser import SuricataAlertIngester, SuricataEveLogReader
from sentinel.security.threat_intel import ThreatIntelService
from sentinel.security.wifi_monitor import WifiMonitorWatcher
from sentinel.security.zeek_parser import (
    ZeekConnBeaconDetector,
    ZeekConnVolumeCorrelator,
    ZeekDnsIngester,
    ZeekDnsLogReader,
    ZeekFileExtractionWatcher,
)

logger = logging.getLogger(__name__)

# See SentinelScheduler._spike_ip_enrichment_job.
_SPIKE_ALERT_TYPES = ('ANOMALOUS_VOLUME', 'HIGH_UPLOAD', 'WAN_BANDWIDTH_SPIKE')
_SPIKE_ENRICHMENT_LOOKBACK_MINUTES = 30  # how far back to look for un-enriched alerts
# conn.log correlation window around a spike alert's created_at. 15min back
# covers the default sustained-poll thresholds for all three spike
# detectors (HIGH_UPLOAD.SUSTAINED_POLLS=3, AnomalousVolumeDetector's
# per-profile volume_sustained_polls, defaulted to 3) with headroom for
# typical admin overrides; 5min forward accounts for Zeek writing a conn.log
# row at connection *close*, not start — a connection open during the spike
# may not appear until after it ends.
CORRELATION_WINDOW_BEFORE_MINUTES = 15
CORRELATION_WINDOW_AFTER_MINUTES = 5


def _is_internal_ip(ip: str) -> bool:
    """True for any RFC1918 private range, loopback, or link-local address
    — genuinely could be another device on this LAN. See _enrich_spike_
    alert: ZeekConnVolumeCorrelator.top_talkers' "remote" IP only ever
    means "not in the local_ips set passed in" (its own docstring) — that
    can still be another device on this same LAN the correlated device
    just wasn't itself compared against (e.g. a NAS backing up to a
    different private-subnet host), not necessarily anything on the public
    internet.

    Deliberately NOT ipaddress.ip_address(ip).is_private — confirmed live
    that property is far broader than RFC1918: it also covers IANA
    documentation/TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24 — the very ranges this project's own tests use as
    stand-in "external" IPs, which then misclassified as internal and
    broke under is_private). Explicit RFC1918 network membership instead,
    which is exactly the "could this be one of the user's own devices"
    question, nothing broader.

    Malformed input (shouldn't happen — Zeek's own id.orig_h/id.resp_h
    fields) is treated as not-internal rather than raising, so a parse
    failure fails safe into the normal threat-intel-checked path instead
    of silently skipping it."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_link_local or any(
        addr in net for net in (
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
        )
    )

DEFAULT_ADAPTER_CALL_TIMEOUT_S = 10.0
# How long to stay quiet on a given IP after reporting it as conflicted
# (see _persist_arp_alert) — an IP statically double-assigned to two of the
# user's own devices keeps flapping until they fix it at the network level,
# and would otherwise re-fire on every single flip.
IP_CONFLICT_QUIET_MINUTES = 30

# Baseline cadence for _reconcile_arp_table's DHCP-lease re-seed (see its
# docstring) — deliberately much slower than the 15s poll cycle it's called
# from. Reconciling this often was itself the complaint: a DHCP-leases
# fetch every single poll cycle, forever, just to catch drift that in
# practice moves far slower than that. 5 minutes is generous headroom
# before a stale pairing could plausibly cause a false positive, without
# hammering the router on every tick.
ARP_DHCP_RECONCILE_INTERVAL_S = 300

# _verify_arp_change_against_dhcp's retry budget for an in-the-moment
# suspected spoof — this is the "actively poll" half of the same request:
# when ArpWatcher actually reports a live mismatch, don't wait for the next
# 5-minute reconciliation and don't trust a single DHCP snapshot either
# (the router's own DHCP exchange for a fresh reassignment needs a moment
# to settle) — poll fast, a few times, and only fall through to
# ARP_SPOOF/auto-block if the router's own lease data still hasn't
# confirmed the new pairing by the last attempt. 4 attempts x 15s = up to
# 45s of added latency before a genuine attack gets blocked — a deliberate
# tradeoff (verify-before-block) traded for not auto-blocking every
# ordinary DHCP reassignment.
ARP_VERIFICATION_MAX_ATTEMPTS = 4
ARP_VERIFICATION_RETRY_INTERVAL_S = 15

# Cadence for _reconcile_block_enforcement — see that method's docstring.
# Piggybacks entirely on adapter.get_connected_devices()'s own 5-minute
# cache (SagemcomXmoAdapter._CONNECTED_DEVICES_CACHE_TTL_S), so this rate
# limit isn't there to protect the router (that call is usually already
# free by the time this runs) — it's just to avoid re-running the DB scan
# and comparison every single 15s poll cycle for a class of drift that
# doesn't appear or disappear that fast.
BLOCK_ENFORCEMENT_RECONCILE_INTERVAL_S = 300


class SentinelScheduler:
    """Runs poll_cycle() on an interval, on its own background event loop/thread."""

    def __init__(
        self,
        poll_interval_s: int,
        redis_url: str,
        ml_model_dir: str,
        ml_min_samples: int,
        ml_contamination: float,
        ml_anomaly_magnitude_multiplier: float,
        ml_anomaly_alert_magnitude_multiplier: float,
        ml_retrain_cron: str,
        sniff_iface: str,
        otx_api_key: str,
        nmap_scan_cron: str,
        threat_feed_refresh_cron: str,
        data_retention_cron: str,
        notification_config: NotificationConfig,
        opencanary_log_path: str,
        canary_poll_interval_s: int,
        zeek_log_dir: str,
        zeek_extract_dir: str,
        zeek_dns_poll_interval_s: int,
        zeek_beacon_scan_interval_s: int,
        spike_ip_enrichment_interval_s: int,
        clamav_host: str,
        clamav_port: int,
        suricata_eve_log_path: str,
        suricata_poll_interval_s: int,
        block_expiry_check_interval_s: int,
        correlation_scan_interval_s: int,
        alert_auto_resolve_check_interval_s: int,
        device_identity_link_scan_interval_s: int,
        stale_device_reap_interval_s: int,
        device_archive_sweep_interval_s: int,
        security_digest_cron: str,
        deployment_tier: str = 'full',
        abusech_auth_key: str = '',
        threat_feed_cache_dir: str = '',
    ) -> None:
        self._tier = deployment_tier
        self._tier_services = services_for_tier(deployment_tier)
        self._poll_interval_s = poll_interval_s
        self._redis_url = redis_url
        self._ml_model_dir = ml_model_dir
        self._ml_min_samples = ml_min_samples
        self._ml_contamination = ml_contamination
        self._ml_anomaly_magnitude_multiplier = ml_anomaly_magnitude_multiplier
        self._ml_anomaly_alert_magnitude_multiplier = ml_anomaly_alert_magnitude_multiplier
        self._ml_retrain_cron = ml_retrain_cron
        self._sniff_iface = sniff_iface
        self._router_ip: str = ''  # resolved in _run_loop via _resolve_router_ip
        # This host's own LAN IP(s), resolved in _run_loop via discover_local_ips()
        # — see _is_own_host()/_raise_threat_alert's self-block safeguard.
        self._local_ips: set[str] = set()
        self._otx_api_key = otx_api_key
        self._abusech_auth_key = abusech_auth_key
        self._threat_feed_cache_dir = threat_feed_cache_dir
        self._nmap_scan_cron = nmap_scan_cron
        self._threat_feed_refresh_cron = threat_feed_refresh_cron
        self._data_retention_cron = data_retention_cron
        self._notification_config = notification_config
        self._opencanary_log_path = opencanary_log_path
        self._canary_poll_interval_s = canary_poll_interval_s
        self._zeek_log_dir = zeek_log_dir
        self._zeek_extract_dir = zeek_extract_dir
        self._zeek_dns_poll_interval_s = zeek_dns_poll_interval_s
        self._zeek_beacon_scan_interval_s = zeek_beacon_scan_interval_s
        self._spike_ip_enrichment_interval_s = spike_ip_enrichment_interval_s
        self._clamav_host = clamav_host
        self._clamav_port = clamav_port
        self._suricata_eve_log_path = suricata_eve_log_path
        self._suricata_poll_interval_s = suricata_poll_interval_s
        self._block_expiry_check_interval_s = block_expiry_check_interval_s
        self._correlation_scan_interval_s = correlation_scan_interval_s
        self._alert_auto_resolve_check_interval_s = alert_auto_resolve_check_interval_s
        self._device_identity_link_scan_interval_s = device_identity_link_scan_interval_s
        self._stale_device_reap_interval_s = stale_device_reap_interval_s
        self._device_archive_sweep_interval_s = device_archive_sweep_interval_s
        self._security_digest_cron = security_digest_cron
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._scheduler: AsyncIOScheduler | None = None
        self._adapter: RouterAdapter | None = None
        # Guards _ensure_adapter's lazy creation below — without this,
        # _startup_job and the first _poll_job tick both call _ensure_adapter
        # around the same moment at boot, both see self._adapter is None
        # (create_router_adapter awaits a DB call and yields control before
        # either assignment lands), and each builds its own independent
        # SagemcomXmoAdapter/XmoClient — confirmed live: two near-simultaneous
        # real XMO login attempts ~50ms apart on the same restart, each
        # independently hitting XMO_LOGIN_RETRY_ERR and arming its own
        # (then-discarded) cooldown, exactly doubling the real hits to the
        # router at the moment we most want to be gentle with it.
        self._adapter_lock = asyncio.Lock()
        # The other configured router (if any) — visibility-only, never fed
        # through the detection pipeline/RuleEngine/WAN bandwidth tracking.
        # See _ensure_secondary_adapter/_secondary_poll_job.
        self._secondary_adapter: RouterAdapter | None = None
        self._secondary_adapter_lock = asyncio.Lock()
        self._redis_client: Redis | None = None
        # Built once and reused across polls: HighUploadDetector, SignalAnomalyDetector,
        # and AnomalyEngine all track state (rolling counts, last RSSI, trained
        # models) in memory across calls — a fresh pipeline/engine per poll
        # would throw that state away every 15 seconds.
        self._pipeline: DetectionPipeline | None = None
        self._anomaly_engine: AnomalyEngine | None = None
        # Tracks a rolling throughput baseline across polls — same
        # once-per-process-and-reused reasoning as _pipeline/_anomaly_engine.
        self._wan_bandwidth_detector: WanBandwidthDetector | None = None
        self._correlator: CrossAlertCorrelator | None = None
        # See sentinel/detection/device_identity.py / sentinel/security/liveness.py.
        self._identity_linker: DeviceIdentityLinker | None = None
        self._liveness_probe: ArpLivenessProbe | None = None
        # Security services — also built once per process, same reasoning.
        self._threat_intel: ThreatIntelService | None = None
        self._scanner: NetworkScanner | None = None
        self._arp_watcher: ArpWatcher | None = None
        self._dhcp_watcher: DhcpWatcher | None = None
        self._fingerprinter: PassiveFingerprinter | None = None
        # None until _run_loop resolves a configured wifi_monitor_iface —
        # unlike the three above, there's no env-config default to fall
        # back to (no deployment can assume a second, monitor-capable WiFi
        # adapter is physically present), so "not constructed at all" is
        # this watcher's normal, common resting state. See
        # sentinel/security/wifi_monitor.py.
        self._wifi_monitor: WifiMonitorWatcher | None = None
        self._canary_reader: OpenCanaryLogReader | None = None
        self._canary_ingester: OpenCanaryIngester | None = None
        self._zeek_dns_reader: ZeekDnsLogReader | None = None
        self._zeek_dns_ingester: ZeekDnsIngester | None = None
        self._zeek_beacon_detector: ZeekConnBeaconDetector | None = None
        self._conn_volume_correlator: ZeekConnVolumeCorrelator | None = None
        self._zeek_file_watcher: ZeekFileExtractionWatcher | None = None
        self._clamav: ClamAvScanner | None = None
        self._suricata_reader: SuricataEveLogReader | None = None
        self._suricata_ingester: SuricataAlertIngester | None = None
        # Rules/notifications — RuleEngine tracks per-(rule, device) streak and
        # rate-limit state across polls, so it's built once too.
        self._notifier: NotificationService | None = None
        self._rule_engine: RuleEngine | None = None
        # Health tracking, read synchronously by Flask's /api/health route.
        self._last_poll_at: datetime | None = None
        self._last_poll_error: str | None = None
        self._last_poll_duration_s: float | None = None
        self._last_nmap_scan_at: datetime | None = None
        self._last_canary_check_at: datetime | None = None
        # time.monotonic(), not a wall-clock timestamp — see
        # _reconcile_arp_table, which is called every 15s poll cycle but
        # only actually does anything once ARP_DHCP_RECONCILE_INTERVAL_S has
        # elapsed. Instance attributes (not bare module constants) purely so
        # tests can override the cadence/retry budget without a real sleep —
        # see tests/test_scheduler/test_threat_auto_block.py's scheduler()
        # fixture.
        self._last_arp_reconcile_at: float | None = None
        self._arp_verify_max_attempts = ARP_VERIFICATION_MAX_ATTEMPTS
        self._arp_verify_retry_interval_s = ARP_VERIFICATION_RETRY_INTERVAL_S
        self._last_block_reconcile_at: float | None = None
        self._last_zeek_dns_check_at: datetime | None = None
        self._last_zeek_beacon_scan_at: datetime | None = None
        self._last_spike_ip_enrichment_at: datetime | None = None
        self._last_zeek_file_scan_at: datetime | None = None
        self._clamav_reachable: bool | None = None
        self._last_suricata_check_at: datetime | None = None
        # See _observed_extremes_job/observed_extremes_snapshot — refreshed
        # hourly, not per-request (a full traffic_samples scan).
        self._observed_extremes: dict | None = None
        self._observed_extremes_computed_at: datetime | None = None
        # ip -> quiet-until, see _persist_arp_alert.
        self._ip_conflict_quiet_until: dict[str, datetime] = {}

    def start(self) -> None:
        """Start the background thread and begin polling. Safe to call once."""
        if self._thread is not None:
            logger.warning('Scheduler already started — ignoring duplicate start()')
            return

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, name='sentinel-scheduler', daemon=True)
        self._thread.start()
        logger.info('Scheduler thread started (poll interval: %ds)', self._poll_interval_s)

    def shutdown(self) -> None:
        """Stop the scheduler and its background thread. Safe to call even if not started."""
        if self._loop is None:
            return
        if self._scheduler is not None:
            self._loop.call_soon_threadsafe(self._scheduler.shutdown, False)
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._thread = None
        logger.info('Scheduler stopped')

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._redis_client = from_url(self._redis_url)

        # A runtime-configured SNIFF_IFACE (an admin's pick from the Settings
        # tab dropdown — see SettingsRepository) overrides the env default,
        # so it persists across restarts without editing .env. Resolved here
        # via run_until_complete since the loop isn't running yet.
        self._sniff_iface = self._loop.run_until_complete(self._resolve_sniff_iface())

        # The router's LAN IP — same resolution create_router_adapter() uses
        # (settings.ROUTER_IP if set, else the default-route gateway) —
        # needed by DhcpWatcher to know which DHCP server is legitimate.
        # Resolved once at startup, same as sniff_iface above.
        self._router_ip = self._loop.run_until_complete(self._resolve_router_ip())

        # This host's own LAN IP(s) — no DB/async dependency, so a plain
        # synchronous call (unlike sniff_iface/router_ip above). See
        # _is_own_host()/_raise_threat_alert's self-block safeguard: a
        # detector false-positiving on Heimdall's own traffic (confirmed
        # case: its own nmap scan misread as C2 beaconing) must never be
        # able to auto-block the machine Heimdall itself runs on.
        self._local_ips = discover_local_ips()

        # Likewise for notification settings (Notifications tab) — a
        # previously-saved ntfy_url/SMTP config persists across restarts
        # without editing .env. SMTP_PASSWORD itself is never DB-backed (see
        # AppSettings' docstring), so it's still read straight off Settings,
        # which model_post_init already populated from SMTP_PASSWORD_FILE.
        self._notification_config = self._loop.run_until_complete(
            self._resolve_notification_config(self._notification_config)
        )

        self._anomaly_engine = AnomalyEngine(
            model_store=ModelStore(self._ml_model_dir),
            min_samples=self._ml_min_samples,
            contamination=self._ml_contamination,
            magnitude_multiplier=self._ml_anomaly_magnitude_multiplier,
            alert_magnitude_multiplier=self._ml_anomaly_alert_magnitude_multiplier,
        )
        self._pipeline = create_default_pipeline(self._anomaly_engine)
        self._wan_bandwidth_detector = WanBandwidthDetector()
        self._correlator = CrossAlertCorrelator()
        self._identity_linker = DeviceIdentityLinker()
        self._liveness_probe = ArpLivenessProbe(self._sniff_iface)
        self._threat_intel = ThreatIntelService(
            self._otx_api_key, self._abusech_auth_key, self._threat_feed_cache_dir
        )
        self._scanner = NetworkScanner()
        self._arp_watcher = ArpWatcher(self._on_arp_alert, self._sniff_iface)
        self._dhcp_watcher = DhcpWatcher(self._on_dhcp_alert, self._sniff_iface, self._router_ip)
        self._fingerprinter = PassiveFingerprinter(self._on_fingerprint, self._sniff_iface)
        # Only constructed if an admin has actually configured a monitor-
        # capable adapter (WiFi Monitor tab, Settings) — see this
        # attribute's own docstring above. _wifi_monitor stays None
        # otherwise, same "no container/feature present, nothing to build"
        # posture as the Docker-tier-gated integrations just below.
        wifi_iface, wifi_ssids, wifi_bssids = self._loop.run_until_complete(self._resolve_wifi_monitor_config())
        if wifi_iface:
            self._wifi_monitor = WifiMonitorWatcher(
                self._on_wifi_alert, self._on_wifi_sighting, wifi_iface, wifi_ssids, wifi_bssids,
                network_callback=self._on_wifi_network,
            )
        # Docker-backed integrations only get built for tiers that actually
        # deploy their container — see sentinel/deployment_tiers.py. Each
        # attribute stays None (its __init__ default) otherwise, and the
        # matching APScheduler job below is simply never registered rather
        # than polling a container that was never started.
        if self._tier_services['opencanary']:
            self._canary_reader = OpenCanaryLogReader(self._opencanary_log_path)
            self._canary_ingester = OpenCanaryIngester()
        if self._tier_services['zeek']:
            self._zeek_dns_reader = ZeekDnsLogReader(f'{self._zeek_log_dir}/dns.log')
            self._zeek_dns_ingester = ZeekDnsIngester()
            self._zeek_beacon_detector = ZeekConnBeaconDetector(self._zeek_log_dir)
            self._conn_volume_correlator = ZeekConnVolumeCorrelator(self._zeek_log_dir)
            self._zeek_file_watcher = ZeekFileExtractionWatcher(self._zeek_extract_dir, self._zeek_log_dir)
        if self._tier_services['clamav']:
            self._clamav = ClamAvScanner(self._clamav_host, self._clamav_port)
        if self._tier_services['suricata']:
            self._suricata_reader = SuricataEveLogReader(self._suricata_eve_log_path)
            self._suricata_ingester = SuricataAlertIngester()
        self._notifier = NotificationService(self._notification_config)
        # _rule_engine is constructed lazily in _poll_job, once the adapter
        # exists (BLOCK_DEVICE actions need it) — see _ensure_adapter().

        self._scheduler = AsyncIOScheduler(event_loop=self._loop)
        self._scheduler.add_job(
            self._poll_job,
            'interval',
            seconds=self._poll_interval_s,
            id='router_poll',
            next_run_time=datetime.now(),  # fire immediately, then on the interval
        )
        self._scheduler.add_job(
            self._secondary_poll_job,
            'interval',
            seconds=self._poll_interval_s,
            id='secondary_router_poll',
            next_run_time=datetime.now(),
        )
        self._scheduler.add_job(
            self._retrain_job,
            CronTrigger.from_crontab(self._ml_retrain_cron),
            id='ml_retrain',
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._nmap_scan_job,
            CronTrigger.from_crontab(self._nmap_scan_cron),
            id='nmap_scan',
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._threat_feed_refresh_job,
            CronTrigger.from_crontab(self._threat_feed_refresh_cron),
            id='threat_feed_refresh',
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._data_retention_job,
            CronTrigger.from_crontab(self._data_retention_cron),
            id='data_retention',
            replace_existing=True,
        )
        if self._tier_services['opencanary']:
            self._scheduler.add_job(
                self._canary_poll_job,
                'interval',
                seconds=self._canary_poll_interval_s,
                id='canary_poll',
            )
        if self._tier_services['zeek']:
            self._scheduler.add_job(
                self._zeek_dns_poll_job,
                'interval',
                seconds=self._zeek_dns_poll_interval_s,
                id='zeek_dns_poll',
            )
            self._scheduler.add_job(
                self._zeek_beacon_scan_job,
                'interval',
                seconds=self._zeek_beacon_scan_interval_s,
                id='zeek_beacon_scan',
            )
            self._scheduler.add_job(
                self._zeek_file_scan_job,
                'interval',
                seconds=self._zeek_dns_poll_interval_s,
                id='zeek_file_scan',
            )
            self._scheduler.add_job(
                self._spike_ip_enrichment_job,
                'interval',
                seconds=self._spike_ip_enrichment_interval_s,
                id='spike_ip_enrichment',
            )
        if self._tier_services['suricata']:
            self._scheduler.add_job(
                self._suricata_poll_job,
                'interval',
                seconds=self._suricata_poll_interval_s,
                id='suricata_poll',
            )
        self._scheduler.add_job(
            self._block_expiry_job,
            'interval',
            seconds=self._block_expiry_check_interval_s,
            id='block_expiry',
        )
        self._scheduler.add_job(
            self._correlation_job,
            'interval',
            seconds=self._correlation_scan_interval_s,
            id='correlation_scan',
        )
        self._scheduler.add_job(
            self._alert_auto_resolve_job,
            'interval',
            seconds=self._alert_auto_resolve_check_interval_s,
            id='alert_auto_resolve',
        )
        self._scheduler.add_job(
            self._identity_link_job,
            'interval',
            seconds=self._device_identity_link_scan_interval_s,
            id='device_identity_link',
        )
        self._scheduler.add_job(
            self._stale_device_reap_job,
            'interval',
            seconds=self._stale_device_reap_interval_s,
            id='stale_device_reap',
        )
        self._scheduler.add_job(
            self._device_archive_sweep_job,
            'interval',
            seconds=self._device_archive_sweep_interval_s,
            id='device_archive_sweep',
        )
        self._scheduler.add_job(
            self._security_digest_job,
            CronTrigger.from_crontab(self._security_digest_cron),
            id='security_digest',
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._observed_extremes_job,
            'interval',
            seconds=3600,
            id='observed_extremes_refresh',
            next_run_time=datetime.now(),  # fire immediately so the panel isn't empty for the first hour
        )
        self._scheduler.add_job(
            self._startup_job,
            'date',
            run_date=datetime.now(),
            id='startup',
        )
        self._scheduler.start()
        self._loop.run_forever()

    async def _poll_job(self) -> None:
        start = time.monotonic()
        try:
            adapter = await self._ensure_adapter()
            if self._rule_engine is None:
                self._rule_engine = RuleEngine(adapter, self._notifier)
            await poll_cycle(
                adapter, self._redis_client, self._pipeline, self._anomaly_engine, self._rule_engine,
                self._wan_bandwidth_detector, self._notifier,
            )
            await self._reconcile_arp_table(adapter)
            await self._reconcile_block_enforcement(adapter)
            self._last_poll_at = datetime.now(timezone.utc)
            self._last_poll_error = None
            self._last_poll_duration_s = time.monotonic() - start
        except Exception as exc:
            logger.exception('Poll cycle failed')
            self._last_poll_error = str(exc)

    async def _secondary_poll_job(self) -> None:
        """Visibility-only poll for the second, non-active router, if one is
        configured — see poll_secondary_router's docstring for exactly what
        this does and doesn't do relative to _poll_job. A no-op cycle (not
        an error) when no second router is configured, which is the common
        case — most installs only ever have Sagemcom, and _ensure_secondary_
        adapter() returns None for them every time without attempting a
        connection.
        """
        try:
            adapter = await self._ensure_secondary_adapter()
            if adapter is None:
                return
            await poll_secondary_router(adapter, self._redis_client)
        except Exception:
            logger.exception('Secondary router poll cycle failed')

    async def _reconcile_arp_table(self, adapter: RouterAdapter) -> None:
        """Re-seed ArpWatcher's IP->MAC table from the router's live DHCP
        leases roughly every ARP_DHCP_RECONCILE_INTERVAL_S — called every
        15s poll cycle (same as _startup_job's one-time version of this
        overlay at boot, see its comment for the full rationale), but only
        actually does anything once that interval has elapsed. A DHCP-lease
        fetch on every single 15s tick, forever, just to catch drift that
        moves far slower than that, was needless router chatter — the
        in-the-moment case (ArpWatcher actually reporting a live mismatch)
        is handled separately and faster by _verify_arp_change_against_dhcp,
        which this cadence deliberately does *not* try to substitute for.

        A device's DHCP lease can move it to a new IP at any point during a
        long uptime, not just around a restart; without this, that
        perfectly ordinary reassignment sits as drift between our cache and
        reality until ArpWatcher's next live observation of that IP
        disagrees with its own (by-then-stale) table entry — indistinguishable,
        from inside ArpWatcher, from an actual spoofing attempt. seed()
        silently overwrites rather than going through _process()'s
        spoof-comparison logic, which is exactly what's wanted here: a
        DHCP-confirmed reassignment is legitimate by definition, so
        reconciling ahead of the next packet means there's nothing left to
        misdiagnose. Never raises — a DHCP-leases fetch failing this cycle
        just means reconciliation waits for the next one, same as any other
        best-effort poll-cycle side task.
        """
        if not self._arp_watcher.is_active:
            return
        now = time.monotonic()
        if (
            self._last_arp_reconcile_at is not None
            and now - self._last_arp_reconcile_at < ARP_DHCP_RECONCILE_INTERVAL_S
        ):
            return
        self._last_arp_reconcile_at = now
        try:
            leases = await adapter.get_dhcp_leases()
        except Exception:
            logger.debug('ARP-table reconciliation: could not fetch DHCP leases this cycle', exc_info=True)
            return
        pairs = [(lease.ip_address, lease.mac_address) for lease in leases if lease.ip_address]
        if pairs:
            self._arp_watcher.seed(pairs)

    async def _reconcile_block_enforcement(self, adapter: RouterAdapter) -> None:
        """Compares devices.is_blocked against the router's own live
        BlacklistStatus for every MAC it currently has a Host entry for, and
        corrects any mismatch it finds. Rate-limited to
        BLOCK_ENFORCEMENT_RECONCILE_INTERVAL_S the same way
        _reconcile_arp_table is — see that constant's comment.

        Why this exists: devices.is_blocked is Heimdall's own memory of
        what it *asked* the router to do, not a live read of what the
        router is *actually* enforcing right now. Those two can drift —
        confirmed live 2026-08-30, and the specific gap this closes: a
        blocked device's MAC rotates (see _identity_link_job), gets
        recognized as the same device, and — before _propagate_block_
        after_link existed — the new MAC would end up fully unblocked at
        the router while the dashboard kept showing the old MAC as
        blocked. This job is the general-purpose safety net for that
        entire class of bug, not just the one instance already fixed
        directly: any other cause of the same drift (a Host record that
        lost its schedule, a block applied or cleared by hand at the
        router's own admin UI) gets caught here too, without needing its
        own dedicated fix.

        get_connected_devices() is usually a cache hit by the time this
        runs (see SagemcomXmoAdapter's 5-minute cache) — this adds no
        router calls of its own in the common case. A MAC the router
        currently has no Host entry for at all (e.g. it's been gone long
        enough to age out) is skipped rather than treated as "confirmed
        unblocked" — no live signal for it either way this cycle.
        """
        now = time.monotonic()
        if (
            self._last_block_reconcile_at is not None
            and now - self._last_block_reconcile_at < BLOCK_ENFORCEMENT_RECONCILE_INTERVAL_S
        ):
            return
        self._last_block_reconcile_at = now

        try:
            devices = await adapter.get_connected_devices()
        except Exception:
            logger.debug('Block-enforcement reconciliation: could not fetch device list this cycle', exc_info=True)
            return
        router_state = {d.mac_address: d.is_blacklisted_at_router for d in devices}
        if not router_state:
            return

        async with get_session() as session:
            db_state = (await session.execute(select(Device.mac_address, Device.is_blocked))).all()

        for mac, db_blocked in db_state:
            if mac not in router_state:
                continue
            router_blocked = router_state[mac]
            if db_blocked != router_blocked:
                await self._correct_block_drift(mac, db_blocked=db_blocked, router_blocked=router_blocked)

    async def _correct_block_drift(self, mac: str, *, db_blocked: bool, router_blocked: bool) -> None:
        """One MAC where devices.is_blocked disagrees with the router's own
        live enforcement state — see _reconcile_block_enforcement. Raises a
        BLOCK_ENFORCEMENT_DRIFT alert either way (via upsert, so repeated
        drift on the same MAC touches one row instead of spamming).

        The router is the source of truth in *both* directions — this only
        ever updates Heimdall's own record to match what the router
        reports, never calls block_device()/unblock_device() to push
        Heimdall's belief back onto the router.

        This used to be asymmetric: "DB blocked, router disagrees" re-issued
        the block instead of updating the record, on the theory that the
        admin's original intent (recorded in Heimdall) should win. Changed
        after a real incident: an admin unblocked a device directly via the
        router's own admin UI (because Heimdall's own unblock wasn't
        working at the time), and the old behavior would have silently
        re-blocked it right back the next reconciliation cycle — fighting a
        deliberate, out-of-band admin action, exactly the failure mode the
        *other* direction was already careful to avoid. There is no way to
        tell "the block silently decayed" apart from "an admin reversed it
        on purpose" from in here, so don't try — the router's live state
        always wins, and Settings.DISABLE_AUTO_BLOCK is irrelevant to this
        method now that it never calls block_device()/unblock_device() at
        all.
        """
        async with get_session() as session:
            device = await session.get(Device, mac)
            if device is not None:
                device.is_blocked = router_blocked

        if db_blocked and not router_blocked:
            description = (
                f'{mac} was marked blocked in Heimdall but the router reports it is not currently '
                f'blacklisted (unblocked directly at the router, the block expired, or it never took '
                f'effect) — updated Heimdall\'s record to match.'
            )
            severity = 'WARNING'
        else:
            description = (
                f'{mac} is blacklisted at the router but Heimdall had no record of blocking it — likely '
                f'blocked manually via the router\'s own admin UI. Updated Heimdall\'s record to match.'
            )
            severity = 'INFO'

        alert, is_new = await AlertRepository().upsert(
            device_mac=mac, alert_type='BLOCK_ENFORCEMENT_DRIFT', severity=severity, description=description,
            raw_data={'db_blocked': db_blocked, 'router_blocked': router_blocked},
        )
        if is_new:
            emit_alert(alert_to_dict(alert))

    async def _verify_arp_change_against_dhcp(self, ip: str, new_mac: str) -> bool:
        """The "actively poll" half of the adaptive-cadence request: when
        ArpWatcher reports a live IP->MAC mismatch, don't wait for the next
        ARP_DHCP_RECONCILE_INTERVAL_S reconciliation and don't trust a
        single DHCP snapshot either — a freshly-issued lease can take a
        moment to show up. Polls the router's DHCP leases up to
        self._arp_verify_max_attempts times, self._arp_verify_retry_interval_s
        apart, and returns True the moment any attempt shows `new_mac` as
        the current lease holder for `ip` — i.e. the router's own data
        confirms this is a legitimate reassignment, not spoofing. Returns
        False (unresolved) if every attempt disagrees or errors — the
        caller treats that as "raise ARP_SPOOF/auto-block as before".
        """
        if not ip or not new_mac:
            return False
        try:
            adapter = await self._ensure_adapter()
        except Exception:
            return False

        for attempt in range(self._arp_verify_max_attempts):
            try:
                leases = await adapter.get_dhcp_leases()
            except Exception:
                logger.debug('ARP verification: DHCP-leases fetch failed (attempt %d)', attempt + 1, exc_info=True)
                leases = []
            if any(lease.ip_address == ip and lease.mac_address == new_mac for lease in leases):
                logger.info(
                    'ARP change for %s (-> %s) confirmed legitimate by a live DHCP lease '
                    '(attempt %d) — not treating as spoofing', ip, new_mac, attempt + 1,
                )
                return True
            if attempt < self._arp_verify_max_attempts - 1:
                await asyncio.sleep(self._arp_verify_retry_interval_s)
        return False

    async def _startup_job(self) -> None:
        """Runs once at boot: seed + start the packet-sniffing watchers, and
        do an initial threat feed refresh so /api/threats/feeds isn't empty
        until the first nightly cron fires."""
        try:
            async with get_session() as session:
                result = await session.execute(select(Device.ip_address, Device.mac_address))
                pairs = [(ip, mac) for ip, mac in result.all() if ip]
            # Then overlay with the router's own live DHCP leases, if
            # reachable — confirmed live 2026-08-28 that `devices.ip_address`
            # can drift stale between polls (a device's DHCP lease moves it
            # to a new IP; our own record doesn't always catch up in time),
            # and ArpWatcher seeding from that stale pairing is exactly what
            # turned a routine DHCP reassignment into a false ARP_SPOOF
            # finding + auto-block right after a restart. seed() lets later
            # entries in the list win per-IP, so appending lease pairs after
            # the DB ones means the router's fresher truth overrides our own
            # cache wherever the two disagree, while devices only known via
            # the DB (leases call failed, or a statically-addressed device
            # DHCP never sees) still get seeded from what we do have. See
            # DhcpLease's docstring and _reconcile_arp_table, which repeats
            # this same overlay every poll cycle so drift during a long
            # uptime — not just at startup — self-heals too.
            try:
                adapter = await self._ensure_adapter()
                leases = await adapter.get_dhcp_leases()
                pairs += [(lease.ip_address, lease.mac_address) for lease in leases]
            except Exception:
                logger.warning(
                    'Could not fetch DHCP leases for ARP-watcher seeding — '
                    "falling back to the devices table's last-known pairings",
                    exc_info=True,
                )
            self._arp_watcher.seed(pairs)
            self._arp_watcher.start()
            self._fingerprinter.start()
        except Exception:
            logger.exception('Failed to start ARP watcher / passive fingerprinter')

        try:
            if self._router_ip:
                self._dhcp_watcher.start()
            else:
                logger.warning('Router IP could not be resolved — DHCP watcher not started')
        except Exception:
            logger.exception('Failed to start DHCP watcher')

        try:
            if self._wifi_monitor is not None:
                self._wifi_monitor.start()
        except Exception:
            logger.exception('Failed to start WiFi monitor watcher')

        try:
            await self._threat_intel.refresh_feeds()
        except Exception:
            logger.exception('Initial threat feed refresh failed')

    async def _nmap_scan_job(self) -> None:
        """Nightly OS/service scan of every known device, stored in devices.nmap_profile.

        Also treats several nmap findings as an attack rather than routine
        profile data: a high-risk port (see HIGH_RISK_PORTS) that was closed
        on the previous scan and is open now — a common sign a device has
        been compromised and is now running a backdoor/remote-admin service
        (skipped entirely for a port explicitly allowlisted for that device,
        see PortAllowlistRepository — a known-legitimate service, e.g. a
        print server's SMB share, should never be flagged as this kind of
        finding again); any finding from nmap's `--script vuln` NSE
        category; any finding from a curated default/blank-credential NSE
        script set (kept as a separate alert type from vuln findings — a
        CVE and an exposed default password are different kinds of
        problem); and a disagreement between this scan's active OS
        detection and PassiveFingerprinter's most recent passive guess
        (both write to Device.os_fingerprint, so without this check they'd
        silently clobber each other with no cross-reference at all). All
        four route through _raise_threat_alert, which auto-blocks the
        device if auto_block_on_threat is armed.
        """
        try:
            async with get_session() as session:
                result = await session.execute(
                    select(Device.mac_address, Device.ip_address, Device.nmap_profile)
                )
                devices = [(mac, ip, profile) for mac, ip, profile in result.all() if ip]
        except Exception:
            logger.exception('Failed to load device list for nmap scan')
            return

        for mac, ip, previous_profile in devices:
            try:
                await self._scan_one_device(mac, ip, previous_profile)
            except Exception:
                logger.exception('nmap scan failed for %s (%s)', mac, ip)

        self._last_nmap_scan_at = datetime.now(timezone.utc)

    async def _scan_one_device(self, mac: str, ip: str, previous_profile: dict | None) -> None:
        """The actual per-device scan-and-alert work _nmap_scan_job loops
        over — split out so a test can exercise this against one device
        directly, without going through _nmap_scan_job's own device-list
        query. That query is intentionally unscoped (every device with a
        known IP, matching this job's real job — scan the whole network),
        which is exactly what makes it dangerous to call from a test on a
        database shared with a live, populated deployment: confirmed live,
        the previous test shape (calling _nmap_scan_job() directly with a
        mocked self._scanner) scanned every real device the shared dev DB
        happened to have at the time, not just the test's own seeded one —
        writing fake HIGH_RISK_PORT_OPENED/VULNERABILITY_DETECTED/
        CREDENTIAL_EXPOSURE_DETECTED alerts and a bogus nmap_profile/
        os_fingerprint onto every one of them. Calling this method directly
        exercises the identical alerting/profile-writing logic against only
        the one (mac, ip) a test passes in.
        """
        scan = await self._scanner.scan_device(ip)
        previous_open_ports = {
            p['port'] for p in (previous_profile or {}).get('ports', [])
            if p.get('state') == 'open'
        }
        allowed_ports = await PortAllowlistRepository().allowed_ports_for(mac)
        newly_opened_high_risk = {
            p.port: HIGH_RISK_PORTS[p.port] for p in scan.ports
            if p.state == 'open' and p.port in HIGH_RISK_PORTS and p.port not in previous_open_ports
            and p.port not in allowed_ports
        }

        profile = {
            'os': scan.os,
            'ports': [dataclasses.asdict(p) for p in scan.ports],
            'scanned_at': datetime.now(timezone.utc).isoformat(),
        }
        async with get_session() as session:
            device = await session.get(Device, mac)
            if device is not None:
                previous_passive_os = device.os_fingerprint
                device.nmap_profile = profile
                if scan.os != 'Unknown':
                    device.os_fingerprint = scan.os
            else:
                previous_passive_os = None

        for port, service in newly_opened_high_risk.items():
            await self._raise_threat_alert(
                mac, 'HIGH_RISK_PORT_OPENED', 'CRITICAL',
                f'{ip} newly exposes {service} on port {port} '
                f'(closed on the previous scan)',
                raw_data={'ip': ip, 'port': port, 'service': service},
                dedup_key=f'port:{port}',
            )

        if scan.os != 'Unknown' and previous_passive_os:
            passive_family = os_family(previous_passive_os)
            active_family = os_family(scan.os)
            if (
                passive_family != 'unknown'
                and active_family != 'unknown'
                and passive_family != active_family
            ):
                await self._raise_threat_alert(
                    mac, 'OS_FINGERPRINT_CONFLICT', 'WARNING',
                    f'{ip} was passively fingerprinted as "{previous_passive_os}" but '
                    f'nmap\'s active scan identifies it as "{scan.os}" — possible MAC '
                    f'spoofing or misclassification',
                    raw_data={'ip': ip, 'passive_os': previous_passive_os, 'active_os': scan.os},
                )

        vuln_findings = await self._scanner.vuln_scan(ip)
        if vuln_findings:
            await self._raise_threat_alert(
                mac, 'VULNERABILITY_DETECTED', 'CRITICAL',
                f'nmap vulnerability scan flagged {ip}: {", ".join(vuln_findings.keys())}',
                raw_data={'ip': ip, 'findings': vuln_findings},
            )

        credential_findings = await self._scanner.credential_scan(ip)
        if credential_findings:
            await self._raise_threat_alert(
                mac, 'CREDENTIAL_EXPOSURE_DETECTED', 'CRITICAL',
                f'nmap credential scan flagged {ip}: {", ".join(credential_findings.keys())}',
                raw_data={'ip': ip, 'findings': credential_findings},
            )

    async def _threat_feed_refresh_job(self) -> None:
        try:
            await self._threat_intel.refresh_feeds()
        except Exception:
            logger.exception('Threat feed refresh failed')

    async def _data_retention_job(self) -> None:
        """Roll off data older than SettingsRepository's data_retention_days
        (env default: Settings.DATA_RETENTION_DAYS) — read fresh every run so
        an admin's change in the Settings tab takes effect on the very next
        nightly run, not just future data.

        traffic_samples/port_stats are TimescaleDB hypertables: drop_chunks()
        removes whole chunks below the cutoff, far cheaper than a row-by-row
        DELETE at this table's poll-driven volume. It's chunk-granular, not
        row-exact — a chunk straddling the cutoff is kept whole, so actual
        retention can run up to one chunk_time_interval (default 7 days)
        longer than configured; that's normal, expected TimescaleDB behavior.

        alerts/wan_status_history are plain tables, so a direct DELETE is
        used instead. devices/trusted_macs are deliberately untouched —
        those represent current known-device state, not a time-series
        history, and pruning them would risk re-triggering NEW_DEVICE alerts
        for a device that's simply been offline (e.g. a seasonal device) for
        longer than the retention window.

        wifi_sightings prunes the same way as alerts (plain DELETE, same
        cutoff/setting) — reuses data_retention_days rather than a
        dedicated knob, since a neighbor's device not seen in that long is
        exactly the same "stale, roll it off" judgment call as an old alert.
        """
        try:
            days = await SettingsRepository().get_data_retention_days()
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            async with get_session() as session:
                # CAST: drop_chunks' older_than is polymorphic, so asyncpg can't infer
                # the parameter's type ("could not determine data type of parameter
                # $1") and without it the whole job — including the DELETEs below —
                # rolled back on every run, i.e. retention never actually ran.
                await session.execute(
                    text("SELECT drop_chunks('traffic_samples', older_than => CAST(:cutoff AS timestamptz))"), {'cutoff': cutoff}
                )
                await session.execute(
                    text("SELECT drop_chunks('port_stats', older_than => CAST(:cutoff AS timestamptz))"), {'cutoff': cutoff}
                )
                await session.execute(delete(WanStatusHistory).where(WanStatusHistory.changed_at < cutoff))
                await session.execute(delete(Alert).where(Alert.created_at < cutoff))
                await session.execute(delete(WifiSighting).where(WifiSighting.last_seen < cutoff))
                await session.execute(delete(WifiNetwork).where(WifiNetwork.last_seen < cutoff))
            logger.info('Data retention cleanup complete (cutoff: %s, retention: %d days)', cutoff, days)
        except Exception:
            logger.exception('Data retention cleanup failed')

    async def _block_expiry_job(self) -> None:
        """Auto-unblocks devices whose auto-block passed its configured
        expiry (AppSettings.auto_block_expiry_hours), notifies for review,
        and records a low-severity AUTO_BLOCK_EXPIRED alert so the event is
        visible in the Alerts history, not just a transient notification.

        Only ever touches devices with blocked_until set — manual blocks
        (POST /devices/<mac>/block) leave it NULL and are never auto-expired.
        Runs on an interval (not a nightly cron) so a 24h SLA doesn't slip
        by up to a full day; see Settings.BLOCK_EXPIRY_CHECK_INTERVAL_SECONDS.
        """
        try:
            now = datetime.now(timezone.utc)
            async with get_session() as session:
                result = await session.execute(
                    select(Device.mac_address, Device.hostname).where(
                        Device.is_blocked.is_(True),
                        Device.blocked_until.isnot(None),
                        Device.blocked_until < now,
                    )
                )
                expired = result.all()
            if not expired:
                return

            expiry_hours = await SettingsRepository().get_auto_block_expiry_hours()
            for mac, hostname in expired:
                try:
                    adapter = await self._adapter_for_mac(mac)
                    unblocked = await adapter.unblock_device(mac)
                except Exception:
                    logger.exception('Failed to auto-unblock expired block for %s', mac)
                    continue
                if not unblocked:
                    logger.warning('Router rejected auto-unblock for expired block on %s', mac)
                    continue

                label = hostname or mac
                description = (
                    f'{label} was auto-unblocked after {expiry_hours}h — '
                    f'review and re-block if still suspicious'
                )
                async with get_session() as session:
                    device = await session.get(Device, mac)
                    if device is not None:
                        device.is_blocked = False
                        device.blocked_at = None
                        device.blocked_until = None
                    alert = Alert(
                        device_mac=mac, alert_type='AUTO_BLOCK_EXPIRED', severity='INFO',
                        description=description, raw_data={'expiry_hours': expiry_hours},
                    )
                    session.add(alert)
                emit_alert(alert_to_dict(alert))
                if self._notifier is not None:
                    await self._notifier.notify(
                        title='Auto-block expired', message=description, severity='WARNING',
                    )
        except Exception:
            logger.exception('Block expiry check failed')

    async def _correlation_job(self) -> None:
        """Scans recent alerts for the curated cross-alert patterns in
        sentinel/detection/correlation.py (e.g. NEW_DEVICE immediately
        followed by ARP_SPOOF) and escalates matches to a single
        COMPROMISE_CHAIN_DETECTED incident, routed through
        _raise_threat_alert like any other high-confidence finding (so it's
        eligible for auto-block the same way, and reuses the same
        alert-persist + websocket-broadcast path)."""
        try:
            async with get_session() as session:
                incidents = await self._correlator.find_new_incidents(session)
            for incident in incidents:
                await self._raise_threat_alert(
                    incident['mac'], 'COMPROMISE_CHAIN_DETECTED', 'CRITICAL',
                    f"{incident['mac']} {incident['description']}",
                    raw_data={
                        'pattern': incident['pattern_name'],
                        'trigger_alert_id': incident['trigger_alert_id'],
                        'follow_alert_id': incident['follow_alert_id'],
                    },
                )
        except Exception:
            logger.exception('Cross-alert correlation scan failed')

    async def _alert_auto_resolve_job(self) -> None:
        """Closes every open alert whose last_seen predates
        AppSettings.alert_auto_resolve_hours (default 72h) — the fallback
        for sources with no natural "this stopped" signal of their own
        (ArpWatcher/DhcpWatcher/PassiveFingerprinter/OpenCanary/Zeek/
        Suricata/nmap's CRITICAL finding types — everything that routes
        through _raise_threat_alert/_persist_ip_conflict_alert without ever
        calling resolve()). Read fresh from SettingsRepository every run so
        an admin's change in the Settings tab takes effect on the very next
        sweep. See AlertRepository.resolve_stale_open.
        """
        try:
            hours = await SettingsRepository().get_alert_auto_resolve_hours()
            closed = await AlertRepository().resolve_stale_open(timedelta(hours=hours))
            if closed:
                logger.info('Alert auto-resolve: closed %d alert(s) past %dh with no recurrence', closed, hours)
        except Exception:
            logger.exception('Alert auto-resolve sweep failed')

    async def _identity_link_job(self) -> None:
        """Auto-links every device row confirmed unreachable in a hostname
        group onto the single member of that group confirmed reachable —
        the heuristic (sharing a hostname, presenting a randomized MAC —
        see sentinel/detection/device_identity.py) only proposes which
        groups to probe; only the ARP confirmation decides who gets linked.
        Deliberately does NOT use Device.is_online/last_seen to pre-filter
        candidates — this router's Hosts/AssociatedDevices view is
        confirmed persistently stale for MACs that are actually long gone
        (see device_identity.py's module docstring), so trusting either
        would silently exclude exactly the rows this feature exists to fix.

        Only acts when EXACTLY ONE member of a group answers: zero
        reachable means the phone is currently fully offline (too soon to
        guess which MAC it'll come back as); two or more reachable means
        this hostname might genuinely belong to more than one physical
        device (e.g. two identical phone models in the household) — safer
        to do nothing than guess wrong in either case.

        Raises a low-severity, one-off DEVICE_IDENTITY_LINKED alert per
        link (same "record + broadcast a system event so it's visible in
        the Alerts history, not just a transient notification" pattern as
        _block_expiry_job's AUTO_BLOCK_EXPIRED) so the linked-away device's
        page — and its UNLINK button, for when this gets it wrong — is
        discoverable.

        Also resolves any still-open NEW_DEVICE alert on the old MAC, and
        any still-open ARP_SPOOF alert on the new one —
        NewDeviceDetector/ArpWatcher both fire within one poll of any
        first-seen MAC or unconfirmed rotation, including a phone's own
        address rotating under WiFi MAC randomization, with no awareness of
        this job at all. Confirmed live: a CRITICAL NEW_DEVICE alert stayed
        open indefinitely even after the exact same phone was later
        successfully linked here. This doesn't stop either alert from
        firing in the first place (those run within a poll cycle; this job
        runs on its own 5-minute schedule, so some lag is unavoidable) — it
        just makes sure a since-explained alert doesn't sit open forever
        once the explanation exists.

        Two independent ways to propose a link, both requiring direct ARP
        confirmation before anything is actually linked (see
        device_identity.py):
        - find_candidate_groups: devices sharing a hostname.
        - find_ip_continuity_candidates: a fallback for a rotated MAC whose
          Host entry never got a hostname at all, so it can never match the
          hostname rule no matter how many times it reconnects. Confirmed
          live 2026-08-30 this is a real, recurring case, not theoretical.
        """
        try:
            async with get_session() as session:
                groups = await self._identity_linker.find_candidate_groups(session)
                ip_candidates = await self._identity_linker.find_ip_continuity_candidates(session)

            for group in groups:
                reachable: list[str] = []
                unreachable: list[str] = []
                for member in group['members']:
                    mac, ip = member['mac_address'], member['ip_address']
                    try:
                        if ip and await self._liveness_probe.is_reachable(ip):
                            reachable.append(mac)
                        else:
                            unreachable.append(mac)
                    except LivenessProbeError:
                        logger.warning('Identity-link ARP probe failed for %s — excluding it this scan', mac)

                if len(reachable) != 1:
                    continue  # ambiguous — nothing or more than one answered, too risky to guess
                new_mac = reachable[0]

                for old_mac in unreachable:
                    reason = (
                        f'Hostname "{group["hostname"]}" is shared by multiple randomized MACs; '
                        f'{old_mac} is unreachable while {new_mac} is confirmed alive — likely the same '
                        f'device reconnecting under a rotated WiFi MAC.'
                    )
                    await self._complete_identity_link(old_mac, new_mac, group['hostname'], reason, 'hostname')

            for candidate in ip_candidates:
                old_mac, new_mac, ip = candidate['old_mac'], candidate['new_mac'], candidate['ip_address']
                try:
                    # Both DB rows share this same on-file IP (that's the
                    # whole premise of the fallback) — is_reachable can't
                    # tell them apart, so this needs to know *which* MAC is
                    # actually answering, not just whether anything is.
                    resolved_mac = await self._liveness_probe.resolve_mac(ip)
                except LivenessProbeError:
                    logger.warning('Identity-link IP-continuity ARP probe failed for %s — excluding it', ip)
                    continue
                if resolved_mac != new_mac:
                    continue  # not (yet) confirmed as the one actually holding this IP

                reason = (
                    f'{new_mac} has no hostname reported yet, but direct ARP confirms it is the device '
                    f'currently answering at {ip} — the same IP {old_mac} ("{candidate["hostname"]}") was '
                    f'last seen on before going quiet. Likely the same device reconnecting under a '
                    f'rotated WiFi MAC.'
                )
                await self._complete_identity_link(
                    old_mac, new_mac, candidate['hostname'], reason, 'ip_continuity',
                )
        except Exception:
            logger.exception('Device identity-link scan failed')

    async def _complete_identity_link(
        self, old_mac: str, new_mac: str, hostname: str, reason: str, match: str,
    ) -> None:
        """Shared finish for both _identity_link_job proposal paths once a
        link is ARP-confirmed: writes the link, resolves whichever alerts
        the rotation already caused, propagates a block if the old MAC had
        one, and raises the DEVICE_IDENTITY_LINKED alert. `match`
        ('hostname' | 'ip_continuity') is stamped onto raw_data purely so
        the two paths stay distinguishable in the Alerts history.
        """
        linked = await DeviceRepository().link(old_mac=old_mac, new_mac=new_mac, reason=reason)
        if linked is None:
            return

        await AlertRepository().resolve(device_mac=old_mac, alert_type='NEW_DEVICE')
        await AlertRepository().resolve(device_mac=new_mac, alert_type='ARP_SPOOF')

        description = f'{hostname} ({old_mac}) linked to {new_mac} — {reason}'
        # Confirmed real bypass, not theoretical: block_device() blacklists
        # old_mac's own Host entry at the router — new_mac gets a
        # completely fresh, unblocked Host entry the moment it appears, and
        # link() above only ever touches linked_to_mac/linked_at/
        # link_reason. Without this, blocking a device and then having its
        # MAC rotate (which this whole job exists to recognize) would
        # silently un-block it in every way that matters, while the
        # dashboard kept showing the old MAC as blocked. `linked` is the
        # refreshed old-mac row link() returns, so linked.is_blocked
        # reflects its state at the moment of linking.
        if linked.is_blocked:
            description += await self._propagate_block_after_link(old_mac, new_mac)

        async with get_session() as session:
            alert = Alert(
                device_mac=new_mac, alert_type='DEVICE_IDENTITY_LINKED', severity='INFO',
                description=description,
                raw_data={'old_mac': old_mac, 'new_mac': new_mac, 'reason': reason, 'match': match},
            )
            session.add(alert)
        emit_alert(alert_to_dict(alert))

    async def _propagate_block_after_link(self, old_mac: str, new_mac: str) -> str:
        """old_mac was blocked before being recognized as the same physical
        device as new_mac — re-issue the block against new_mac's own Host
        entry so it actually carries over (see _identity_link_job's comment
        for why this doesn't happen automatically). Returns a suffix to
        append to the DEVICE_IDENTITY_LINKED alert's description — never
        silently claims success, same convention as _raise_threat_alert's
        'AUTO-BLOCK FAILED' wording, since a linked device that's actually
        still unprotected must not read as if nothing needs attention.
        Also honors Settings.DISABLE_AUTO_BLOCK — same kill-switch
        _raise_threat_alert checks, since this is just as much an
        auto-block action as any other and must be just as inert while
        it's set.
        """
        if settings.DISABLE_AUTO_BLOCK:
            return f' — {old_mac} was blocked; AUTO-BLOCK DISABLED (dev override) — not propagated to {new_mac}'

        try:
            adapter = await self._adapter_for_mac(new_mac)
            blocked_now = await adapter.block_device(new_mac)
        except Exception:
            logger.exception('Failed to propagate block from %s to %s after identity link', old_mac, new_mac)
            blocked_now = False

        if not blocked_now:
            return (
                f' — {old_mac} was blocked; AUTO-BLOCK PROPAGATION TO {new_mac} FAILED, '
                f'device may be unprotected (see backend logs)'
            )

        async with get_session() as session:
            new_device = await session.get(Device, new_mac)
            if new_device is not None:
                new_device.is_blocked = True
                expiry_hours = await SettingsRepository().get_auto_block_expiry_hours()
                now = datetime.now(timezone.utc)
                new_device.blocked_at = now
                new_device.blocked_until = now + timedelta(hours=expiry_hours) if expiry_hours > 0 else None
        return f' — {old_mac} was blocked; block propagated to {new_mac}'

    async def _stale_device_reap_job(self) -> None:
        """ARP-probes every device the DB currently believes is online and
        marks any that don't answer offline right away, rather than waiting
        for the router's own (often slow) Hosts/AssociatedDevices view to
        notice. A second writer of Device.is_online alongside
        _upsert_devices (sentinel/scheduler/jobs.py) — deliberately not
        reconciled in code: if the router's next poll still reports a
        device active, _upsert_devices simply flips is_online back True,
        exactly as it does today. A probe failure (LivenessProbeError) is
        treated as "unknown", never as "confirmed dead" — see
        sentinel/security/liveness.py.
        """
        try:
            async with get_session() as session:
                result = await session.execute(
                    select(Device.mac_address, Device.ip_address).where(
                        Device.is_online.is_(True),
                        Device.ip_address.isnot(None),
                        Device.linked_to_mac.is_(None),
                    )
                )
                targets = [(mac, ip) for mac, ip in result.all() if ip]

            semaphore = asyncio.Semaphore(8)

            async def _check(mac: str, ip: str) -> str | None:
                async with semaphore:
                    try:
                        return None if await self._liveness_probe.is_reachable(ip) else mac
                    except LivenessProbeError:
                        return None

            unreachable = [mac for mac in await asyncio.gather(*(_check(mac, ip) for mac, ip in targets)) if mac]

            for mac in unreachable:
                try:
                    async with get_session() as session:
                        device = await session.get(Device, mac)
                        if device is not None and device.is_online:
                            device.is_online = False
                except Exception:
                    logger.exception('Failed to mark %s offline after a failed liveness probe', mac)

            if unreachable:
                logger.info('Stale-device reap: marked %d device(s) offline early', len(unreachable))
        except Exception:
            logger.exception('Stale-device reap sweep failed')

    async def _device_archive_sweep_job(self) -> None:
        """Two stages of one devices lifecycle, both admin-tunable from the
        Settings tab and both read fresh from SettingsRepository every run
        (same reasoning as every other tunable sweep in this file):

          1. Soft-archives devices with no activity in AppSettings.
             device_archive_after_days (default 90) — see DeviceRepository.
             archive_stale(). Reversible, nothing deleted.
          2. Permanently deletes devices that have themselves been archived
             for AppSettings.device_purge_after_days (default 90, on top of
             stage 1's window) — see DeviceRepository.purge_archived().
             Requested directly: archived-forever isn't real cleanup, it
             just relocates the clutter. NOT reversible.

        Not the same job as _stale_device_reap_job above — that one
        ARP-probes currently-"online" devices to correct is_online faster
        than the router's own slow view; this one is a much longer-horizon
        sweep for devices that simply haven't been active in a long time.

        No alert raised for either stage (unlike DEVICE_IDENTITY_LINKED) —
        both are routine, low-stakes housekeeping, same posture as
        _data_retention_job's INFO-log-only precedent, not a decision that
        needs prompt human review. Discovery and undo (stage 1 only) happen via
        the Settings tab's device archive section.
        """
        try:
            days = await SettingsRepository().get_device_archive_after_days()
            archived = await DeviceRepository().archive_stale(timedelta(days=days))
            if archived:
                logger.info(
                    'Device archive sweep: archived %d device(s) with no activity in %d+ days', archived, days,
                )
        except Exception:
            logger.exception('Device archive sweep failed')

        # Second, later stage of the same lifecycle — isolated in its own
        # try/except so a purge failure can never suppress the archive
        # step above (or vice versa) having already succeeded this run.
        # See DeviceRepository.purge_archived's own docstring for why this
        # exists: archiving alone never actually deletes anything.
        try:
            purge_days = await SettingsRepository().get_device_purge_after_days()
            purged = await DeviceRepository().purge_archived(timedelta(days=purge_days))
            if purged:
                for mac in purged:
                    self._anomaly_engine.forget(mac)
                logger.info(
                    'Device archive sweep: permanently deleted %d device(s) archived for %d+ days: %s',
                    len(purged), purge_days, ', '.join(purged),
                )
        except Exception:
            logger.exception('Device purge sweep failed')

    async def _security_digest_job(self) -> None:
        """Periodic 'here's what happened' summary. Unlike live per-alert
        notifications (which only fire for alerts matched by an admin-
        defined NOTIFY rule — see RuleEngine._fire), this is the first
        mechanism that reports on every alert type uniformly, since it
        reads the alerts table directly rather than riding along with rule
        evaluation. Sent unconditionally on every cron fire, including a
        calmer "all clear" framing when the window is empty — a periodic
        "still watching, nothing to report" is itself reassurance for a
        home security tool, not noise.

        The actual [cutoff, now) query — alert-type groups, per-device
        traffic, hourly household bandwidth — lives in
        sentinel.notifications.digest_query.build_digest_data, shared with
        the on-demand Reports tab (sentinel/api/routes/reports.py); see
        that module's own docstring for the query shape and every design
        note behind it (why grouped by alert_type instead of one row per
        alert, why traffic is PER_DEVICE-only, why bandwidth is never
        device-scoped, why severity_counts isn't derived from the capped
        groups). This method just resolves the window, calls it once, and
        renders the result both as plain text (render_digest_text — also
        what ntfy gets) and as the tabular HTML email body
        (render_digest_html, via NotificationService's html_message param).
        """
        try:
            settings_repo = SettingsRepository()
            last_sent = await settings_repo.get_last_digest_sent_at()
            now = datetime.now(timezone.utc)
            cutoff = last_sent or (now - timedelta(days=1))

            # Query logic lives in digest_query.py, shared with the Reports
            # tab (sentinel/api/routes/reports.py) — same window-based
            # alert-type/device-traffic/hourly-bandwidth shape, just an
            # on-demand [start, end) x optional device instead of this job's
            # own [cutoff, now) x every device, so the two can never quietly
            # drift apart. See build_digest_data's own docstring.
            async with get_session() as session:
                digest = await build_digest_data(session, cutoff, now)

            message = render_digest_text(
                digest.digest_groups, digest.total, digest.severity_counts, cutoff, digest.truncated,
                digest.total_types, traffic=digest.traffic, traffic_truncated=digest.traffic_truncated,
                total_traffic_devices=digest.total_traffic_devices, hourly_bandwidth=digest.hourly_bandwidth,
            )
            html_message = render_digest_html(
                digest.digest_groups, digest.total, digest.severity_counts, cutoff, now, digest.truncated,
                digest.total_types, traffic=digest.traffic, traffic_truncated=digest.traffic_truncated,
                total_traffic_devices=digest.total_traffic_devices, hourly_bandwidth=digest.hourly_bandwidth,
            )
            severity_counts = digest.severity_counts
            severity = (
                'CRITICAL' if severity_counts.get('CRITICAL')
                else 'WARNING' if severity_counts.get('WARNING')
                else 'INFO'
            )

            if self._notifier is not None:
                # 'Security Digest', not 'Heimdall security digest' —
                # NotificationService._send_email already prefixes every
                # subject with 'Heimdall: ', so the old title doubled up
                # to 'Heimdall: Heimdall security digest'. ntfy's title
                # gets no such prefix, so this reads cleanly there too.
                await self._notifier.notify(
                    title='Security Digest', message=message, severity=severity, html_message=html_message,
                )
            await settings_repo.set_last_digest_sent_at(now)
        except Exception:
            logger.exception('Security digest job failed')

    async def _canary_poll_job(self) -> None:
        """Tail the OpenCanary log and raise a threat alert for any new
        honeypot-interaction event. Any connection to a honeypot service is
        inherently malicious (nothing legitimate ever talks to one), so this
        goes through _raise_threat_alert like every other attack-signal
        source — a real intrusion here should auto-block exactly as an
        ARP-spoof or Suricata hit does, not just get logged."""
        self._last_canary_check_at = datetime.now(timezone.utc)
        lines = self._canary_reader.read_new_lines()
        for line in lines:
            alert = self._canary_ingester.parse_event(line)
            if alert is None:
                continue
            try:
                await self._persist_canary_alert(alert)
            except Exception:
                logger.exception('Failed to persist OpenCanary alert')

    async def _persist_canary_alert(self, alert: Alert) -> None:
        src_host = alert.raw_data.get('src_host')
        mac = await self._mac_for_ip(src_host) if src_host else None
        await self._raise_threat_alert(
            mac, alert.alert_type, alert.severity, alert.description, raw_data=alert.raw_data,
        )

    async def _mac_for_ip(self, ip: str) -> str | None:
        """Resolve a source IP (as seen in a Zeek log line) to a known device_mac —
        same lookup _persist_canary_alert uses for OpenCanary's src_host."""
        async with get_session() as session:
            result = await session.execute(select(Device.mac_address).where(Device.ip_address == ip))
            return result.scalars().first()

    async def _zeek_dns_poll_job(self) -> None:
        """Tail Zeek's dns.log, record every query, and raise an alert for
        any query against a domain ThreatIntelService's URLhaus feed has
        flagged as malicious."""
        self._last_zeek_dns_check_at = datetime.now(timezone.utc)
        for line in self._zeek_dns_reader.read_new_lines():
            parsed = self._zeek_dns_ingester.parse_event(line)
            if parsed is None:
                continue
            source_ip, query = parsed
            try:
                await self._persist_dns_query(source_ip, query)
            except Exception:
                logger.exception('Failed to persist Zeek DNS query')

    async def _persist_dns_query(self, source_ip: str, query: str) -> None:
        mac = await self._mac_for_ip(source_ip)
        is_malicious = self._threat_intel.is_domain_malicious(query)
        async with get_session() as session:
            session.add(DnsQuery(
                time=datetime.now(timezone.utc),
                device_mac=mac,
                query=query,
                blocked=is_malicious,
                list_name='urlhaus' if is_malicious else None,
            ))
        if is_malicious:
            await self._raise_threat_alert(
                mac, 'DNS_MALICIOUS_QUERY', 'CRITICAL',
                f'{source_ip} queried {query}, which is on the URLhaus malicious-domain feed',
                raw_data={'source_ip': source_ip, 'query': query},
                dedup_key=query,
            )

    async def _zeek_beacon_scan_job(self) -> None:
        """Re-scan Zeek's conn.log for suspiciously regular connection
        intervals (a common C2 beaconing signature) and alert per offending
        (source, destination, destination-port) triple.

        Grouped down to the port because a real beacon always calls home on
        the *same* port — dedup_key includes it too, so distinct ports on
        the same dst are separate incidents, not coalesced into one alert.

        Unlike the volume-spike detectors (ANOMALOUS_VOLUME/HIGH_UPLOAD/
        WAN_BANDWIDTH_SPIKE — see _spike_ip_enrichment_job), a beaconing
        finding already *has* a destination IP with no correlation needed,
        so it's checked against ThreatIntelService right here rather than
        via a separate enrichment pass. Reuses the same raw_data field
        names (remote_ip/remote_ip_connections/remote_ip_malicious) the
        frontend's RemoteIpNote already renders for the spike alerts, so
        this needs no new UI — just populating the same shape. Only
        annotates the alert; a malicious verdict here doesn't escalate to a
        separate MALICIOUS_TRAFFIC_DESTINATION finding the way a spike
        alert's does, since C2_BEACONING is already CRITICAL and already
        auto-block-eligible on its own — the threat-intel check adds
        corroborating context, not a promotion in severity.
        """
        try:
            suspicious = self._zeek_beacon_detector.detect()
        except Exception:
            logger.exception('Zeek beacon scan failed')
            self._last_zeek_beacon_scan_at = datetime.now(timezone.utc)
            return

        for pair in suspicious:
            mac = await self._mac_for_ip(pair['src'])
            verdict = await self._threat_intel.lookup_ip(pair['dst'])
            description = (
                f"{pair['src']} has made {pair['count']} connections to "
                f"{pair['dst']}:{pair['dst_port']} at suspiciously regular "
                f"~{pair['interval_mean_s']}s intervals "
                f"(stddev {pair['interval_std_s']}s) — possible C2 beaconing"
            )
            if verdict['is_malicious']:
                description += ' — destination IP is flagged malicious by threat intelligence'
            await self._raise_threat_alert(
                mac, 'C2_BEACONING', 'CRITICAL', description,
                raw_data={
                    **pair,
                    'remote_ip': pair['dst'],
                    'remote_ip_connections': pair['count'],
                    'remote_ip_malicious': verdict['is_malicious'],
                    'otx_pulses': verdict['otx_pulses'],
                    'in_blocklist': verdict['in_blocklist'],
                },
                dedup_key=f"{pair['dst']}:{pair['dst_port']}",
            )
        self._last_zeek_beacon_scan_at = datetime.now(timezone.utc)

    async def _spike_ip_enrichment_job(self, *, only_alert_ids: set[int] | None = None) -> None:
        """Enriches recent traffic-spike alerts (ANOMALOUS_VOLUME/HIGH_UPLOAD/
        WAN_BANDWIDTH_SPIKE) with the remote IP their traffic was most likely
        headed to/from, correlated via Zeek's conn.log (see
        ZeekConnVolumeCorrelator — the router's own TrafficSample data carries
        no IP at all). An internal (private-range) destination is purely
        informational — another device on this LAN, nothing for threat intel
        to have an opinion about — and is never checked or escalated; only a
        genuinely external destination gets checked against ThreatIntelService.
        See _enrich_spike_alert / _is_internal_ip.

        Zeek-only: self._conn_volume_correlator is None on tiers without
        Zeek, but this job is only registered under the 'zeek' tier gate
        anyway, so the guard below is defensive belt-and-suspenders like
        every other Zeek job here, not the primary gate.

        Each alert is enriched at most once — raw_data.ip_enrichment_done
        marks it, checked in Python rather than a JSONB SQL predicate, since
        the candidate set from the bounded created_at query below is always
        small and NULL/keyless JSONB comparisons in SQL are a footgun. A
        malicious verdict escalates through _raise_threat_alert as a new
        MALICIOUS_TRAFFIC_DESTINATION CRITICAL finding (auto-block eligible),
        dedup_key=remote_ip — the original spike alert is only annotated via
        AlertRepository.merge_raw_data, never escalated in place.

        only_alert_ids is test-only — confirmed a real, live incident, not a
        theoretical risk: this job's candidate query is deliberately
        unscoped (every recent spike-type alert, system-wide, which is
        exactly correct for its real job), and on a database shared with a
        live, populated deployment (this dev environment has no isolated
        test DB) that meant an earlier version of this file's tests, which
        called this method directly with a mocked self._conn_volume_
        correlator, could and did sweep up a real, not-yet-enriched
        HIGH_UPLOAD alert that happened to exist at the time — annotating a
        real device's real alert with the test's literal placeholder IP
        (203.0.113.10). Passing only_alert_ids restricts the candidate set
        to exactly those ids regardless of what else exists in the shared
        table; omitted (the only way the real registered cron job ever
        calls this), behavior is 100% unchanged from before this parameter
        existed.
        """
        if self._conn_volume_correlator is None:
            return
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=_SPIKE_ENRICHMENT_LOOKBACK_MINUTES)
            async with get_session() as session:
                stmt = select(Alert).where(
                    Alert.alert_type.in_(_SPIKE_ALERT_TYPES),
                    Alert.created_at >= cutoff,
                )
                if only_alert_ids is not None:
                    stmt = stmt.where(Alert.id.in_(only_alert_ids))
                candidates = (await session.execute(stmt)).scalars().all()

            for alert in candidates:
                if (alert.raw_data or {}).get('ip_enrichment_done'):
                    continue
                try:
                    await self._enrich_spike_alert(alert)
                except Exception:
                    logger.exception('IP enrichment failed for alert %d', alert.id)
            self._last_spike_ip_enrichment_at = datetime.now(timezone.utc)
        except Exception:
            logger.exception('Spike IP enrichment sweep failed')

    async def _enrich_spike_alert(self, alert: Alert) -> None:
        if alert.device_mac:
            async with get_session() as session:
                device = await session.get(Device, alert.device_mac)
            local_ips = {device.ip_address} if device and device.ip_address else set()
        else:
            # WAN_BANDWIDTH_SPIKE has no device_mac — scope the local-IP set
            # to currently-online devices (not every device ever seen), so a
            # long-offline device's stale, since-reassigned IP can't
            # misattribute traffic. See DeviceRepository.list_online.
            local_ips = {ip for _, ip in await DeviceRepository().list_online()}

        marker: dict = {'ip_enrichment_done': True}
        if not local_ips:
            await AlertRepository().merge_raw_data(alert.id, marker)
            return

        since = alert.created_at - timedelta(minutes=CORRELATION_WINDOW_BEFORE_MINUTES)
        until = alert.created_at + timedelta(minutes=CORRELATION_WINDOW_AFTER_MINUTES)
        talkers = self._conn_volume_correlator.top_talkers(
            local_ips=local_ips, since=since, until=until, top_n=3,
        )
        if not talkers:
            await AlertRepository().merge_raw_data(alert.id, marker)
            return

        top = talkers[0]
        marker.update({
            'remote_ip': top.remote_ip,
            'remote_ip_bytes': top.total_bytes,
            'remote_ip_connections': top.connection_count,
            'remote_ip_local_device': top.local_ip,
        })

        if _is_internal_ip(top.remote_ip):
            # Informational only — see this method's docstring. Skips the
            # threat-intel lookup entirely (meaningless for a private
            # address) and the MALICIOUS_TRAFFIC_DESTINATION escalation
            # below (must never treat another of the user's own devices as
            # a possible compromise).
            marker['remote_ip_internal'] = True
            await AlertRepository().merge_raw_data(alert.id, marker)
            return

        verdict = await self._threat_intel.lookup_ip(top.remote_ip)
        marker.update({'remote_ip_internal': False, 'remote_ip_malicious': verdict['is_malicious']})
        await AlertRepository().merge_raw_data(alert.id, marker)

        if verdict['is_malicious']:
            local_mac = await self._mac_for_ip(top.local_ip) or alert.device_mac
            await self._raise_threat_alert(
                local_mac, 'MALICIOUS_TRAFFIC_DESTINATION', 'CRITICAL',
                f'Traffic linked to a {alert.alert_type.replace("_", " ").lower()} alert was headed to '
                f'{top.remote_ip}, which threat intelligence flags as malicious.',
                raw_data={
                    'remote_ip': top.remote_ip, 'bytes': top.total_bytes,
                    'otx_pulses': verdict['otx_pulses'], 'in_blocklist': verdict['in_blocklist'],
                    'trigger_alert_id': alert.id, 'trigger_alert_type': alert.alert_type,
                },
                dedup_key=top.remote_ip,
            )

    async def _zeek_file_scan_job(self) -> None:
        """Scan every file Zeek's file-extraction analyzer has pulled to disk
        via ClamAV, alerting (and deleting) on anything infected.

        Also refreshes _clamav_reachable here rather than pinging inside
        security_services_snapshot() — that method is read synchronously by
        /api/health, which the frontend polls every 15s per open tab; pinging
        clamd on every one of those requests would open a lot of avoidable
        sockets. This job's own interval is a cheap enough cadence for it.

        Guards on self._clamav being set even though this job is only
        registered when the 'zeek' tier flag is on — defensive, since the
        'clamav' flag is tracked separately and the two only coincide by
        the current tier table's design, not by any hard coupling.
        """
        if self._clamav is None:
            self._last_zeek_file_scan_at = datetime.now(timezone.utc)
            return
        self._clamav_reachable = await self._clamav.ping()

        try:
            extracted = self._zeek_file_watcher.collect()
        except Exception:
            logger.exception('Zeek file-extraction poll failed')
            self._last_zeek_file_scan_at = datetime.now(timezone.utc)
            return

        for filename, data, source_ip in extracted:
            try:
                result = await self._clamav.scan_bytes(data)
            except Exception:
                logger.exception('ClamAV scan failed for extracted file %s', filename)
                continue
            if result:
                mac = await self._mac_for_ip(source_ip) if source_ip else None
                await self._raise_threat_alert(
                    mac, 'MALWARE_DETECTED', 'CRITICAL',
                    f'ClamAV flagged a file downloaded by {source_ip or "an unknown device"} '
                    f'({filename}): {result}',
                    raw_data={'filename': filename, 'source_ip': source_ip, 'clamav_result': result},
                )
        self._last_zeek_file_scan_at = datetime.now(timezone.utc)

    async def _suricata_poll_job(self) -> None:
        """Tail Suricata's eve.json and raise an IDS_SIGNATURE_MATCH alert
        for every new IDS signature match. Only event_type=="alert" lines are
        ingested — Suricata also logs dns/http/tls/flow/stats to the same
        file, but Zeek already covers DNS visibility, so ingesting those too
        would be redundant, not more coverage. See sentinel/security/
        suricata_parser.py's field-shape caveat: this is unverified against
        a live eve.json, so a per-line failure must not drop the rest of
        the batch (same isolation as _canary_poll_job).
        """
        self._last_suricata_check_at = datetime.now(timezone.utc)
        for line in self._suricata_reader.read_new_lines():
            parsed = self._suricata_ingester.parse_event(line)
            if parsed is None:
                continue
            try:
                await self._persist_suricata_alert(parsed)
            except Exception:
                logger.exception('Failed to persist Suricata alert')

    async def _persist_suricata_alert(self, parsed: dict) -> None:
        mac = await self._mac_for_ip(parsed['src_ip'])
        await self._raise_threat_alert(
            mac, 'IDS_SIGNATURE_MATCH', parsed['severity'],
            f"{parsed['src_ip']} triggered Suricata rule \"{parsed['signature']}\" "
            f"({parsed['category']})",
            raw_data=parsed,
        )

    def _on_arp_alert(self, event: dict) -> None:
        """Sync callback invoked from ArpWatcher's own daemon thread — one
        event type is a security finding (ARP_SPOOF, routed to
        _persist_arp_alert), the other is just a passive "something
        connected" nudge (ARP_NEW_IP, routed to _handle_arp_new_ip)."""
        if self._loop is None:
            return
        if event.get('type') == 'ARP_NEW_IP':
            asyncio.run_coroutine_threadsafe(self._handle_arp_new_ip(event), self._loop)
        else:
            asyncio.run_coroutine_threadsafe(self._persist_arp_alert(event), self._loop)

    async def _handle_arp_new_ip(self, event: dict) -> None:
        """ArpWatcher observed a MAC/IP pairing it's never seen before — the
        "actively sync on a connect event" half of the adaptive device-sync
        cadence (see SagemcomXmoAdapter.get_connected_devices' caching).
        Just invalidates the cache; the next poll cycle (~15s, already
        running regardless) does the actual fetch/upsert, same as any other
        cycle — this never touches the DB or raises anything itself, and is
        deliberately not rate-limited: invalidating an already-invalidated
        cache is a no-op, so a burst of new-IP events (e.g. many devices
        reconnecting after a router reboot) costs nothing beyond that one
        eventual re-fetch.
        """
        try:
            adapter = await self._ensure_adapter()
            adapter.invalidate_connected_devices_cache()
        except Exception:
            pass
        # The new IP/MAC pairing could equally belong to the secondary
        # (non-active) router if one is configured — invalidate its cache
        # too rather than assuming it's always the active router's device.
        if self._secondary_adapter is not None:
            self._secondary_adapter.invalidate_connected_devices_cache()

    async def _persist_arp_alert(self, event: dict) -> None:
        # new_mac is the attacker's MAC impersonating a known IP — attribute
        # the alert to it (rather than the previous None) so it's both
        # visible on the alert and available to auto-block.
        new_mac = event.get('new_mac')

        # ArpWatcher can't tell "attacker impersonating a known IP" apart
        # from "two of the user's own devices both configured with the same
        # static IP" — it only sees a MAC change. If the device now holding
        # the IP is one we already trust, treat it as the latter: never
        # auto-block a trusted device over this, and downgrade the noise to
        # a single INFO alert instead of a recurring CRITICAL one. A
        # genuinely untrusted MAC still gets the full ARP_SPOOF/auto-block
        # treatment below, regardless of this IP's conflict history.
        if new_mac and await TrustedMacRepository().is_trusted(new_mac):
            await self._persist_ip_conflict_alert(event, new_mac)
            return

        # Confirmed live 2026-08-30: a device Heimdall has *already*
        # identity-linked (see _identity_link_job/DeviceIdentityLinker) can
        # still trip a fresh ARP_SPOOF hours after linking — the old,
        # rotated-away MAC briefly reappearing on the wire (a stale ARP
        # cache entry elsewhere on the LAN, a gratuitous ARP, or
        # _reconcile_arp_table's own periodic DHCP-lease reseed catching a
        # not-yet-expired old lease) looks identical to spoofing to
        # ArpWatcher, which has no idea the two MACs were ever linked. If
        # both sides of this "change" already resolve to the same canonical
        # identity, it's exactly that kind of already-resolved noise, not a
        # new finding — reseed the table with the confirmed-canonical MAC so
        # ArpWatcher stops flip-flopping between the two, and skip alerting.
        old_mac = event.get('old_mac')
        if old_mac and new_mac:
            device_repo = DeviceRepository()
            old_canonical = await device_repo.canonical_mac(old_mac)
            new_canonical = await device_repo.canonical_mac(new_mac)
            if old_canonical == new_canonical:
                logger.info(
                    'ARP change for %s (%s -> %s) is between two MACs already identity-linked '
                    'as %s — not treating as spoofing', event.get('ip'), old_mac, new_mac, old_canonical,
                )
                self._arp_watcher.seed([(event['ip'], new_mac)])
                return

        # Before treating an untrusted MAC change as spoofing: actively
        # re-poll the router's own DHCP leases (see
        # _verify_arp_change_against_dhcp) to check whether this is actually
        # just an ordinary DHCP reassignment the router already agrees
        # with. Only escalate to a full ARP_SPOOF/auto-block if that
        # doesn't resolve within its retry budget — this is what stops a
        # routine lease handoff (e.g. a device reconnecting and getting a
        # different MAC-to-IP pairing than our own cache expected) from
        # being auto-blocked the moment ArpWatcher notices, while still
        # blocking promptly once the router's own data fails to back up
        # the new pairing.
        if await self._verify_arp_change_against_dhcp(event.get('ip'), new_mac):
            if new_mac:
                self._arp_watcher.seed([(event['ip'], new_mac)])
            return

        # Confirmed live 2026-09-04: the trust check above runs once, before
        # the DHCP-verify retry loop's own wait (up to ARP_VERIFICATION_MAX_
        # ATTEMPTS x ARP_VERIFICATION_RETRY_INTERVAL_S = 45s). A device that
        # arrives during the learning period only gets auto-trusted once the
        # next poll cycle notices it's online (_auto_trust_new_connections_
        # during_learning, jobs.py) — a completely different clock than
        # ArpWatcher's real-time packet detection, with no guarantee the two
        # line up before this point. A second laptop NIC (already-trusted
        # machine, brand-new MAC) plugging in mid-poll-cycle tripped exactly
        # this: trust landed 9s after this alert would have fired, which
        # would have auto-blocked the user's own already-trusted device.
        # Re-checking here catches a trust grant that arrived during the
        # verify wait — narrows the race, doesn't eliminate it (a grant that
        # lands after this point still isn't caught), but costs nothing to
        # add and directly matches an incident that already happened.
        if new_mac and await TrustedMacRepository().is_trusted(new_mac):
            await self._persist_ip_conflict_alert(event, new_mac)
            return

        await self._raise_threat_alert(
            new_mac, event['type'], event['severity'], event['description'], raw_data=event,
        )

    async def _persist_ip_conflict_alert(self, event: dict, new_mac: str) -> None:
        ip = event.get('ip')
        now = datetime.now(timezone.utc)
        if self._ip_conflict_quiet_until.get(ip, now) > now:
            return  # already reported this IP's conflict recently — don't flood
        self._ip_conflict_quiet_until[ip] = now + timedelta(minutes=IP_CONFLICT_QUIET_MINUTES)

        old_mac = event.get('old_mac')
        description = (
            f'{ip} is claimed by more than one device — seen as both {old_mac} and {new_mac} '
            f'(currently trusted). Likely two devices configured with the same static IP, not '
            f'an attack; give one of them a different address to resolve.'
        )
        # dedup_key=ip — two different IPs conflicting for the same trusted
        # device are distinct incidents (see test_conflict_quiet_window_is_
        # keyed_by_ip_not_by_device) and must not coalesce into one row just
        # because they share device_mac/alert_type. No resolve() call —
        # like every other event-triggered source with no natural "this
        # stopped" signal, only the alert_auto_resolve sweep job closes
        # this. The _ip_conflict_quiet_until gate above already limits how
        # often this even reaches upsert().
        alert, is_new = await AlertRepository().upsert(
            device_mac=new_mac, alert_type='IP_CONFLICT', severity='INFO',
            description=description, raw_data=event, dedup_key=ip,
        )
        if is_new:
            emit_alert(alert_to_dict(alert))

    def _on_dhcp_alert(self, event: dict) -> None:
        """Sync callback invoked from DhcpWatcher's own daemon thread."""
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._persist_dhcp_alert(event), self._loop)

    async def _persist_dhcp_alert(self, event: dict) -> None:
        # mac is the rogue server's own MAC (Ethernet src of the OFFER) —
        # attribute the alert to it directly, same as _persist_arp_alert
        # does for new_mac; no DB lookup needed, the sniffed packet already
        # carries it.
        await self._raise_threat_alert(
            event.get('mac'), event['type'], event['severity'], event['description'], raw_data=event,
        )

    def _on_fingerprint(self, ip: str, os_guess: str) -> None:
        """Sync callback invoked from PassiveFingerprinter's own daemon thread."""
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._persist_fingerprint(ip, os_guess), self._loop)

    async def _persist_fingerprint(self, ip: str, os_guess: str) -> None:
        """Records the OS guess, and treats a *change* on an already-known
        device as a possible attack: same IP/MAC, different underlying OS
        signature, suggests hardware was swapped in behind a cloned MAC
        (which a MAC-only check like ArpWatcher can't see, since the MAC
        never changes). Heuristic, not definitive — OS_SIGNATURES is a
        3-entry TTL/window table (see fingerprint.py), so route changes that
        shift TTL by a hop can in principle cause a false mismatch.
        """
        async with get_session() as session:
            result = await session.execute(select(Device).where(Device.ip_address == ip))
            device = result.scalars().first()
            if device is None:
                return
            previous = device.os_fingerprint
            device.os_fingerprint = os_guess
            mac = device.mac_address

        if previous and previous != 'Unknown' and os_guess != 'Unknown' and os_guess != previous:
            await self._raise_threat_alert(
                mac, 'FINGERPRINT_MISMATCH', 'CRITICAL',
                f'{ip} ({mac}) was fingerprinted as "{previous}" but now looks like "{os_guess}" '
                f'on the same MAC — possible MAC-cloning/spoofing',
                raw_data={'ip': ip, 'mac': mac, 'previous_os': previous, 'new_os': os_guess},
            )

    def _on_wifi_alert(self, event: dict) -> None:
        """Sync callback invoked from WifiMonitorWatcher's own daemon thread."""
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._persist_wifi_alert(event), self._loop)

    async def _persist_wifi_alert(self, event: dict) -> None:
        # mac=None — the rogue AP's BSSID isn't a Device we track/could ever
        # block (see _raise_threat_alert's `elif mac:` branch, which cleanly
        # skips the auto-block attempt entirely for a falsy mac); the BSSID/
        # SSID live in raw_data/description instead.
        await self._raise_threat_alert(
            None, event['type'], event['severity'], event['description'], raw_data=event,
        )

    def _on_wifi_sighting(self, event: dict) -> None:
        """Sync callback invoked from WifiMonitorWatcher's own daemon thread."""
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._persist_wifi_sighting(event), self._loop)

    def _on_wifi_network(self, event: dict) -> None:
        """Sync callback invoked from WifiMonitorWatcher's own daemon thread."""
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._persist_wifi_network(event), self._loop)

    async def _persist_wifi_network(self, event: dict) -> None:
        """A nearby access point — passive inventory, never an alert."""
        try:
            await WifiNetworkRepository().upsert(
                event['bssid'], ssid=event['ssid'], channel=event.get('channel'),
                signal=event.get('signal'), secured=event.get('secured', True),
            )
        except Exception:
            logger.exception('Failed to persist WiFi network %s', event.get('bssid'))

    async def _persist_wifi_sighting(self, event: dict) -> None:
        """Passive inventory, not an attack signal — never routes through
        _raise_threat_alert/AlertRepository. See WifiSightingRepository."""
        try:
            await WifiSightingRepository().upsert(
                event['mac'], signal=event.get('signal'), probed_ssid=event.get('ssid'),
            )
        except Exception:
            logger.exception('Failed to persist WiFi sighting for %s', event.get('mac'))

    async def _raise_threat_alert(
        self, mac: str | None, alert_type: str, severity: str, description: str,
        raw_data: dict | None = None, dedup_key: str | None = None,
    ) -> None:
        """Create/touch+broadcast an Alert for a detected attack. If
        Settings.DISABLE_AUTO_BLOCK isn't set and auto_block_on_threat is
        armed, blocks the device via the router adapter first so the alert
        description can note it — the single
        choke point every attack-signal source (ArpWatcher, DhcpWatcher,
        PassiveFingerprinter, WifiMonitorWatcher, NetworkScanner, Zeek DNS/beaconing/file-
        extraction, Suricata, OpenCanary) routes through, so all of them
        respond the same way. Deliberately NOT used by the ML/statistical
        detector pipeline (sentinel/detection/pipeline.py) or its own alerts
        (anomalous-volume, signal-anomaly, vendor-mismatch, etc.) — those
        are heuristic/probabilistic signals worth a human's judgment, not a
        confirmed attack, so they must never auto-block.

        Routes persistence through AlertRepository.upsert() — these sources
        have no natural "this stopped" signal of their own (a packet or log
        line, not a poll-driven condition), so nothing here ever resolve()s;
        only the alert_auto_resolve sweep job closes them. dedup_key
        disambiguates cases where (mac, alert_type) alone would wrongly
        merge distinct incidents (e.g. two different high-risk ports opening
        on the same device). Only a genuinely new alert (the "fire"
        transition) is pushed live — a touch on an already-open alert is
        already covered by the frontend's existing 15s poll.

        Always re-issues the block, even if device.is_blocked is already True
        — that DB flag is only ever a cache of the last known outcome, and
        trusting it to skip re-blocking let a real attack through once
        already (the flag went stale from an earlier attempt, the device was
        actually still on the network, and this method silently did nothing
        because it *believed* the cache). adapter.block_device() is idempotent
        (it just re-asserts the same blacklist state), so there's no cost to
        always calling it — on both a fire and a touch.

        The description only ever claims "auto-blocked" if adapter.block_device()
        itself confirmed success — a False return (or a raised exception) is
        surfaced as "AUTO-BLOCK FAILED" instead, never silently swallowed, so
        the alert never lies about a device having been removed from the network.

        Every successful auto-block also (re-)stamps blocked_at/blocked_until,
        even if the device was already blocked — a fresh threat always resets
        the expiry clock, so _block_expiry_job can never unblock a device
        moments after it was legitimately re-blocked for a new reason. See
        AppSettings.auto_block_expiry_hours (0 = auto-blocks never expire).
        Manual blocks (POST /devices/<mac>/block) never go through this
        method, so blocked_until stays NULL for them — indefinite by design.

        Also stamps Alert.mitigation with canned "what to do about this"
        guidance via build_mitigation() — None for alert types it doesn't
        recognize, same fallback SettingsRepository-style callers already
        tolerate elsewhere.

        Never blocks the machine Heimdall itself runs on (see
        _is_own_host()) — a detector false-positiving on Heimdall's own
        traffic (confirmed case: ZeekConnBeaconDetector misreading
        Heimdall's own nmap scan as C2 beaconing, since a scan's own packet
        pacing looks exactly like low-jitter beaconing at a glance) must
        never be able to cut the host running the security tool off its
        own network. The alert itself still fires — this only suppresses
        the block, since the finding is worth a human's attention even
        when the auto-response would be self-destructive.
        """
        blocked_now = False
        block_failed = False
        # Hard kill-switch, checked before anything else — see Settings.
        # DISABLE_AUTO_BLOCK's docstring for why this is a separate,
        # env-only override rather than just relying on the DB-backed
        # auto_block_on_threat setting this same method also checks below.
        auto_block_disabled = settings.DISABLE_AUTO_BLOCK
        is_self = False
        if auto_block_disabled:
            pass  # every block attempt skipped outright — see description branch below
        elif bool(mac) and await self._is_own_host(mac):
            is_self = True
            logger.warning(
                'Suppressing auto-block for %s (%s) — this MAC resolves to the Heimdall '
                'host itself (see discover_local_ips()); never auto-blocking our own machine.',
                mac, alert_type,
            )
        elif mac:
            try:
                if await SettingsRepository().get_auto_block_on_threat():
                    adapter = await self._adapter_for_mac(mac)
                    blocked_now = await adapter.block_device(mac)
                    block_failed = not blocked_now
            except Exception:
                block_failed = True
                logger.exception('Auto-block failed for %s (%s)', mac, alert_type)

        if auto_block_disabled:
            description = f'{description} — AUTO-BLOCK DISABLED (dev override) — alert only, device not blocked'
        elif is_self:
            description = f'{description} — auto-block suppressed: this device is the Heimdall host itself'
        elif blocked_now:
            description = f'{description} — device auto-blocked'
        elif block_failed:
            description = f'{description} — AUTO-BLOCK FAILED, device is still on the network (see backend logs)'

        if blocked_now:
            async with get_session() as session:
                device = await session.get(Device, mac)
                if device is not None:
                    device.is_blocked = True
                    expiry_hours = await SettingsRepository().get_auto_block_expiry_hours()
                    now = datetime.now(timezone.utc)
                    device.blocked_at = now
                    device.blocked_until = now + timedelta(hours=expiry_hours) if expiry_hours > 0 else None

        alert, is_new = await AlertRepository().upsert(
            device_mac=mac, alert_type=alert_type, severity=severity,
            description=description, raw_data=raw_data or {},
            mitigation=build_mitigation(alert_type, raw_data),
            dedup_key=dedup_key,
        )
        if is_new:
            emit_alert(alert_to_dict(alert))
            # getattr, not a plain attribute read — same reasoning as
            # _is_own_host's self._local_ips: a test double built via
            # object.__new__(SentinelScheduler) never runs __init__, so
            # self._notifier may not exist at all.
            notifier = getattr(self, '_notifier', None)
            if notifier is not None:
                await notifier.notify_new_critical_alert(alert)

    async def _is_own_host(self, mac: str) -> bool:
        """True if `mac` currently resolves to one of this Heimdall
        instance's own local IPs (see self._local_ips / discover_local_ips()
        in _run_loop). A missing/empty self._local_ips (discovery failed,
        or this is a bare object.__new__(SentinelScheduler) test double)
        means "can't confirm this is self" — returns False, never True, so
        a discovery failure can only ever fail to *help* the safeguard, not
        accidentally suppress a real block. getattr, not a plain attribute
        read — a test double built via object.__new__(SentinelScheduler)
        never runs __init__, so self._local_ips may not exist at all."""
        local_ips = getattr(self, '_local_ips', None)
        if not local_ips:
            return False
        async with get_session() as session:
            device = await session.get(Device, mac)
        return bool(device and device.ip_address in local_ips)

    async def _retrain_job(self) -> None:
        try:
            await ModelTrainer(self._anomaly_engine).retrain_all()
        except Exception:
            logger.exception('Nightly ML retrain failed')

    async def _observed_extremes_job(self) -> None:
        """Refreshes the cached RATIO/POLLS/CONTAM. observed-extremes stats
        — see sentinel/detection/observed_extremes.py. On failure, the
        previous successfully-computed result (if any) is left in place
        rather than cleared, so a transient DB hiccup doesn't blank out an
        otherwise-still-valid reference panel until the next hourly run."""
        try:
            self._observed_extremes = await compute_observed_extremes()
            self._observed_extremes_computed_at = datetime.now(timezone.utc)
        except Exception:
            logger.exception('Observed-extremes refresh failed')

    async def _resolve_sniff_iface(self) -> str:
        """The admin's configured SNIFF_IFACE (SettingsRepository), falling
        back to this scheduler's own env-config default if the DB isn't
        reachable yet at startup — better to sniff on something than crash
        the whole scheduler thread over a transient DB hiccup."""
        try:
            return await SettingsRepository().get_sniff_iface()
        except Exception:
            logger.exception(
                'Failed to read sniff_iface from SettingsRepository — using env default %s',
                self._sniff_iface,
            )
            return self._sniff_iface

    async def _resolve_wifi_monitor_config(self) -> tuple[str | None, list[str], list[str]]:
        """(wifi_monitor_iface, protected_ssids, trusted_bssids) from
        SettingsRepository. Unlike _resolve_sniff_iface, a DB read failure
        here falls back to (None, [], []) — disabled — rather than any env
        default, since (see AppSettings.wifi_monitor_iface's docstring)
        there is no env-config fallback for a second, monitor-capable
        adapter to assume exists."""
        try:
            data = await SettingsRepository().get_all()
            return data['wifi_monitor_iface'], data['wifi_protected_ssids'], data['wifi_trusted_bssids']
        except Exception:
            logger.exception('Failed to read WiFi monitor config from SettingsRepository — disabling it')
            return None, [], []

    async def _resolve_router_ip(self) -> str:
        """The router's LAN-side IP, same resolution create_router_adapter()
        uses — settings.ROUTER_IP if configured, else the default-route
        gateway. Best-effort: returns '' on failure rather than raising, so
        a discovery hiccup doesn't crash the whole scheduler thread;
        _startup_job skips starting DhcpWatcher entirely when this is blank
        rather than starting it with nothing to compare against (which
        would flag every legitimate DHCP OFFER as rogue)."""
        if settings.ROUTER_IP:
            return settings.ROUTER_IP
        try:
            return discover_gateway_ip()
        except Exception:
            logger.exception('Failed to auto-discover router IP — DHCP watcher will not start')
            return ''

    async def _resolve_notification_config(self, fallback: NotificationConfig) -> NotificationConfig:
        """The admin's configured ntfy_url/SMTP settings (SettingsRepository),
        falling back to `fallback` (the env-config default built in
        init_scheduler) if the DB isn't reachable yet at startup."""
        try:
            repo = SettingsRepository()
            smtp = await repo.get_smtp_settings()
            return NotificationConfig(
                ntfy_url=await repo.get_ntfy_url(),
                smtp_host=smtp['smtp_host'] or '',
                smtp_port=smtp['smtp_port'] or 587,
                smtp_from=smtp['smtp_from'] or '',
                smtp_to=smtp['smtp_to'] or '',
                smtp_username=smtp['smtp_username'] or '',
                smtp_password=fallback.smtp_password,
                smtp_use_tls=smtp['smtp_use_tls'] if smtp['smtp_use_tls'] is not None else True,
            )
        except Exception:
            logger.exception('Failed to read notification config from SettingsRepository — using env defaults')
            return fallback

    async def _ensure_adapter(self) -> RouterAdapter:
        """The active/primary router's adapter — see AppSettings.active_router
        and this module's top-of-file design note in factory.py. Feeds the
        detection pipeline, WAN bandwidth tracking, RuleEngine auto-block,
        and ARP/DHCP reconciliation.

        Guarded by self._adapter_lock (double-checked locking) — see that
        attribute's docstring for the concurrent-callers-at-boot race this
        prevents. The outer check avoids acquiring the lock at all once the
        adapter is already built, which is the overwhelmingly common case.
        """
        if self._adapter is None:
            async with self._adapter_lock:
                if self._adapter is None:
                    self._adapter = await create_router_adapter()
        return self._adapter

    async def _ensure_secondary_adapter(self) -> RouterAdapter | None:
        """The other configured router's adapter (visibility-only — see
        _secondary_poll_job), or None if no second router is configured.
        Deliberately re-checks configuration on every call while nothing is
        built yet (None is both "not built" and "not configured" here) —
        cheap since that path never opens a connection, and it means
        configuring MiWiFi from the Settings tab takes effect on the very
        next poll without a restart.

        Guarded by self._secondary_adapter_lock for the same reason as
        _ensure_adapter — concurrent callers at boot could otherwise each
        build (and each real-login) their own independent adapter instance.
        """
        if self._secondary_adapter is None:
            async with self._secondary_adapter_lock:
                if self._secondary_adapter is None:
                    active = await SettingsRepository().get_active_router()
                    self._secondary_adapter = await create_secondary_router_adapter(active)
        return self._secondary_adapter

    async def _adapter_for_mac(self, mac: str) -> RouterAdapter:
        """Resolve which configured adapter actually owns `mac`, for block/
        unblock/quarantine actions — once a second router is configured, a
        device most recently reported by it must be blocked through *that*
        router, not whichever one happens to be active/primary. Falls back
        to the active adapter if this MAC has no devices row yet, or its
        recorded Device.source_router isn't the active router but the
        secondary adapter isn't available either (e.g. mid-reconfiguration).
        """
        active = await SettingsRepository().get_active_router()
        source_router = await DeviceRepository().get_source_router(mac)
        if source_router and source_router != active:
            secondary = await self._ensure_secondary_adapter()
            if secondary is not None:
                return secondary
        return await self._ensure_adapter()

    # ── Thread-safe bridge for Flask routes ──────────────────────────────────
    #
    # The router adapter only exists on this scheduler's own event loop/thread.
    # Flask handles requests on separate thread(s), so routes that need to talk
    # to the adapter (block/unblock, live router info) submit a coroutine here
    # via asyncio.run_coroutine_threadsafe() and block on the result — the
    # request thread waits, but nothing on the scheduler's loop does.

    def call_adapter(
        self, coro: Coroutine[Any, Any, Any], timeout: float = DEFAULT_ADAPTER_CALL_TIMEOUT_S
    ) -> Any:
        """Run an adapter coroutine on the scheduler's loop; block until it completes."""
        if self._loop is None:
            raise RuntimeError('Scheduler not running')
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=timeout)
        except FutureTimeoutError:
            future.cancel()
            raise TimeoutError(f'Adapter call did not complete within {timeout}s') from None

    def block_device(self, mac: str, timeout: float = DEFAULT_ADAPTER_CALL_TIMEOUT_S) -> bool:
        """Thread-safe: block a device via the router adapter."""
        return self.call_adapter(self._block_device(mac), timeout)

    def unblock_device(self, mac: str, timeout: float = DEFAULT_ADAPTER_CALL_TIMEOUT_S) -> bool:
        """Thread-safe: unblock a device via the router adapter."""
        return self.call_adapter(self._unblock_device(mac), timeout)

    def quarantine_device(self, mac: str, timeout: float = DEFAULT_ADAPTER_CALL_TIMEOUT_S) -> bool:
        """Thread-safe: quarantine (WAN-only block) a device via the router adapter."""
        return self.call_adapter(self._quarantine_device(mac), timeout)

    def unquarantine_device(self, mac: str, timeout: float = DEFAULT_ADAPTER_CALL_TIMEOUT_S) -> bool:
        """Thread-safe: remove a device's quarantine via the router adapter."""
        return self.call_adapter(self._unquarantine_device(mac), timeout)

    def get_router_info(self, timeout: float = DEFAULT_ADAPTER_CALL_TIMEOUT_S) -> RouterInfo:
        """Thread-safe: fetch live router info via the router adapter."""
        return self.call_adapter(self._get_router_info(), timeout)

    async def _block_device(self, mac: str) -> bool:
        adapter = await self._adapter_for_mac(mac)
        return await adapter.block_device(mac)

    async def _unblock_device(self, mac: str) -> bool:
        adapter = await self._adapter_for_mac(mac)
        return await adapter.unblock_device(mac)

    async def _quarantine_device(self, mac: str) -> bool:
        adapter = await self._adapter_for_mac(mac)
        return await adapter.quarantine_device(mac)

    async def _unquarantine_device(self, mac: str) -> bool:
        adapter = await self._adapter_for_mac(mac)
        return await adapter.unquarantine_device(mac)

    async def _get_router_info(self) -> RouterInfo:
        adapter = await self._ensure_adapter()
        return await adapter.get_router_info()

    def health_snapshot(self) -> dict[str, Any]:
        """Synchronous status summary for /api/health — safe to call from any thread."""
        return {
            'scheduler_running': self._thread is not None and self._thread.is_alive(),
            'last_poll_at': self._last_poll_at.isoformat() if self._last_poll_at else None,
            'last_poll_error': self._last_poll_error,
        }

    def metrics_snapshot(self) -> dict[str, Any]:
        """Poll-latency figures for /api/metrics — see health_snapshot for
        the equivalent JSON status view. last_poll_duration_s only updates on
        a *successful* poll (same as last_poll_at), so a poll cycle that's
        currently failing repeatedly still reports its last good duration,
        not a stale/misleading partial-failure timing.
        """
        return {
            'scheduler_running': self._thread is not None and self._thread.is_alive(),
            'last_poll_duration_s': self._last_poll_duration_s,
            'last_poll_age_s': (
                (datetime.now(timezone.utc) - self._last_poll_at).total_seconds()
                if self._last_poll_at else None
            ),
        }

    def security_services_snapshot(self) -> dict[str, Any]:
        """Real status for the security services that are actually wired — no
        fabricated rows for services (e.g. Pi-hole) that don't have a live
        signal to report yet.

        `deployment_tier`/`active_services` let the frontend distinguish
        "not installed for this tier" from "installed but currently
        down/idle" — every other field here is a None-guarded boolean or
        timestamp that looks the same in both cases on its own. See
        sentinel/deployment_tiers.py."""
        return {
            'deployment_tier': self._tier,
            'active_services': active_service_keys(self._tier),
            'arp_watch_active': self._arp_watcher.is_active if self._arp_watcher else False,
            'dhcp_watch_active': self._dhcp_watcher.is_active if self._dhcp_watcher else False,
            'fingerprint_active': self._fingerprinter.is_active if self._fingerprinter else False,
            'sniff_iface': self._sniff_iface,
            'wifi_monitor_active': self._wifi_monitor.is_active if self._wifi_monitor else False,
            'nmap_last_scan_at': (
                self._last_nmap_scan_at.isoformat() if self._last_nmap_scan_at else None
            ),
            'canary_last_check_at': (
                self._last_canary_check_at.isoformat() if self._last_canary_check_at else None
            ),
            'zeek_dns_last_check_at': (
                self._last_zeek_dns_check_at.isoformat() if self._last_zeek_dns_check_at else None
            ),
            'zeek_beacon_last_scan_at': (
                self._last_zeek_beacon_scan_at.isoformat() if self._last_zeek_beacon_scan_at else None
            ),
            'spike_ip_enrichment_last_run_at': (
                self._last_spike_ip_enrichment_at.isoformat() if self._last_spike_ip_enrichment_at else None
            ),
            'clamav_reachable': self._clamav_reachable,
            'suricata_last_check_at': (
                self._last_suricata_check_at.isoformat() if self._last_suricata_check_at else None
            ),
        }

    def observed_extremes_snapshot(self) -> dict[str, Any]:
        """The most recently computed RATIO/POLLS/CONTAM. observed-extremes
        stats — see sentinel/detection/observed_extremes.py and
        _observed_extremes_job. computed_at is None before the first hourly
        run completes (e.g. right after a fresh start)."""
        return {
            'extremes': self._observed_extremes,
            'computed_at': (
                self._observed_extremes_computed_at.isoformat() if self._observed_extremes_computed_at else None
            ),
        }

    def memory_diagnostics_snapshot(self) -> dict[str, Any]:
        """Sizes of the in-memory collections most likely to grow unbounded
        on a long-running process — every one is keyed by MAC/IP and nothing
        currently evicts an entry for a device that's left the network, so
        they naturally grow with distinct-device churn (e.g. MAC-randomizing
        phones) even without an actual bug. What distinguishes a real leak
        is a count that keeps climbing indefinitely rather than plateauing
        once the LAN's device population stabilizes — call this endpoint a
        few times spaced minutes apart and compare. See GET /api/debug/memory.
        """
        adapter = self._adapter
        return {
            'arp_watcher_table_size': self._arp_watcher.table_size if self._arp_watcher else None,
            'fingerprinter_cache_size': self._fingerprinter.cache_size if self._fingerprinter else None,
            'rule_engine_streak_count': self._rule_engine.streak_count if self._rule_engine else None,
            'rule_engine_rate_limited_count': (
                self._rule_engine.rate_limited_count if self._rule_engine else None
            ),
            'anomaly_engine_buffered_device_count': (
                self._anomaly_engine.buffered_device_count if self._anomaly_engine else None
            ),
            'anomaly_engine_trained_model_count': (
                self._anomaly_engine.trained_model_count if self._anomaly_engine else None
            ),
            'adapter_traffic_delta_tracked_count': (
                adapter._device_delta.tracked_key_count if hasattr(adapter, '_device_delta') else None
            ),
        }

    def threat_intel_feeds_snapshot(self) -> dict[str, Any]:
        return self._threat_intel.feed_status() if self._threat_intel else {}

    def get_nmap_version(self) -> str | None:
        """Installed nmap binary version, for the Services panel's hover
        card — None on tiers with no nmap-capable scanner (self._scanner is
        only constructed for tiers that include it, see security_services_
        snapshot's active_services) or if the version probe itself fails."""
        if self._scanner is None:
            return None
        try:
            return self._scanner.binary_version()
        except Exception:
            return None

    async def get_clamav_version(self) -> str | None:
        """Live clamd version string, for the same hover card — None if
        ClamAV isn't wired for this tier or clamd isn't reachable right now."""
        if self._clamav is None:
            return None
        return await self._clamav.version()

    def get_threat_intel_service(self) -> ThreatIntelService:
        """Return the shared ThreatIntelService instance, for /api/threats routes."""
        if self._threat_intel is None:
            raise RuntimeError('Scheduler not running')
        return self._threat_intel

    def reset_ml_state(self) -> None:
        """Thread-safe: clear the running AnomalyEngine's in-memory bootstrap
        buffers and loaded-model cache — called via /api/settings/purge after
        the on-disk model files and devices/traffic_samples tables have been
        wiped, so this process doesn't keep serving now-orphaned models for
        the rest of its uptime. Fire-and-forget: reset() is a couple of plain
        dict.clear() calls, nothing worth blocking the request thread on."""
        if self._loop is None or self._anomaly_engine is None:
            return
        self._loop.call_soon_threadsafe(self._anomaly_engine.reset)

    def restart_sniffers(self, iface: str) -> None:
        """Restart ARP watch + DHCP watch + passive fingerprinting on a new
        interface — called when the admin changes SNIFF_IFACE in the
        Settings tab, so it takes effect immediately instead of only on the
        next process restart. Safe to call whether or not sniffing ever
        successfully started (e.g. no NET_RAW) — restart() just
        stops-then-starts.

        Unlike reset_ml_state(), this doesn't need to run on the scheduler's
        own event loop — ArpWatcher/DhcpWatcher/PassiveFingerprinter manage
        their own threads directly and don't touch the asyncio loop at all,
        so calling their plain restart() methods straight from the Flask
        request thread is safe.
        """
        self._sniff_iface = iface
        if self._arp_watcher is not None:
            self._arp_watcher.restart(iface)
        # Only restart the DHCP watcher if it has something to compare
        # against — see _startup_job's identical guard. Restarting it with
        # a blank expected_server_ip would flag every legitimate DHCP
        # OFFER as rogue.
        if self._dhcp_watcher is not None and self._router_ip:
            self._dhcp_watcher.restart(iface)
        if self._fingerprinter is not None:
            self._fingerprinter.restart(iface)

    def reload_wifi_monitor(self, iface: str | None, protected_ssids: list[str], trusted_bssids: list[str]) -> None:
        """Applies a WiFi Monitor settings change immediately — called
        after POST /api/settings changes wifi_monitor_iface/
        wifi_protected_ssids/wifi_trusted_bssids. Unlike restart_sniffers,
        this watcher may not have existed at all yet (no monitor-capable
        adapter was ever configured), so this also covers first-time
        enable/disable, not just a live interface swap.

        Same "safe to call from the Flask request thread directly" posture
        as restart_sniffers — WifiMonitorWatcher manages its own thread and
        never touches the asyncio loop.
        """
        if not iface:
            if self._wifi_monitor is not None:
                self._wifi_monitor.stop()
                self._wifi_monitor = None
            return

        if self._wifi_monitor is None:
            self._wifi_monitor = WifiMonitorWatcher(
                self._on_wifi_alert, self._on_wifi_sighting, iface, protected_ssids, trusted_bssids,
                network_callback=self._on_wifi_network,
            )
            self._wifi_monitor.start()
            return

        if self._wifi_monitor.iface != iface:
            self._wifi_monitor.restart(iface)
        self._wifi_monitor.update_targets(protected_ssids, trusted_bssids)

    def reload_router_credentials(self) -> None:
        """Thread-safe: drop the cached router adapter so the next call to
        _ensure_adapter() rebuilds it from the current settings.ROUTER_USERNAME/
        ROUTER_PASSWORD — called after the admin changes router credentials
        in the Settings tab (PATCH /api/settings has already written the new
        password to disk and mutated settings.ROUTER_PASSWORD in place by the
        time this runs). Closes the old adapter's HTTP client on the
        scheduler's own loop rather than leaking it.
        """
        if self._loop is None:
            return

        def _apply() -> None:
            old_adapter = self._adapter
            self._adapter = None
            if old_adapter is None:
                return
            aclose = getattr(old_adapter, 'aclose', None)
            if aclose is not None:
                asyncio.ensure_future(aclose(), loop=self._loop)

        self._loop.call_soon_threadsafe(_apply)

    def reload_secondary_router_credentials(self) -> None:
        """Thread-safe: drop the cached secondary (non-active) router
        adapter so the next _secondary_poll_job rebuilds it from current
        settings — mirrors reload_router_credentials() above, for
        self._secondary_adapter. Called after the admin changes MiWiFi
        credentials in the Settings tab, or flips AppSettings.active_router
        (which swaps which configured router *is* "secondary")."""
        if self._loop is None:
            return

        def _apply() -> None:
            old_adapter = self._secondary_adapter
            self._secondary_adapter = None
            if old_adapter is None:
                return
            aclose = getattr(old_adapter, 'aclose', None)
            if aclose is not None:
                asyncio.ensure_future(aclose(), loop=self._loop)

        self._loop.call_soon_threadsafe(_apply)

    def reload_notification_config(self, config: NotificationConfig) -> None:
        """Thread-safe: rebuild the notifier with new SMTP settings — called
        after the admin saves the Settings tab's Notifications section, so it
        takes effect on the next notify() call without restarting the
        process. Also drops the cached RuleEngine (lazily rebuilt in
        _poll_job) since it was constructed with a reference to the old
        notifier and RuleEngine itself doesn't expose a way to swap it."""
        self._notification_config = config
        if self._loop is None:
            return

        def _apply() -> None:
            self._notifier = NotificationService(config)
            self._rule_engine = None

        self._loop.call_soon_threadsafe(_apply)


_scheduler: SentinelScheduler | None = None


def init_scheduler(app: Flask) -> None:
    """Create and start the process-wide scheduler from the Flask app config.

    Called once from the Flask app factory, guarded by SCHEDULER_ENABLED so
    tests and one-off create_app() calls don't spin up a background thread.
    """
    global _scheduler

    if _scheduler is not None:
        logger.warning('init_scheduler() called more than once — ignoring')
        return

    notification_config = NotificationConfig(
        ntfy_url=app.config['NTFY_URL'],
        smtp_host=app.config['SMTP_HOST'],
        smtp_port=app.config['SMTP_PORT'],
        smtp_from=app.config['SMTP_FROM'],
        smtp_to=app.config['SMTP_TO'],
        smtp_username=app.config['SMTP_USERNAME'],
        smtp_password=app.config['SMTP_PASSWORD'],
        smtp_use_tls=app.config['SMTP_USE_TLS'],
    )
    _scheduler = SentinelScheduler(
        poll_interval_s=app.config['POLL_INTERVAL_SECONDS'],
        redis_url=app.config['REDIS_URL'],
        ml_model_dir=app.config['ML_MODEL_DIR'],
        ml_min_samples=app.config['ML_MIN_SAMPLES_TO_TRAIN'],
        ml_contamination=app.config['ML_CONTAMINATION'],
        ml_anomaly_magnitude_multiplier=app.config['ML_ANOMALY_MAGNITUDE_MULTIPLIER'],
        ml_anomaly_alert_magnitude_multiplier=app.config['ML_ANOMALY_ALERT_MAGNITUDE_MULTIPLIER'],
        ml_retrain_cron=app.config['ML_RETRAIN_CRON'],
        sniff_iface=app.config['SNIFF_IFACE'],
        otx_api_key=app.config['OTX_API_KEY'],
        abusech_auth_key=app.config.get('ABUSECH_AUTH_KEY', ''),
        threat_feed_cache_dir=app.config.get('THREAT_FEED_CACHE_DIR', ''),
        nmap_scan_cron=app.config['NMAP_SCAN_CRON'],
        threat_feed_refresh_cron=app.config['THREAT_FEED_REFRESH_CRON'],
        data_retention_cron=app.config['DATA_RETENTION_CRON'],
        notification_config=notification_config,
        opencanary_log_path=app.config['OPENCANARY_LOG_PATH'],
        canary_poll_interval_s=app.config['CANARY_POLL_INTERVAL_SECONDS'],
        zeek_log_dir=app.config['ZEEK_LOG_DIR'],
        zeek_extract_dir=app.config['ZEEK_EXTRACT_DIR'],
        zeek_dns_poll_interval_s=app.config['ZEEK_DNS_POLL_INTERVAL_SECONDS'],
        zeek_beacon_scan_interval_s=app.config['ZEEK_BEACON_SCAN_INTERVAL_SECONDS'],
        spike_ip_enrichment_interval_s=app.config['SPIKE_IP_ENRICHMENT_INTERVAL_SECONDS'],
        clamav_host=app.config['CLAMAV_HOST'],
        clamav_port=app.config['CLAMAV_PORT'],
        suricata_eve_log_path=app.config['SURICATA_EVE_LOG_PATH'],
        suricata_poll_interval_s=app.config['SURICATA_POLL_INTERVAL_SECONDS'],
        block_expiry_check_interval_s=app.config['BLOCK_EXPIRY_CHECK_INTERVAL_SECONDS'],
        correlation_scan_interval_s=app.config['CORRELATION_SCAN_INTERVAL_SECONDS'],
        alert_auto_resolve_check_interval_s=app.config['ALERT_AUTO_RESOLVE_CHECK_INTERVAL_SECONDS'],
        device_identity_link_scan_interval_s=app.config['DEVICE_IDENTITY_LINK_SCAN_INTERVAL_SECONDS'],
        stale_device_reap_interval_s=app.config['STALE_DEVICE_REAP_INTERVAL_SECONDS'],
        device_archive_sweep_interval_s=app.config['DEVICE_ARCHIVE_SWEEP_INTERVAL_SECONDS'],
        security_digest_cron=app.config['SECURITY_DIGEST_CRON'],
        deployment_tier=app.config['DEPLOYMENT_TIER'],
    )
    _scheduler.start()


def get_scheduler() -> SentinelScheduler:
    """Return the process-wide scheduler. Raises if init_scheduler() hasn't run yet."""
    if _scheduler is None:
        raise RuntimeError('Scheduler not initialised — call init_scheduler() first')
    return _scheduler


def shutdown_scheduler() -> None:
    """Stop the process-wide scheduler, if one was started."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown()
        _scheduler = None
