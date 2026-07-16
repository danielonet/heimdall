"""APScheduler wrapper: owns a dedicated background event loop for async poll jobs.

Flask (Werkzeug dev server / gunicorn sync workers) doesn't run its own asyncio
event loop, so the scheduler gets its own thread + loop rather than sharing Flask's.
"""
from __future__ import annotations

import asyncio
import dataclasses
import logging
import threading
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import datetime, timedelta, timezone
from typing import Any, Coroutine

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import Flask
from redis.asyncio import Redis, from_url
from sqlalchemy import delete, select, text

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.factory import create_router_adapter
from sentinel.adapter.models import RouterInfo
from sentinel.api.serializers import alert_to_dict
from sentinel.api.websocket import emit_alert
from sentinel.db.models import Alert, Device, WanStatusHistory
from sentinel.db.repositories import SettingsRepository
from sentinel.db.session import get_session
from sentinel.detection.pipeline import DetectionPipeline, create_default_pipeline
from sentinel.detection.rules_engine import RuleEngine
from sentinel.ml.anomaly_engine import AnomalyEngine
from sentinel.ml.model_store import ModelStore
from sentinel.ml.trainer import ModelTrainer
from sentinel.notifications.service import NotificationConfig, NotificationService
from sentinel.scheduler.jobs import poll_cycle
from sentinel.security.arp_watch import ArpWatcher
from sentinel.security.canary import OpenCanaryIngester, OpenCanaryLogReader
from sentinel.security.fingerprint import PassiveFingerprinter
from sentinel.security.scanner import NetworkScanner
from sentinel.security.threat_intel import ThreatIntelService

logger = logging.getLogger(__name__)

DEFAULT_ADAPTER_CALL_TIMEOUT_S = 10.0


class SentinelScheduler:
    """Runs poll_cycle() on an interval, on its own background event loop/thread."""

    def __init__(
        self,
        poll_interval_s: int,
        redis_url: str,
        ml_model_dir: str,
        ml_min_samples: int,
        ml_contamination: float,
        ml_retrain_cron: str,
        sniff_iface: str,
        otx_api_key: str,
        nmap_scan_cron: str,
        threat_feed_refresh_cron: str,
        data_retention_cron: str,
        notification_config: NotificationConfig,
        opencanary_log_path: str,
        canary_poll_interval_s: int,
    ) -> None:
        self._poll_interval_s = poll_interval_s
        self._redis_url = redis_url
        self._ml_model_dir = ml_model_dir
        self._ml_min_samples = ml_min_samples
        self._ml_contamination = ml_contamination
        self._ml_retrain_cron = ml_retrain_cron
        self._sniff_iface = sniff_iface
        self._otx_api_key = otx_api_key
        self._nmap_scan_cron = nmap_scan_cron
        self._threat_feed_refresh_cron = threat_feed_refresh_cron
        self._data_retention_cron = data_retention_cron
        self._notification_config = notification_config
        self._opencanary_log_path = opencanary_log_path
        self._canary_poll_interval_s = canary_poll_interval_s
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._scheduler: AsyncIOScheduler | None = None
        self._adapter: RouterAdapter | None = None
        self._redis_client: Redis | None = None
        # Built once and reused across polls: HighUploadDetector, SignalAnomalyDetector,
        # and AnomalyEngine all track state (rolling counts, last RSSI, trained
        # models) in memory across calls — a fresh pipeline/engine per poll
        # would throw that state away every 15 seconds.
        self._pipeline: DetectionPipeline | None = None
        self._anomaly_engine: AnomalyEngine | None = None
        # Security services — also built once per process, same reasoning.
        self._threat_intel: ThreatIntelService | None = None
        self._scanner: NetworkScanner | None = None
        self._arp_watcher: ArpWatcher | None = None
        self._fingerprinter: PassiveFingerprinter | None = None
        self._canary_reader: OpenCanaryLogReader | None = None
        self._canary_ingester: OpenCanaryIngester | None = None
        # Rules/notifications — RuleEngine tracks per-(rule, device) streak and
        # rate-limit state across polls, so it's built once too.
        self._notifier: NotificationService | None = None
        self._rule_engine: RuleEngine | None = None
        # Health tracking, read synchronously by Flask's /api/health route.
        self._last_poll_at: datetime | None = None
        self._last_poll_error: str | None = None
        self._last_nmap_scan_at: datetime | None = None
        self._last_canary_check_at: datetime | None = None

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
        )
        self._pipeline = create_default_pipeline(self._anomaly_engine)
        self._threat_intel = ThreatIntelService(self._otx_api_key)
        self._scanner = NetworkScanner()
        self._arp_watcher = ArpWatcher(self._on_arp_alert, self._sniff_iface)
        self._fingerprinter = PassiveFingerprinter(self._on_fingerprint, self._sniff_iface)
        self._canary_reader = OpenCanaryLogReader(self._opencanary_log_path)
        self._canary_ingester = OpenCanaryIngester()
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
        self._scheduler.add_job(
            self._canary_poll_job,
            'interval',
            seconds=self._canary_poll_interval_s,
            id='canary_poll',
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
        try:
            adapter = await self._ensure_adapter()
            if self._rule_engine is None:
                self._rule_engine = RuleEngine(adapter, self._notifier)
            await poll_cycle(
                adapter, self._redis_client, self._pipeline, self._anomaly_engine, self._rule_engine
            )
            self._last_poll_at = datetime.now(timezone.utc)
            self._last_poll_error = None
        except Exception as exc:
            logger.exception('Poll cycle failed')
            self._last_poll_error = str(exc)

    async def _startup_job(self) -> None:
        """Runs once at boot: seed + start the packet-sniffing watchers, and
        do an initial threat feed refresh so /api/threats/feeds isn't empty
        until the first nightly cron fires."""
        try:
            async with get_session() as session:
                result = await session.execute(select(Device.ip_address, Device.mac_address))
                pairs = [(ip, mac) for ip, mac in result.all() if ip]
            self._arp_watcher.seed(pairs)
            self._arp_watcher.start()
            self._fingerprinter.start()
        except Exception:
            logger.exception('Failed to start ARP watcher / passive fingerprinter')

        try:
            await self._threat_intel.refresh_feeds()
        except Exception:
            logger.exception('Initial threat feed refresh failed')

    async def _nmap_scan_job(self) -> None:
        """Nightly OS/service scan of every known device, stored in devices.nmap_profile."""
        try:
            async with get_session() as session:
                result = await session.execute(select(Device.mac_address, Device.ip_address))
                devices = [(mac, ip) for mac, ip in result.all() if ip]
        except Exception:
            logger.exception('Failed to load device list for nmap scan')
            return

        for mac, ip in devices:
            try:
                scan = await self._scanner.scan_device(ip)
                profile = {
                    'os': scan.os,
                    'ports': [dataclasses.asdict(p) for p in scan.ports],
                    'scanned_at': datetime.now(timezone.utc).isoformat(),
                }
                async with get_session() as session:
                    device = await session.get(Device, mac)
                    if device is not None:
                        device.nmap_profile = profile
                        if scan.os != 'Unknown':
                            device.os_fingerprint = scan.os
            except Exception:
                logger.exception('nmap scan failed for %s (%s)', mac, ip)

        self._last_nmap_scan_at = datetime.now(timezone.utc)

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
        """
        try:
            days = await SettingsRepository().get_data_retention_days()
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            async with get_session() as session:
                await session.execute(
                    text("SELECT drop_chunks('traffic_samples', older_than => :cutoff)"), {'cutoff': cutoff}
                )
                await session.execute(
                    text("SELECT drop_chunks('port_stats', older_than => :cutoff)"), {'cutoff': cutoff}
                )
                await session.execute(delete(WanStatusHistory).where(WanStatusHistory.changed_at < cutoff))
                await session.execute(delete(Alert).where(Alert.created_at < cutoff))
            logger.info('Data retention cleanup complete (cutoff: %s, retention: %d days)', cutoff, days)
        except Exception:
            logger.exception('Data retention cleanup failed')

    async def _canary_poll_job(self) -> None:
        """Tail the OpenCanary log and persist any new honeypot-interaction alerts."""
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
        async with get_session() as session:
            if src_host:
                result = await session.execute(
                    select(Device.mac_address).where(Device.ip_address == src_host)
                )
                alert.device_mac = result.scalars().first()
            session.add(alert)
        emit_alert(alert_to_dict(alert))

    def _on_arp_alert(self, event: dict) -> None:
        """Sync callback invoked from ArpWatcher's own daemon thread."""
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._persist_arp_alert(event), self._loop)

    async def _persist_arp_alert(self, event: dict) -> None:
        async with get_session() as session:
            alert = Alert(
                device_mac=None,
                alert_type=event['type'],
                severity=event['severity'],
                description=event['description'],
                raw_data=event,
            )
            session.add(alert)
        emit_alert(alert_to_dict(alert))

    def _on_fingerprint(self, ip: str, os_guess: str) -> None:
        """Sync callback invoked from PassiveFingerprinter's own daemon thread."""
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._persist_fingerprint(ip, os_guess), self._loop)

    async def _persist_fingerprint(self, ip: str, os_guess: str) -> None:
        async with get_session() as session:
            result = await session.execute(select(Device).where(Device.ip_address == ip))
            device = result.scalars().first()
            if device is not None:
                device.os_fingerprint = os_guess

    async def _retrain_job(self) -> None:
        try:
            await ModelTrainer(self._anomaly_engine).retrain_all()
        except Exception:
            logger.exception('Nightly ML retrain failed')

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
        if self._adapter is None:
            self._adapter = await create_router_adapter()
        return self._adapter

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

    def get_router_info(self, timeout: float = DEFAULT_ADAPTER_CALL_TIMEOUT_S) -> RouterInfo:
        """Thread-safe: fetch live router info via the router adapter."""
        return self.call_adapter(self._get_router_info(), timeout)

    async def _block_device(self, mac: str) -> bool:
        adapter = await self._ensure_adapter()
        return await adapter.block_device(mac)

    async def _unblock_device(self, mac: str) -> bool:
        adapter = await self._ensure_adapter()
        return await adapter.unblock_device(mac)

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

    def security_services_snapshot(self) -> dict[str, Any]:
        """Real status for the security services that are actually wired — no
        fabricated rows for services (Suricata/Pi-hole/Zeek/ClamAV) that don't
        have a live signal to report."""
        return {
            'arp_watch_active': self._arp_watcher.is_active if self._arp_watcher else False,
            'fingerprint_active': self._fingerprinter.is_active if self._fingerprinter else False,
            'sniff_iface': self._sniff_iface,
            'nmap_last_scan_at': (
                self._last_nmap_scan_at.isoformat() if self._last_nmap_scan_at else None
            ),
            'canary_last_check_at': (
                self._last_canary_check_at.isoformat() if self._last_canary_check_at else None
            ),
        }

    def threat_intel_feeds_snapshot(self) -> dict[str, Any]:
        return self._threat_intel.feed_status() if self._threat_intel else {}

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
        """Restart ARP watch + passive fingerprinting on a new interface —
        called when the admin changes SNIFF_IFACE in the Settings tab, so it
        takes effect immediately instead of only on the next process
        restart. Safe to call whether or not sniffing ever successfully
        started (e.g. no NET_RAW) — restart() just stops-then-starts.

        Unlike reset_ml_state(), this doesn't need to run on the scheduler's
        own event loop — ArpWatcher/PassiveFingerprinter manage their own
        threads directly and don't touch the asyncio loop at all, so calling
        their plain restart() methods straight from the Flask request thread
        is safe.
        """
        self._sniff_iface = iface
        if self._arp_watcher is not None:
            self._arp_watcher.restart(iface)
        if self._fingerprinter is not None:
            self._fingerprinter.restart(iface)

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
        ml_retrain_cron=app.config['ML_RETRAIN_CRON'],
        sniff_iface=app.config['SNIFF_IFACE'],
        otx_api_key=app.config['OTX_API_KEY'],
        nmap_scan_cron=app.config['NMAP_SCAN_CRON'],
        threat_feed_refresh_cron=app.config['THREAT_FEED_REFRESH_CRON'],
        data_retention_cron=app.config['DATA_RETENTION_CRON'],
        notification_config=notification_config,
        opencanary_log_path=app.config['OPENCANARY_LOG_PATH'],
        canary_poll_interval_s=app.config['CANARY_POLL_INTERVAL_SECONDS'],
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
