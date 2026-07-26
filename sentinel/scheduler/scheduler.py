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
from sentinel.db.models import Alert, Device, DnsQuery, WanStatusHistory
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
from sentinel.security.clamav_scanner import ClamAvScanner
from sentinel.security.fingerprint import PassiveFingerprinter
from sentinel.security.os_classification import os_family
from sentinel.security.scanner import HIGH_RISK_PORTS, NetworkScanner
from sentinel.security.threat_intel import ThreatIntelService
from sentinel.security.zeek_parser import (
    ZeekConnBeaconDetector,
    ZeekDnsIngester,
    ZeekDnsLogReader,
    ZeekFileExtractionWatcher,
)

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
        zeek_log_dir: str,
        zeek_extract_dir: str,
        zeek_dns_poll_interval_s: int,
        zeek_beacon_scan_interval_s: int,
        clamav_host: str,
        clamav_port: int,
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
        self._zeek_log_dir = zeek_log_dir
        self._zeek_extract_dir = zeek_extract_dir
        self._zeek_dns_poll_interval_s = zeek_dns_poll_interval_s
        self._zeek_beacon_scan_interval_s = zeek_beacon_scan_interval_s
        self._clamav_host = clamav_host
        self._clamav_port = clamav_port
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
        self._zeek_dns_reader: ZeekDnsLogReader | None = None
        self._zeek_dns_ingester: ZeekDnsIngester | None = None
        self._zeek_beacon_detector: ZeekConnBeaconDetector | None = None
        self._zeek_file_watcher: ZeekFileExtractionWatcher | None = None
        self._clamav: ClamAvScanner | None = None
        # Rules/notifications — RuleEngine tracks per-(rule, device) streak and
        # rate-limit state across polls, so it's built once too.
        self._notifier: NotificationService | None = None
        self._rule_engine: RuleEngine | None = None
        # Health tracking, read synchronously by Flask's /api/health route.
        self._last_poll_at: datetime | None = None
        self._last_poll_error: str | None = None
        self._last_nmap_scan_at: datetime | None = None
        self._last_canary_check_at: datetime | None = None
        self._last_zeek_dns_check_at: datetime | None = None
        self._last_zeek_beacon_scan_at: datetime | None = None
        self._last_zeek_file_scan_at: datetime | None = None
        self._clamav_reachable: bool | None = None

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
        self._zeek_dns_reader = ZeekDnsLogReader(f'{self._zeek_log_dir}/dns.log')
        self._zeek_dns_ingester = ZeekDnsIngester()
        self._zeek_beacon_detector = ZeekConnBeaconDetector(self._zeek_log_dir)
        self._zeek_file_watcher = ZeekFileExtractionWatcher(self._zeek_extract_dir, self._zeek_log_dir)
        self._clamav = ClamAvScanner(self._clamav_host, self._clamav_port)
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
        """Nightly OS/service scan of every known device, stored in devices.nmap_profile.

        Also treats several nmap findings as an attack rather than routine
        profile data: a high-risk port (see HIGH_RISK_PORTS) that was closed
        on the previous scan and is open now — a common sign a device has
        been compromised and is now running a backdoor/remote-admin service;
        any finding from nmap's `--script vuln` NSE category; any finding
        from a curated default/blank-credential NSE script set (kept as a
        separate alert type from vuln findings — a CVE and an exposed
        default password are different kinds of problem); and a disagreement
        between this scan's active OS detection and PassiveFingerprinter's
        most recent passive guess (both write to Device.os_fingerprint, so
        without this check they'd silently clobber each other with no
        cross-reference at all). All four route through _raise_threat_alert,
        which auto-blocks the device if auto_block_on_threat is armed.
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
                scan = await self._scanner.scan_device(ip)
                previous_open_ports = {
                    p['port'] for p in (previous_profile or {}).get('ports', [])
                    if p.get('state') == 'open'
                }
                newly_opened_high_risk = {
                    p.port: HIGH_RISK_PORTS[p.port] for p in scan.ports
                    if p.state == 'open' and p.port in HIGH_RISK_PORTS and p.port not in previous_open_ports
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
            )

    async def _zeek_beacon_scan_job(self) -> None:
        """Re-scan Zeek's conn.log for suspiciously regular connection
        intervals (a common C2 beaconing signature) and alert per offending
        (source, destination) pair."""
        try:
            suspicious = self._zeek_beacon_detector.detect()
        except Exception:
            logger.exception('Zeek beacon scan failed')
            self._last_zeek_beacon_scan_at = datetime.now(timezone.utc)
            return

        for pair in suspicious:
            mac = await self._mac_for_ip(pair['src'])
            await self._raise_threat_alert(
                mac, 'C2_BEACONING', 'CRITICAL',
                f"{pair['src']} has made {pair['count']} connections to {pair['dst']} "
                f"at suspiciously regular ~{pair['interval_mean_s']}s intervals "
                f"(stddev {pair['interval_std_s']}s) — possible C2 beaconing",
                raw_data=pair,
            )
        self._last_zeek_beacon_scan_at = datetime.now(timezone.utc)

    async def _zeek_file_scan_job(self) -> None:
        """Scan every file Zeek's file-extraction analyzer has pulled to disk
        via ClamAV, alerting (and deleting) on anything infected.

        Also refreshes _clamav_reachable here rather than pinging inside
        security_services_snapshot() — that method is read synchronously by
        /api/health, which the frontend polls every 15s per open tab; pinging
        clamd on every one of those requests would open a lot of avoidable
        sockets. This job's own interval is a cheap enough cadence for it.
        """
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

    def _on_arp_alert(self, event: dict) -> None:
        """Sync callback invoked from ArpWatcher's own daemon thread."""
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._persist_arp_alert(event), self._loop)

    async def _persist_arp_alert(self, event: dict) -> None:
        # new_mac is the attacker's MAC impersonating a known IP — attribute
        # the alert to it (rather than the previous None) so it's both
        # visible on the alert and available to auto-block.
        await self._raise_threat_alert(
            event.get('new_mac'), event['type'], event['severity'], event['description'], raw_data=event,
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

    async def _raise_threat_alert(
        self, mac: str | None, alert_type: str, severity: str, description: str,
        raw_data: dict | None = None,
    ) -> None:
        """Create+broadcast an Alert for a detected attack. If auto_block_on_threat
        is armed, blocks the device via the router adapter first so the alert
        description can note it — the single place ArpWatcher/PassiveFingerprinter/
        NetworkScanner-driven attack alerts go through, so all three respond
        the same way.

        Always re-issues the block, even if device.is_blocked is already True
        — that DB flag is only ever a cache of the last known outcome, and
        trusting it to skip re-blocking let a real attack through once
        already (the flag went stale from an earlier attempt, the device was
        actually still on the network, and this method silently did nothing
        because it *believed* the cache). adapter.block_device() is idempotent
        (it just re-asserts the same blacklist state), so there's no cost to
        always calling it.

        The description only ever claims "auto-blocked" if adapter.block_device()
        itself confirmed success — a False return (or a raised exception) is
        surfaced as "AUTO-BLOCK FAILED" instead, never silently swallowed, so
        the alert never lies about a device having been removed from the network.
        """
        blocked_now = False
        block_failed = False
        if mac:
            try:
                if await SettingsRepository().get_auto_block_on_threat():
                    adapter = await self._ensure_adapter()
                    blocked_now = await adapter.block_device(mac)
                    block_failed = not blocked_now
            except Exception:
                block_failed = True
                logger.exception('Auto-block failed for %s (%s)', mac, alert_type)

        if blocked_now:
            description = f'{description} — device auto-blocked'
        elif block_failed:
            description = f'{description} — AUTO-BLOCK FAILED, device is still on the network (see backend logs)'

        async with get_session() as session:
            if blocked_now:
                device = await session.get(Device, mac)
                if device is not None:
                    device.is_blocked = True
            alert = Alert(
                device_mac=mac, alert_type=alert_type, severity=severity,
                description=description, raw_data=raw_data or {},
            )
            session.add(alert)
        emit_alert(alert_to_dict(alert))

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
        fabricated rows for services (e.g. Suricata/Pi-hole) that don't have a
        live signal to report yet."""
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
            'zeek_dns_last_check_at': (
                self._last_zeek_dns_check_at.isoformat() if self._last_zeek_dns_check_at else None
            ),
            'zeek_beacon_last_scan_at': (
                self._last_zeek_beacon_scan_at.isoformat() if self._last_zeek_beacon_scan_at else None
            ),
            'clamav_reachable': self._clamav_reachable,
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
        zeek_log_dir=app.config['ZEEK_LOG_DIR'],
        zeek_extract_dir=app.config['ZEEK_EXTRACT_DIR'],
        zeek_dns_poll_interval_s=app.config['ZEEK_DNS_POLL_INTERVAL_SECONDS'],
        zeek_beacon_scan_interval_s=app.config['ZEEK_BEACON_SCAN_INTERVAL_SECONDS'],
        clamav_host=app.config['CLAMAV_HOST'],
        clamav_port=app.config['CLAMAV_PORT'],
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
