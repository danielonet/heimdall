import os
from typing import Optional

from pydantic_settings import BaseSettings


def _read_secret_file(path: str) -> str:
    """Read a Docker secret from a file path, stripping trailing whitespace."""
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ''


def write_secret_file(path: str, value: str) -> None:
    """Write a Docker-secret-style file — used by the Settings tab's
    router/SMTP password fields, so editing a password there still keeps
    the file (not the database) as the source of truth, per CLAUDE.md's
    "secrets via Docker secrets only" rule.

    Only works when `path` is actually writable by this process. The
    project's console/dev mode (scripts/run.sh) points *_FILE env vars
    directly at ./secrets/*.txt, which is writable. A full docker-compose
    deployment using Docker's native `secrets:` mechanism mounts these
    read-only at /run/secrets/*, so this will raise OSError there — see
    docs/architecture/09-docker-compose.md.
    """
    if not path:
        raise ValueError('No secret file path is configured for this value')
    with open(path, 'w') as f:
        f.write(value.strip() + '\n')


class Settings(BaseSettings):
    """Application configuration.

    Scalar values are read from environment variables or the .env file.
    Secrets (router password, JWT key, OTX key) are loaded from Docker secret
    files referenced by *_FILE environment variables. The _FILE variables
    are consumed at import time so that Settings instances expose plain values.
    """

    # ── Router ────────────────────────────────────────────────────────────────
    ROUTER_ADAPTER: str = 'sagemcom'
    ROUTER_IP: str = ''            # blank = auto-discover from default route
    ROUTER_PORT: int = 80
    ROUTER_USERNAME: str = 'home'
    ROUTER_PASSWORD: str = ''      # populated from ROUTER_PASSWORD_FILE if blank
    ROUTER_PASSWORD_FILE: str = ''  # also the write target for PATCH /api/settings
    POLL_INTERVAL_SECONDS: int = 15
    USE_MOCK_ROUTER: bool = True  # dev flag: use WireMock simulator instead of real router
    SCHEDULER_ENABLED: bool = True  # set False in tests to avoid starting the poll loop

    # ── Deployment ────────────────────────────────────────────────────────────
    # 'minimal' | 'intermediate' | 'full' — which optional Docker-backed
    # security services (OpenCanary/Zeek/ClamAV/Suricata) this install runs.
    # See sentinel/deployment_tiers.py. Defaults to 'full' since that's the
    # behavior every install had before this setting existed.
    DEPLOYMENT_TIER: str = 'full'

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = 'postgresql+asyncpg://sentinel:pass@postgres/sentinel'

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_URL: str = 'redis://redis:6379'

    # ── JWT ───────────────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str = ''       # populated from JWT_SECRET_FILE if blank
    JWT_ACCESS_TOKEN_EXPIRES: int = 900       # 15 minutes
    JWT_REFRESH_TOKEN_EXPIRES: int = 604800   # 7 days

    # ── Auth ──────────────────────────────────────────────────────────────────
    ADMIN_USERNAME: str = 'admin'
    ADMIN_PASSWORD: str = ''       # populated from ADMIN_PASSWORD_FILE if blank

    # ── ML ────────────────────────────────────────────────────────────────────
    ML_MIN_SAMPLES_TO_TRAIN: int = 100
    ML_CONTAMINATION: float = 0.05
    # AnomalyEngine.is_anomalous() requires decision_function() to be not just
    # past the calibrated 0.0 boundary but beyond MAGNITUDE_MULTIPLIER times
    # that device's own fitted training-score spread — a mild/borderline
    # outlier (barely past the boundary) no longer counts the same as an
    # extreme one. Self-relative (each device compared only to its own
    # history), not a fixed cross-device constant — see anomaly_engine.py's
    # ANOMALY_THRESHOLD comment for why a shared constant caused a real
    # incident previously; this is a different shape of comparison.
    ML_ANOMALY_MAGNITUDE_MULTIPLIER: float = 0.5
    # A second, stricter multiplier on top of the one above — clearing
    # MAGNITUDE_MULTIPLIER only means "notably unusual for this device",
    # which in practice includes a lot of perfectly ordinary heavy use (a
    # family video call, a long social-media video binge) that just isn't
    # what this device usually does. Requested directly after exactly that:
    # real family VoIP/video traffic tripping WARNING-level ANOMALOUS_VOLUME
    # alerts. A sample has to clear *this* multiplier — further out along
    # the same device's own fitted score spread — before it's escalated
    # from an informational data point to something worth a WARNING. See
    # AnomalyEngine.anomaly_severity().
    ML_ANOMALY_ALERT_MAGNITUDE_MULTIPLIER: float = 1.5
    ML_RETRAIN_CRON: str = '0 3 * * *'       # 03:00 daily
    ML_MODEL_DIR: str = '/data/models'       # matches the ml-models Docker volume;
                                              # override in .env for host/console dev
    # A model trained on ML_MIN_SAMPLES_TO_TRAIN samples (~25min at the default
    # poll interval) has only seen a narrow slice of a device's real behaviour
    # and floods WARNING alerts for normal variation it hasn't learned yet
    # (e.g. no diurnal pattern). AnomalousVolumeDetector suppresses alerts
    # until a device has been observed for this long, regardless of when its
    # model actually finished training. See docs/architecture/05-ml-anomaly-engine.md.
    ML_LEARNING_PERIOD_HOURS: int = 72

    # ── Data retention ────────────────────────────────────────────────────────
    # traffic_samples/port_stats accumulate one row per device/port every
    # POLL_INTERVAL_SECONDS forever unless something rolls them off — this is
    # the rolling window's env default; both this and ML_LEARNING_PERIOD_HOURS
    # above have a runtime-overridable copy in the app_settings table (see
    # SettingsRepository) so an admin can change either from the Settings tab
    # without restarting the process.
    DATA_RETENTION_DAYS: int = 90
    DATA_RETENTION_CRON: str = '30 3 * * *'  # 03:30 daily

    # ── Security services ─────────────────────────────────────────────────────
    OTX_API_KEY: str = ''          # populated from OTX_API_KEY_FILE if blank
    SNIFF_IFACE: str = 'eth0'
    NMAP_SCAN_CRON: str = '0 2 * * *'          # 02:00 daily
    THREAT_FEED_REFRESH_CRON: str = '0 4 * * *'  # 04:00 daily
    OPENCANARY_LOG_PATH: str = '/var/log/opencanary/opencanary.log'
    CANARY_POLL_INTERVAL_SECONDS: int = 10
    # See sentinel/security/zeek_parser.py and zeek/local.zeek.
    ZEEK_LOG_DIR: str = '/var/log/zeek'
    ZEEK_EXTRACT_DIR: str = '/var/zeek/extracted'
    ZEEK_DNS_POLL_INTERVAL_SECONDS: int = 10
    # Beaconing detection needs a window of connection history to compute
    # interval statistics over, not a per-line reaction — much longer than
    # the DNS poll interval.
    ZEEK_BEACON_SCAN_INTERVAL_SECONDS: int = 300
    # How often to correlate recent traffic-spike alerts (ANOMALOUS_VOLUME/
    # HIGH_UPLOAD/WAN_BANDWIDTH_SPIKE) against conn.log for a remote IP and
    # check it against threat intel. Zeek-only — see
    # sentinel/security/zeek_parser.py:ZeekConnVolumeCorrelator and
    # SentinelScheduler._spike_ip_enrichment_job.
    SPIKE_IP_ENRICHMENT_INTERVAL_SECONDS: int = 300
    CLAMAV_HOST: str = 'localhost'
    CLAMAV_PORT: int = 3310
    # See sentinel/security/suricata_parser.py.
    SURICATA_EVE_LOG_PATH: str = '/var/log/suricata/eve.json'
    SURICATA_POLL_INTERVAL_SECONDS: int = 15
    # How often to check for auto-blocks past their AppSettings.
    # auto_block_expiry_hours — an interval, not a nightly cron, so a 24h
    # SLA doesn't slip by up to a full day. See SentinelScheduler._block_expiry_job.
    BLOCK_EXPIRY_CHECK_INTERVAL_SECONDS: int = 900
    # How often to scan recent alerts for cross-alert correlation patterns
    # (e.g. NEW_DEVICE immediately followed by ARP_SPOOF). See
    # sentinel/detection/correlation.py.
    CORRELATION_SCAN_INTERVAL_SECONDS: int = 300
    # How often to sweep for open alerts past AppSettings.
    # alert_auto_resolve_hours with no recurrence and auto-resolve them —
    # an interval, not a nightly cron, same reasoning as
    # BLOCK_EXPIRY_CHECK_INTERVAL_SECONDS. See SentinelScheduler._alert_auto_resolve_job.
    ALERT_AUTO_RESOLVE_CHECK_INTERVAL_SECONDS: int = 1800
    # How often to scan for device-identity link candidates (a phone's
    # randomized WiFi MAC reconnecting under a new address) — an ARP-
    # confirmed auto-link, not a nightly cron, same reasoning as
    # CORRELATION_SCAN_INTERVAL_SECONDS. See sentinel/detection/
    # device_identity.py and SentinelScheduler._identity_link_job.
    DEVICE_IDENTITY_LINK_SCAN_INTERVAL_SECONDS: int = 300
    # How often to ARP-probe currently-online devices and mark unreachable
    # ones offline promptly, instead of waiting for the router's own
    # (often slow) view to catch up. See SentinelScheduler._stale_device_reap_job.
    STALE_DEVICE_REAP_INTERVAL_SECONDS: int = 120
    # How often to sweep for devices with no activity in AppSettings.
    # device_archive_after_days and soft-archive them — an interval, not a
    # nightly cron, same reasoning as ALERT_AUTO_RESOLVE_CHECK_INTERVAL_SECONDS.
    # Distinct from STALE_DEVICE_REAP_INTERVAL_SECONDS above, which is an
    # unrelated ARP-liveness job. See SentinelScheduler._device_archive_sweep_job.
    DEVICE_ARCHIVE_SWEEP_INTERVAL_SECONDS: int = 3600
    # Daily by default — edit for weekly (e.g. '0 7 * * 1' for Monday).
    # Env-only, like every other *_CRON setting (not SettingsRepository-backed).
    SECURITY_DIGEST_CRON: str = '0 7 * * *'

    # ── Diagnostics ───────────────────────────────────────────────────────────
    # Starts tracemalloc at process boot and enables GET /api/debug/memory.
    # Off by default — tracemalloc adds real memory/CPU overhead (it tracks
    # a traceback per allocation), worth paying only while actively hunting
    # a leak. See sentinel/api/routes/debug.py.
    MEMORY_DEBUG_ENABLED: bool = False

    # ── Safety overrides ──────────────────────────────────────────────────────
    # Hard kill-switch for every auto-block code path (SentinelScheduler.
    # _raise_threat_alert, _propagate_block_after_link, and
    # _correct_block_drift's re-block branch) — every one of them still
    # raises its alert exactly as normal, just never calls block_device()
    # or flips is_blocked. Deliberately env-only (like every other flag in
    # this section), NOT the DB-backed auto_block_on_threat setting
    # (SettingsRepository/the Settings tab): that setting is part of the
    # app's own mutable state, and this exists specifically so it can't be
    # flipped back on by anything happening *inside* the app while it's
    # armed for a live attack-simulation test (a bug, a stray API call from
    # a Kali box, /api/settings/purge resetting settings to defaults) — only
    # restarting the process with this unset turns auto-block back on.
    # See scripts/dev.sh's --no-auto-block flag.
    DISABLE_AUTO_BLOCK: bool = False

    # ── Notifications ─────────────────────────────────────────────────────────
    NTFY_URL: str = ''             # e.g. https://ntfy.sh/heimdall-alerts
    SMTP_HOST: str = ''
    SMTP_PORT: int = 587
    SMTP_FROM: str = ''
    SMTP_TO: str = ''               # falls back to SMTP_FROM if blank (notify yourself)
    SMTP_USERNAME: str = ''
    SMTP_PASSWORD: str = ''        # populated from SMTP_PASSWORD_FILE if blank
    SMTP_PASSWORD_FILE: str = ''   # also the write target for PATCH /api/settings
    SMTP_USE_TLS: bool = True

    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'
        extra = 'ignore'  # .env carries Docker/shell-only vars (e.g. DB_PASS,
                          # ROUTER_PASSWORD_FILE) that aren't Settings fields

    def model_post_init(self, __context: object) -> None:
        """Load secrets from Docker secret files when the plain value is empty."""
        if not self.ROUTER_PASSWORD and self.ROUTER_PASSWORD_FILE:
            object.__setattr__(self, 'ROUTER_PASSWORD', _read_secret_file(self.ROUTER_PASSWORD_FILE))

        if not self.SMTP_PASSWORD and self.SMTP_PASSWORD_FILE:
            object.__setattr__(self, 'SMTP_PASSWORD', _read_secret_file(self.SMTP_PASSWORD_FILE))

        if not self.JWT_SECRET_KEY:
            path = os.environ.get('JWT_SECRET_FILE', '')
            if path:
                object.__setattr__(self, 'JWT_SECRET_KEY', _read_secret_file(path))

        if not self.OTX_API_KEY:
            path = os.environ.get('OTX_API_KEY_FILE', '')
            if path:
                object.__setattr__(self, 'OTX_API_KEY', _read_secret_file(path))

        if not self.ADMIN_PASSWORD:
            path = os.environ.get('ADMIN_PASSWORD_FILE', '')
            if path:
                object.__setattr__(self, 'ADMIN_PASSWORD', _read_secret_file(path))


settings = Settings()
