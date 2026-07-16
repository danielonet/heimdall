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
    POLL_INTERVAL_SECONDS: int = 15
    USE_MOCK_ROUTER: bool = True  # dev flag: use WireMock simulator instead of real router
    SCHEDULER_ENABLED: bool = True  # set False in tests to avoid starting the poll loop

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

    # ── Notifications ─────────────────────────────────────────────────────────
    NTFY_URL: str = ''             # e.g. https://ntfy.sh/heimdall-alerts
    SMTP_HOST: str = ''
    SMTP_PORT: int = 587
    SMTP_FROM: str = ''
    SMTP_TO: str = ''               # falls back to SMTP_FROM if blank (notify yourself)
    SMTP_USERNAME: str = ''
    SMTP_PASSWORD: str = ''
    SMTP_USE_TLS: bool = True

    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'
        extra = 'ignore'  # .env carries Docker/shell-only vars (e.g. DB_PASS,
                          # ROUTER_PASSWORD_FILE) that aren't Settings fields

    def model_post_init(self, __context: object) -> None:
        """Load secrets from Docker secret files when the plain value is empty."""
        if not self.ROUTER_PASSWORD:
            path = os.environ.get('ROUTER_PASSWORD_FILE', '')
            if path:
                object.__setattr__(self, 'ROUTER_PASSWORD', _read_secret_file(path))

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
