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
    ROUTER_USERNAME: str = 'admin'
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

    # ── ML ────────────────────────────────────────────────────────────────────
    ML_MIN_SAMPLES_TO_TRAIN: int = 100
    ML_CONTAMINATION: float = 0.05
    ML_RETRAIN_CRON: str = '0 3 * * *'       # 03:00 daily

    # ── Security services ─────────────────────────────────────────────────────
    OTX_API_KEY: str = ''          # populated from OTX_API_KEY_FILE if blank
    SNIFF_IFACE: str = 'eth0'
    NMAP_SCAN_CRON: str = '0 2 * * *'        # 02:00 daily

    # ── Notifications ─────────────────────────────────────────────────────────
    NTFY_URL: str = ''             # e.g. https://ntfy.sh/heimdall-alerts
    SMTP_HOST: str = ''
    SMTP_FROM: str = ''

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


settings = Settings()
