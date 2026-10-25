"""Apply Alembic migrations programmatically — used as the backend container's
startup step so a fresh install gets its schema without a manual
`alembic upgrade head` (the repo-root alembic.ini isn't part of the image,
whose build context is ./sentinel).

Run as: python -m sentinel.db.migrate
"""
from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

from alembic import command
from alembic.config import Config

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / 'migrations'
MAX_ATTEMPTS = 30
RETRY_DELAY_S = 3


def build_config(database_url: str | None = None) -> Config:
    """Return an Alembic Config pointing at the packaged migrations.

    env.py prefers the DATABASE_URL environment variable; the URL set here is
    only the fallback (Settings.DATABASE_URL when the variable is unset).
    """
    if database_url is None:
        from sentinel.config import settings
        database_url = os.environ.get('DATABASE_URL') or settings.DATABASE_URL
    config = Config()
    config.set_main_option('script_location', str(MIGRATIONS_DIR))
    config.set_main_option('sqlalchemy.url', database_url.replace('%', '%%'))
    return config


def upgrade_to_head() -> None:
    """Run `alembic upgrade head`, retrying while Postgres is still starting."""
    config = build_config()
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            command.upgrade(config, 'head')
            logger.info('Database schema is up to date')
            return
        except Exception as exc:  # noqa: BLE001 — any failure here is retried, then re-raised
            if attempt == MAX_ATTEMPTS:
                raise
            logger.warning(
                'Migration attempt %d/%d failed (%s) — retrying in %ds',
                attempt, MAX_ATTEMPTS, exc.__class__.__name__, RETRY_DELAY_S,
            )
            time.sleep(RETRY_DELAY_S)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    try:
        upgrade_to_head()
    except Exception:
        logger.exception('Database migration failed')
        sys.exit(1)
