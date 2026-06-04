"""Database session management (stub — full implementation in Phase 2)."""
import logging

from flask import Flask

logger = logging.getLogger(__name__)


def init_db(app: Flask) -> None:
    """Initialise the async SQLAlchemy engine and bind it to the Flask app.

    Full async SQLAlchemy + TimescaleDB implementation is deferred to Phase 2.
    The app factory calls this so the hook is in place from the start.
    """
    database_url = app.config.get('DATABASE_URL', '')
    logger.info('Database URL: %s (session init deferred to Phase 2)', database_url)
