"""Async SQLAlchemy engine/session management, bound to the Flask app config."""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from flask import Flask
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

logger = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_db(app: Flask) -> None:
    """Create the process-wide async engine and session factory.

    Called once from the Flask app factory. Other modules (scheduler jobs,
    detectors) import get_session() directly rather than going through the
    Flask app, since they run outside of a request context.
    """
    global _engine, _session_factory

    database_url = app.config['DATABASE_URL']
    _engine = create_async_engine(database_url, pool_pre_ping=True)
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)

    logger.info('Database engine initialised: %s', _engine.url.render_as_string(hide_password=True))


def get_engine() -> AsyncEngine:
    """Return the process-wide async engine. Raises if init_db() hasn't run yet."""
    if _engine is None:
        raise RuntimeError('Database engine not initialised — call init_db() first')
    return _engine


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    """Yield an AsyncSession for a single unit of work, committing on success.

    Usage:
        async with get_session() as session:
            session.add(obj)
    """
    if _session_factory is None:
        raise RuntimeError('Database engine not initialised — call init_db() first')

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
