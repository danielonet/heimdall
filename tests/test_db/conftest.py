"""Shared fixtures for sentinel.db tests."""
import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine


def _database_url() -> str:
    """Return the test database URL, matching how run.sh builds DATABASE_URL."""
    return os.environ.get(
        'DATABASE_URL',
        'postgresql+asyncpg://sentinel:pass@localhost/sentinel',
    )


@pytest_asyncio.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """Yield an AsyncSession bound to a transaction rolled back after the test.

    Requires a running Postgres reachable at DATABASE_URL with the Alembic
    migrations already applied (alembic upgrade head). Skips if unreachable.
    """
    engine = create_async_engine(_database_url())
    try:
        connection = await engine.connect()
    except Exception as exc:
        await engine.dispose()
        pytest.skip(f'Database unavailable: {exc}')

    transaction = await connection.begin()
    session = AsyncSession(bind=connection, expire_on_commit=False)

    try:
        yield session
    finally:
        await session.close()
        await transaction.rollback()
        await connection.close()
        await engine.dispose()
