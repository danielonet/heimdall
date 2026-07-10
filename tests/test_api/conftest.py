"""Shared fixtures for tests/test_api — a real Flask test client against the
real Postgres/Redis (SCHEDULER_ENABLED=False for isolation/speed; the one test
that needs a live scheduler builds its own app — see test_scheduler_integration.py).
"""
import asyncio
import os

import pytest
from sqlalchemy import text

from sentinel.api.app import create_app
from sentinel.db.session import get_session

TEST_ADMIN_PASSWORD = 'test-admin-password-do-not-use-in-prod'


def _test_config(**overrides) -> dict:
    config = {
        'DATABASE_URL': os.environ.get(
            'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
        ),
        'REDIS_URL': os.environ.get('REDIS_URL', 'redis://localhost:6379'),
        'ADMIN_PASSWORD': TEST_ADMIN_PASSWORD,
        'ADMIN_USERNAME': 'admin',
        'SCHEDULER_ENABLED': False,
        'TESTING': True,
    }
    config.update(overrides)
    return config


@pytest.fixture
def app():
    return create_app(config=_test_config())


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers(client):
    """Log in as the test admin and return an Authorization header dict."""
    resp = client.post(
        '/api/login', json={'username': 'admin', 'password': TEST_ADMIN_PASSWORD}
    )
    token = resp.get_json()['access_token']
    return {'Authorization': f'Bearer {token}'}


@pytest.fixture(autouse=True)
def _cleanup_tables():
    yield
    asyncio.run(_truncate_all())


async def _truncate_all() -> None:
    async with get_session() as session:
        await session.execute(text(
            'TRUNCATE devices, traffic_samples, port_stats, wan_status_history, '
            'alerts, rules, threat_intel_cache RESTART IDENTITY'
        ))
