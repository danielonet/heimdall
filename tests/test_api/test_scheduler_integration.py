"""Tests that need a real running scheduler + mock adapter: block/unblock,
live /api/router, and a healthy /api/health.

Runs the app as a real subprocess (like `flask run`) and drives it over HTTP,
rather than Flask's in-process test_client(). test_client() calls async views
via asgiref's CurrentThreadExecutor from the same thread that started the
scheduler's background event loop, which deadlocks — confirmed via a thread
dump, not reproducible through a real WSGI server handling real requests
(verified manually against `flask run` first). This test exercises the actual
production call path instead of fighting that in-process quirk.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from tests.test_api.conftest import TEST_ADMIN_PASSWORD

REPO_ROOT = Path(__file__).resolve().parents[2]
PORT = 5099
BASE_URL = f'http://127.0.0.1:{PORT}'
MOCK_MAC = 'a8:5e:60:f1:2c:3d'  # daniel-laptop, from MockSagemcomAdapter


@pytest.fixture(autouse=True)
def _cleanup_tables():
    """Override conftest's version: that one needs the in-process DB session
    singleton, but this module's app runs in a subprocess. Real cleanup
    happens in live_server's teardown, once the subprocess has exited."""
    yield


def _request(method: str, path: str, token: str | None = None, body: dict | None = None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f'{BASE_URL}{path}', method=method, headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


@pytest.fixture(scope='module')
def live_server():
    env = os.environ.copy()
    env['ADMIN_PASSWORD'] = TEST_ADMIN_PASSWORD
    env['USE_MOCK_ROUTER'] = 'true'
    env['POLL_INTERVAL_SECONDS'] = '2'
    env['SCHEDULER_ENABLED'] = 'true'

    proc = subprocess.Popen(
        [sys.executable, '-m', 'flask', '--app', 'sentinel.api.app:create_app()',
         'run', '--host', '127.0.0.1', '--port', str(PORT)],
        cwd=REPO_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        _wait_for_first_poll()
        yield
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        asyncio.run(_truncate_all())


async def _truncate_all() -> None:
    database_url = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(
                'TRUNCATE devices, traffic_samples, port_stats, wan_status_history, '
                'alerts, rules RESTART IDENTITY'
            ))
    finally:
        await engine.dispose()


def _wait_for_first_poll(timeout_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            _, body = _request('GET', '/api/health')
            if body['scheduler']['last_poll_at']:
                return
        except OSError as exc:
            # Covers ConnectionRefusedError (server not listening yet) and
            # socket timeouts (server still starting up) — both transient.
            last_error = exc
        time.sleep(0.3)
    raise TimeoutError(f'Scheduler did not complete a poll cycle in time ({last_error})')


@pytest.fixture
def access_token(live_server):
    _, body = _request('POST', '/api/login', body={'username': 'admin', 'password': TEST_ADMIN_PASSWORD})
    return body['access_token']


class TestHealthWithScheduler:
    def test_reports_ok(self, live_server):
        status, body = _request('GET', '/api/health')
        assert status == 200
        assert body['status'] == 'ok'


class TestRouterInfoWithScheduler:
    def test_returns_live_router_info(self, live_server):
        status, body = _request('GET', '/api/router')
        assert status == 200
        assert 'Mock' in body['model']


class TestBlockUnblockWithScheduler:
    def test_block_then_unblock_a_mock_device(self, live_server, access_token):
        block_status, block_body = _request('POST', f'/api/devices/{MOCK_MAC}/block', token=access_token)
        assert block_status == 200
        assert block_body['is_blocked'] is True

        _, device_body = _request('GET', f'/api/devices/{MOCK_MAC}')
        assert device_body['is_blocked'] is True

        unblock_status, unblock_body = _request('POST', f'/api/devices/{MOCK_MAC}/unblock', token=access_token)
        assert unblock_status == 200
        assert unblock_body['is_blocked'] is False
