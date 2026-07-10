"""APScheduler wrapper: owns a dedicated background event loop for async poll jobs.

Flask (Werkzeug dev server / gunicorn sync workers) doesn't run its own asyncio
event loop, so the scheduler gets its own thread + loop rather than sharing Flask's.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from flask import Flask
from redis.asyncio import Redis, from_url

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.factory import create_router_adapter
from sentinel.detection.pipeline import DetectionPipeline, create_default_pipeline
from sentinel.scheduler.jobs import poll_cycle

logger = logging.getLogger(__name__)


class SentinelScheduler:
    """Runs poll_cycle() on an interval, on its own background event loop/thread."""

    def __init__(self, poll_interval_s: int, redis_url: str) -> None:
        self._poll_interval_s = poll_interval_s
        self._redis_url = redis_url
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._scheduler: AsyncIOScheduler | None = None
        self._adapter: RouterAdapter | None = None
        self._redis_client: Redis | None = None
        # Built once and reused across polls: HighUploadDetector and
        # SignalAnomalyDetector track state (rolling counts, last RSSI) in
        # memory across calls, so a fresh pipeline per poll would break them.
        self._pipeline: DetectionPipeline | None = None

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
        self._scheduler = AsyncIOScheduler(event_loop=self._loop)
        self._scheduler.add_job(
            self._poll_job,
            'interval',
            seconds=self._poll_interval_s,
            id='router_poll',
            next_run_time=datetime.now(),  # fire immediately, then on the interval
        )
        self._scheduler.start()
        self._loop.run_forever()

    async def _poll_job(self) -> None:
        if self._adapter is None:
            self._adapter = await create_router_adapter()
        if self._pipeline is None:
            self._pipeline = create_default_pipeline()
        try:
            await poll_cycle(self._adapter, self._redis_client, self._pipeline)
        except Exception:
            logger.exception('Poll cycle failed')


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

    _scheduler = SentinelScheduler(
        poll_interval_s=app.config['POLL_INTERVAL_SECONDS'],
        redis_url=app.config['REDIS_URL'],
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
