"""APScheduler wrapper: owns a dedicated background event loop for async poll jobs.

Flask (Werkzeug dev server / gunicorn sync workers) doesn't run its own asyncio
event loop, so the scheduler gets its own thread + loop rather than sharing Flask's.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from typing import Any, Coroutine

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import Flask
from redis.asyncio import Redis, from_url

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.factory import create_router_adapter
from sentinel.adapter.models import RouterInfo
from sentinel.detection.pipeline import DetectionPipeline, create_default_pipeline
from sentinel.ml.anomaly_engine import AnomalyEngine
from sentinel.ml.model_store import ModelStore
from sentinel.ml.trainer import ModelTrainer
from sentinel.scheduler.jobs import poll_cycle

logger = logging.getLogger(__name__)

DEFAULT_ADAPTER_CALL_TIMEOUT_S = 10.0


class SentinelScheduler:
    """Runs poll_cycle() on an interval, on its own background event loop/thread."""

    def __init__(
        self,
        poll_interval_s: int,
        redis_url: str,
        ml_model_dir: str,
        ml_min_samples: int,
        ml_contamination: float,
        ml_retrain_cron: str,
    ) -> None:
        self._poll_interval_s = poll_interval_s
        self._redis_url = redis_url
        self._ml_model_dir = ml_model_dir
        self._ml_min_samples = ml_min_samples
        self._ml_contamination = ml_contamination
        self._ml_retrain_cron = ml_retrain_cron
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._scheduler: AsyncIOScheduler | None = None
        self._adapter: RouterAdapter | None = None
        self._redis_client: Redis | None = None
        # Built once and reused across polls: HighUploadDetector, SignalAnomalyDetector,
        # and AnomalyEngine all track state (rolling counts, last RSSI, trained
        # models) in memory across calls — a fresh pipeline/engine per poll
        # would throw that state away every 15 seconds.
        self._pipeline: DetectionPipeline | None = None
        self._anomaly_engine: AnomalyEngine | None = None
        # Health tracking, read synchronously by Flask's /api/health route.
        self._last_poll_at: datetime | None = None
        self._last_poll_error: str | None = None

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
        self._anomaly_engine = AnomalyEngine(
            model_store=ModelStore(self._ml_model_dir),
            min_samples=self._ml_min_samples,
            contamination=self._ml_contamination,
        )
        self._pipeline = create_default_pipeline(self._anomaly_engine)

        self._scheduler = AsyncIOScheduler(event_loop=self._loop)
        self._scheduler.add_job(
            self._poll_job,
            'interval',
            seconds=self._poll_interval_s,
            id='router_poll',
            next_run_time=datetime.now(),  # fire immediately, then on the interval
        )
        self._scheduler.add_job(
            self._retrain_job,
            CronTrigger.from_crontab(self._ml_retrain_cron),
            id='ml_retrain',
            replace_existing=True,
        )
        self._scheduler.start()
        self._loop.run_forever()

    async def _poll_job(self) -> None:
        try:
            adapter = await self._ensure_adapter()
            await poll_cycle(adapter, self._redis_client, self._pipeline, self._anomaly_engine)
            self._last_poll_at = datetime.now(timezone.utc)
            self._last_poll_error = None
        except Exception as exc:
            logger.exception('Poll cycle failed')
            self._last_poll_error = str(exc)

    async def _retrain_job(self) -> None:
        try:
            await ModelTrainer(self._anomaly_engine).retrain_all()
        except Exception:
            logger.exception('Nightly ML retrain failed')

    async def _ensure_adapter(self) -> RouterAdapter:
        if self._adapter is None:
            self._adapter = await create_router_adapter()
        return self._adapter

    # ── Thread-safe bridge for Flask routes ──────────────────────────────────
    #
    # The router adapter only exists on this scheduler's own event loop/thread.
    # Flask handles requests on separate thread(s), so routes that need to talk
    # to the adapter (block/unblock, live router info) submit a coroutine here
    # via asyncio.run_coroutine_threadsafe() and block on the result — the
    # request thread waits, but nothing on the scheduler's loop does.

    def call_adapter(
        self, coro: Coroutine[Any, Any, Any], timeout: float = DEFAULT_ADAPTER_CALL_TIMEOUT_S
    ) -> Any:
        """Run an adapter coroutine on the scheduler's loop; block until it completes."""
        if self._loop is None:
            raise RuntimeError('Scheduler not running')
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=timeout)
        except FutureTimeoutError:
            future.cancel()
            raise TimeoutError(f'Adapter call did not complete within {timeout}s') from None

    def block_device(self, mac: str, timeout: float = DEFAULT_ADAPTER_CALL_TIMEOUT_S) -> bool:
        """Thread-safe: block a device via the router adapter."""
        return self.call_adapter(self._block_device(mac), timeout)

    def unblock_device(self, mac: str, timeout: float = DEFAULT_ADAPTER_CALL_TIMEOUT_S) -> bool:
        """Thread-safe: unblock a device via the router adapter."""
        return self.call_adapter(self._unblock_device(mac), timeout)

    def get_router_info(self, timeout: float = DEFAULT_ADAPTER_CALL_TIMEOUT_S) -> RouterInfo:
        """Thread-safe: fetch live router info via the router adapter."""
        return self.call_adapter(self._get_router_info(), timeout)

    async def _block_device(self, mac: str) -> bool:
        adapter = await self._ensure_adapter()
        return await adapter.block_device(mac)

    async def _unblock_device(self, mac: str) -> bool:
        adapter = await self._ensure_adapter()
        return await adapter.unblock_device(mac)

    async def _get_router_info(self) -> RouterInfo:
        adapter = await self._ensure_adapter()
        return await adapter.get_router_info()

    def health_snapshot(self) -> dict[str, Any]:
        """Synchronous status summary for /api/health — safe to call from any thread."""
        return {
            'scheduler_running': self._thread is not None and self._thread.is_alive(),
            'last_poll_at': self._last_poll_at.isoformat() if self._last_poll_at else None,
            'last_poll_error': self._last_poll_error,
        }


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
        ml_model_dir=app.config['ML_MODEL_DIR'],
        ml_min_samples=app.config['ML_MIN_SAMPLES_TO_TRAIN'],
        ml_contamination=app.config['ML_CONTAMINATION'],
        ml_retrain_cron=app.config['ML_RETRAIN_CRON'],
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
