"""Nightly retraining: refits each device's anomaly models from its recent
TimescaleDB history. Runs on ML_RETRAIN_CRON via APScheduler — see
sentinel/scheduler/scheduler.py.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from sentinel.adapter.models import TrafficGranularity
from sentinel.adapter.models import TrafficSample as TrafficSampleSnapshot
from sentinel.db.models import TrafficSample
from sentinel.db.session import get_session
from sentinel.ml.anomaly_engine import AnomalyEngine
from sentinel.ml.feature_builder import build_feature_vector

logger = logging.getLogger(__name__)

RETRAIN_WINDOW_DAYS = 7


class ModelTrainer:
    """Refits every device's models from its last RETRAIN_WINDOW_DAYS of traffic history."""

    def __init__(self, engine: AnomalyEngine) -> None:
        self._engine = engine

    async def retrain_all(self) -> None:
        """Retrain every device that has PER_DEVICE traffic history, one at a time."""
        macs = await self._distinct_macs()
        for mac in macs:
            vectors = await self._feature_vectors_for(mac)
            self._engine.retrain_from_history(mac, vectors)
        logger.info('Nightly ML retrain complete: %d device(s) processed', len(macs))

    async def _distinct_macs(self) -> list[str]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=RETRAIN_WINDOW_DAYS)
        async with get_session() as session:
            result = await session.execute(
                select(TrafficSample.mac_address)
                .where(
                    TrafficSample.time >= cutoff,
                    TrafficSample.granularity == TrafficGranularity.PER_DEVICE.value,
                )
                .distinct()
            )
            return list(result.scalars().all())

    async def _feature_vectors_for(self, mac: str):
        cutoff = datetime.now(timezone.utc) - timedelta(days=RETRAIN_WINDOW_DAYS)
        async with get_session() as session:
            result = await session.execute(
                select(TrafficSample)
                .where(TrafficSample.mac_address == mac, TrafficSample.time >= cutoff)
                .order_by(TrafficSample.time)
            )
            rows = result.scalars().all()

        return [build_feature_vector(_to_snapshot(row)) for row in rows]


def _to_snapshot(row: TrafficSample) -> TrafficSampleSnapshot:
    """Adapt a persisted traffic_samples row into the dataclass build_feature_vector expects."""
    return TrafficSampleSnapshot(
        mac_address=row.mac_address,
        timestamp=row.time,
        bytes_sent_delta=row.bytes_sent_delta or 0,
        bytes_recv_delta=row.bytes_recv_delta or 0,
        throughput_up_kbps=row.throughput_up_kbps or 0,
        throughput_dn_kbps=row.throughput_dn_kbps or 0,
        granularity=TrafficGranularity(row.granularity) if row.granularity else TrafficGranularity.PER_DEVICE,
        poll_interval_s=row.poll_interval_s or 15,
    )
