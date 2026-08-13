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
from sentinel.db.models import Device, TrafficSample
from sentinel.db.repositories import DeviceTypeProfileRepository
from sentinel.db.session import get_session
from sentinel.ml.anomaly_engine import AnomalyEngine
from sentinel.ml.feature_builder import build_feature_vector

logger = logging.getLogger(__name__)

RETRAIN_WINDOW_DAYS = 7


class ModelTrainer:
    """Refits every device's models from its last RETRAIN_WINDOW_DAYS of traffic history."""

    def __init__(self, engine: AnomalyEngine) -> None:
        self._engine = engine
        self._profile_repo = DeviceTypeProfileRepository()

    async def retrain_all(self) -> None:
        """Retrain every device that has PER_DEVICE traffic history, one at a time.

        Resolves each device's contamination rate from its device_type
        profile (see DeviceTypeProfileRepository.get_profile) before
        refitting — a device whose type is prone to short, legitimate,
        recurring bursts (e.g. a phone during a video call) gets fit with a
        higher rate, so that pattern stops being flagged as an outlier
        indefinitely. A device with no devices row, or a device_type not
        found in the mac_to_type map (deleted/never seen), falls back to
        DEFAULT_PROFILE's contamination — same as an unrecognized type
        always has.
        """
        mac_to_type = await self._distinct_macs_with_device_type()
        for mac, device_type in mac_to_type.items():
            vectors = await self._feature_vectors_for(mac)
            contamination = (await self._profile_repo.get_profile(device_type))['contamination']
            self._engine.retrain_from_history(mac, vectors, contamination=contamination)
        logger.info('Nightly ML retrain complete: %d device(s) processed', len(mac_to_type))

    async def _distinct_macs_with_device_type(self) -> dict[str, str | None]:
        """One query instead of N+1 — every distinct PER_DEVICE mac with
        recent traffic history, left-joined against its current device_type
        (None if the mac has no devices row, or the row's device_type is
        blank)."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=RETRAIN_WINDOW_DAYS)
        async with get_session() as session:
            result = await session.execute(
                select(TrafficSample.mac_address, Device.device_type)
                .outerjoin(Device, Device.mac_address == TrafficSample.mac_address)
                .where(
                    TrafficSample.time >= cutoff,
                    TrafficSample.granularity == TrafficGranularity.PER_DEVICE.value,
                )
                .distinct()
            )
            return dict(result.all())

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
