"""Base class for all threat detectors.

Every detector lives under sentinel/detection/detectors/ and is registered in
sentinel/detection/pipeline.py — detection logic must never be added to the
adapter, API routes, or scheduler directly (see CLAUDE.md rule 3).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficSample
from sentinel.db.models import Alert


class BaseDetector(ABC):
    """A single threat-detection rule, run against every device/traffic event.

    The pipeline itself is stateless; any state a detector needs across polls
    (rolling windows, last-seen values) is the detector's own responsibility —
    kept in-memory or read back from PostgreSQL.
    """

    enabled: bool = True
    severity: str = 'INFO'  # INFO | WARNING | CRITICAL

    @abstractmethod
    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        """Called for every DeviceSnapshot in a poll cycle. Return an Alert or None."""

    @abstractmethod
    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        """Called for every per-device TrafficSample. Return an Alert or None.

        Only called for TrafficGranularity.PER_DEVICE samples with a matching
        DeviceSnapshot — wired PER_PORT samples carry a port alias, not a
        device MAC, and per docs/router/wired-monitoring-caveat.md must not be
        attributed to a single device.
        """
