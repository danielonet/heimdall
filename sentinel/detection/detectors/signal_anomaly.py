"""SignalAnomalyDetector — flags a sudden RSSI jump on a known WiFi device.

A large signal-strength change can mean the device physically moved, or that
a different device is now transmitting under a spoofed MAC address.
"""
from __future__ import annotations

from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficSample
from sentinel.db.models import Alert
from sentinel.detection.detectors.base import BaseDetector

RSSI_DELTA_THRESHOLD_DBM = 15


class SignalAnomalyDetector(BaseDetector):
    """Fires when a WiFi device's RSSI shifts by more than RSSI_DELTA_THRESHOLD_DBM between polls."""

    severity = 'WARNING'

    def __init__(self) -> None:
        self._last_rssi: dict[str, int] = {}

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        if snapshot.interface_name != 'WiFi':
            return None  # wired devices report signal_strength_dbm=0, not meaningful

        previous = self._last_rssi.get(snapshot.mac_address)
        self._last_rssi[snapshot.mac_address] = snapshot.signal_strength_dbm

        if previous is None:
            return None  # first observation, nothing to compare against

        delta = abs(snapshot.signal_strength_dbm - previous)
        if delta <= RSSI_DELTA_THRESHOLD_DBM:
            return None

        return Alert(
            device_mac=snapshot.mac_address,
            alert_type='SIGNAL_ANOMALY',
            severity=self.severity,
            description=(
                f'{snapshot.hostname or snapshot.mac_address} signal strength '
                f'jumped {delta} dBm ({previous} -> {snapshot.signal_strength_dbm} dBm)'
            ),
            raw_data={'previous_dbm': previous, 'current_dbm': snapshot.signal_strength_dbm},
        )

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None
