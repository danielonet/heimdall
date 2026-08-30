"""Runs every enabled detector against each device/traffic event, in sequence."""
from __future__ import annotations

from sentinel.adapter.models import DeviceSnapshot, TrafficSample
from sentinel.db.models import Alert
from sentinel.detection.detectors.base import BaseDetector
from sentinel.ml.anomaly_engine import AnomalyEngine


class DetectionPipeline:
    """Ordered chain of BaseDetector instances, run against every poll cycle's events."""

    def __init__(self, detectors: list[BaseDetector]) -> None:
        self._detectors = [d for d in detectors if d.enabled]

    async def process_device(self, snapshot: DeviceSnapshot) -> list[Alert]:
        """Run every detector's inspect_device() against one device snapshot."""
        alerts = []
        for detector in self._detectors:
            alert = await detector.inspect_device(snapshot)
            if alert:
                alerts.append(alert)
        return alerts

    async def process_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> list[Alert]:
        """Run every detector's inspect_traffic() against one traffic sample."""
        alerts = []
        for detector in self._detectors:
            alert = await detector.inspect_traffic(sample, snapshot)
            if alert:
                alerts.append(alert)
        return alerts


def create_default_pipeline(anomaly_engine: AnomalyEngine) -> DetectionPipeline:
    """Build the pipeline with the detectors that are ready to run today.

    anomaly_engine must be the same instance the scheduler uses to score
    traffic_samples.anomaly_score — AnomalousVolumeDetector reads its buffered
    state/trained models, so a separate engine would never fire.

    Port/WAN-level detectors are intentionally left out for now — see
    docs/architecture/04-detection-pipeline.md.

    HighUploadDetector/SignalAnomalyDetector/AnomalousVolumeDetector — the
    three purely behavioral/statistical detectors, as opposed to the
    identity/security-relevant ones below — are wired with the same shared
    TrustedMacRepository and suppress their alerts entirely for a trusted
    MAC (confirmed live 2026-08-30: family devices doing ordinary heavy use
    kept flooding INFO/WARNING alerts even after prior tuning). NewDeviceDetector
    already had its own trust check; VendorMismatchDetector/
    AccessPointCrossingDetector deliberately keep firing regardless of
    trust — an OUI mismatch or an unauthorized guest->private jump on an
    already-trusted MAC is arguably more suspicious (a spoofed device
    hiding behind an established identity), not less.
    """
    from sentinel.db.repositories import DeviceRepository, SettingsRepository, TrustedMacRepository
    from sentinel.detection.detectors.anomalous_volume import AnomalousVolumeDetector

    from sentinel.detection.detectors.ap_crossing import AccessPointCrossingDetector
    from sentinel.detection.detectors.high_upload import HighUploadDetector
    from sentinel.detection.detectors.new_device import NewDeviceDetector
    from sentinel.detection.detectors.signal_anomaly import SignalAnomalyDetector
    from sentinel.detection.detectors.vendor_mismatch import VendorMismatchDetector

    return DetectionPipeline([
        NewDeviceDetector(DeviceRepository(), TrustedMacRepository()),
        HighUploadDetector(TrustedMacRepository()),
        VendorMismatchDetector(),
        SignalAnomalyDetector(DeviceRepository(), SettingsRepository(), TrustedMacRepository()),
        AnomalousVolumeDetector(anomaly_engine, DeviceRepository(), SettingsRepository(), TrustedMacRepository()),
        AccessPointCrossingDetector(DeviceRepository()),
    ])
