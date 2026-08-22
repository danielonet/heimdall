import dataclasses
import os
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity, TrafficSample
from sentinel.db.models import Alert
from sentinel.db.repositories import AlertRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.detectors.high_upload import HighUploadDetector

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    """HighUploadDetector's get_profile() call is DB-backed for a non-blank
    device_type (see the IP Camera/Printer/unrecognized-string tests below),
    and resolve() calls are real DB I/O once an alert has been open — every
    test in this file needs the DB now."""
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Alert).where(Alert.device_mac == _MAC))
    await get_engine().dispose()

_SNAPSHOT = DeviceSnapshot(
    mac_address='aa:bb:cc:dd:ee:ff',
    ip_address='10.100.102.10',
    hostname='upload-heavy-device',
    vendor_name='Acme Corp',
    interface_name='WiFi',
)


def _sample(sent: int, recv: int, granularity=TrafficGranularity.PER_DEVICE, mac='aa:bb:cc:dd:ee:ff') -> TrafficSample:
    return TrafficSample(
        mac_address=mac,
        timestamp=datetime.now(timezone.utc),
        bytes_sent_delta=sent,
        bytes_recv_delta=recv,
        granularity=granularity,
    )


class TestInspectTraffic:
    async def test_below_min_bytes_never_alerts(self):
        detector = HighUploadDetector()
        for _ in range(5):
            alert = await detector.inspect_traffic(_sample(sent=100, recv=10), _SNAPSHOT)
            assert alert is None

    async def test_low_ratio_never_alerts(self):
        detector = HighUploadDetector()
        for _ in range(5):
            alert = await detector.inspect_traffic(_sample(sent=20_000, recv=20_000), _SNAPSHOT)
            assert alert is None

    async def test_single_high_ratio_poll_does_not_alert(self):
        detector = HighUploadDetector()
        alert = await detector.inspect_traffic(_sample(sent=100_000, recv=1_000), _SNAPSHOT)
        assert alert is None

    async def test_sustained_high_ratio_alerts_on_third_poll(self):
        detector = HighUploadDetector()
        sample = _sample(sent=100_000, recv=1_000)
        assert await detector.inspect_traffic(sample, _SNAPSHOT) is None
        assert await detector.inspect_traffic(sample, _SNAPSHOT) is None
        alert = await detector.inspect_traffic(sample, _SNAPSHOT)
        assert alert is not None
        assert alert.severity == 'WARNING'
        assert alert.alert_type == 'HIGH_UPLOAD'
        assert alert.device_mac == 'aa:bb:cc:dd:ee:ff'

    async def test_counter_resets_after_alert_fires(self):
        detector = HighUploadDetector()
        sample = _sample(sent=100_000, recv=1_000)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        await detector.inspect_traffic(sample, _SNAPSHOT)  # fires here
        # Immediately after firing, the streak resets — needs 3 more to fire again.
        assert await detector.inspect_traffic(sample, _SNAPSHOT) is None
        assert await detector.inspect_traffic(sample, _SNAPSHOT) is None

    async def test_fires_again_on_a_second_fresh_streak_no_cooldown(self):
        """Regression: an attack tool sustaining a high ratio continuously
        used to re-fire every SUSTAINED_POLLS worth of polls for as long as
        it kept running — confirmed in production, 1,885 alerts from one
        device over 4 days. That's now AlertRepository.upsert()'s job (at
        the poll_cycle level) — this detector itself has no cooldown of its
        own, so a second, genuinely fresh 3-poll streak must fire again."""
        detector = HighUploadDetector()
        sample = _sample(sent=100_000, recv=1_000)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        first_alert = await detector.inspect_traffic(sample, _SNAPSHOT)
        assert first_alert is not None

        await detector.inspect_traffic(sample, _SNAPSHOT)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        second_alert = await detector.inspect_traffic(sample, _SNAPSHOT)  # a fresh 3-poll streak
        assert second_alert is not None

    async def test_streak_reset_resolves_the_open_alert_row(self):
        alert, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type='HIGH_UPLOAD', severity='WARNING', description='seed',
        )

        detector = HighUploadDetector()
        sample = _sample(sent=100_000, recv=1_000)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        await detector.inspect_traffic(sample, _SNAPSHOT)  # fires, sets _alert_open
        assert detector._alert_open[_MAC] is True

        low = _sample(sent=20_000, recv=20_000)
        await detector.inspect_traffic(low, _SNAPSHOT)  # ratio drops back under threshold

        async with get_session() as session:
            refreshed = await session.get(Alert, alert.id)
            assert refreshed.resolved is True
        assert detector._alert_open[_MAC] is False

    async def test_resolve_is_not_called_when_nothing_was_ever_open(self, monkeypatch):
        called = False

        async def _boom(*args, **kwargs):
            nonlocal called
            called = True
            return True

        monkeypatch.setattr(AlertRepository, 'resolve', _boom)
        detector = HighUploadDetector()
        await detector.inspect_traffic(_sample(sent=100, recv=10), _SNAPSHOT)  # below MIN_BYTES
        assert called is False

    async def test_low_ratio_poll_breaks_the_streak(self):
        detector = HighUploadDetector()
        high = _sample(sent=100_000, recv=1_000)
        low = _sample(sent=20_000, recv=20_000)
        await detector.inspect_traffic(high, _SNAPSHOT)
        await detector.inspect_traffic(high, _SNAPSHOT)
        await detector.inspect_traffic(low, _SNAPSHOT)  # breaks the streak
        alert = await detector.inspect_traffic(high, _SNAPSHOT)
        assert alert is None  # streak restarted, only 1 high poll so far

    async def test_per_port_samples_are_skipped(self):
        detector = HighUploadDetector()
        port_sample = _sample(sent=500_000, recv=1_000, granularity=TrafficGranularity.PER_PORT, mac='PHY5')
        for _ in range(5):
            alert = await detector.inspect_traffic(port_sample, _SNAPSHOT)
            assert alert is None

    async def test_inspect_device_always_returns_none(self):
        detector = HighUploadDetector()
        assert await detector.inspect_device(_SNAPSHOT) is None


class TestDeviceTypeAwareThreshold:
    async def test_ip_camera_tolerates_a_ratio_that_would_alert_by_default(self):
        """IP cameras legitimately sustain a high upload/download ratio
        (streaming out) — device_profiles.py raises their threshold to 10:1,
        so a 5:1 ratio (well above the 3:1 default) must not alert."""
        camera_snapshot = dataclasses.replace(_SNAPSHOT, device_type='IP Camera')
        detector = HighUploadDetector()
        sample = _sample(sent=50_000, recv=10_000)  # 5:1 ratio
        for _ in range(5):
            assert await detector.inspect_traffic(sample, camera_snapshot) is None

    async def test_printer_alerts_at_a_ratio_the_default_threshold_would_ignore(self):
        """A 2.5:1 ratio never counts as 'high' under the flat default
        threshold (3.0), but device_profiles.py tightens Printer's threshold
        to 2.0 — printers have almost no legitimate reason to sustain any
        elevated upload ratio. Printer's seeded volume_sustained_polls is 2
        (not the default 3) — see test_sustain_count_is_also_device_type_aware
        below for the regression this profile row's *other* field used to
        silently not apply to this detector at all."""
        printer_snapshot = dataclasses.replace(_SNAPSHOT, device_type='Printer')
        detector = HighUploadDetector()
        sample = _sample(sent=25_000, recv=10_000)  # 2.5:1
        assert await detector.inspect_traffic(sample, printer_snapshot) is None
        alert = await detector.inspect_traffic(sample, printer_snapshot)
        assert alert is not None
        assert alert.alert_type == 'HIGH_UPLOAD'
        assert '2 consecutive polls' in alert.description

    async def test_sustain_count_is_also_device_type_aware(self):
        """Regression: this detector used to read only the ratio threshold
        from the per-device-type profile row and kept a hardcoded 3-poll
        sustain for every device type regardless — so raising a type's
        volume_sustained_polls from the Device Type Profiles UI (the same
        field AnomalousVolumeDetector's streak already respected) silently
        did nothing here. Smartphone's seeded profile raises the sustain to
        6 polls specifically to absorb short legitimate bursts — confirm a
        5-poll streak (one short of that) does NOT alert, where the old
        hardcoded 3-poll behavior would have fired on poll 3."""
        phone_snapshot = dataclasses.replace(_SNAPSHOT, device_type='Smartphone')
        detector = HighUploadDetector()
        sample = _sample(sent=100_000, recv=1_000)  # well above Smartphone's 2.5:1 threshold
        for _ in range(5):
            assert await detector.inspect_traffic(sample, phone_snapshot) is None
        alert = await detector.inspect_traffic(sample, phone_snapshot)  # 6th poll
        assert alert is not None
        assert '6 consecutive polls' in alert.description

    async def test_unrecognized_device_type_behaves_like_default(self):
        weird_snapshot = dataclasses.replace(_SNAPSHOT, device_type='Some Router String We Have Never Seen')
        detector = HighUploadDetector()
        sample = _sample(sent=100_000, recv=1_000)
        assert await detector.inspect_traffic(sample, weird_snapshot) is None
        assert await detector.inspect_traffic(sample, weird_snapshot) is None
        alert = await detector.inspect_traffic(sample, weird_snapshot)
        assert alert is not None
