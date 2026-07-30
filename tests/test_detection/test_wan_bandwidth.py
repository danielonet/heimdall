from datetime import datetime, timezone

from sentinel.adapter.models import WanStats
from sentinel.detection.wan_bandwidth import WanBandwidthDetector


def _sample(up: int, down: int) -> WanStats:
    return WanStats(
        timestamp=datetime.now(timezone.utc),
        bytes_sent_delta=0,
        bytes_recv_delta=0,
        throughput_up_kbps=up,
        throughput_dn_kbps=down,
    )


class TestInspect:
    def test_no_alert_during_the_baseline_warmup_period(self):
        detector = WanBandwidthDetector()
        for _ in range(9):
            assert detector.inspect(_sample(100, 500)) is None

    def test_steady_traffic_never_alerts(self):
        detector = WanBandwidthDetector()
        for _ in range(50):
            assert detector.inspect(_sample(100, 500)) is None

    def test_sustained_spike_alerts(self):
        detector = WanBandwidthDetector()
        # Establish a low-variance baseline first — a little jitter so
        # stdev isn't exactly zero (which the detector treats as "not
        # enough real variation to judge an outlier against" and never fires).
        for i in range(15):
            jitter = 5 if i % 2 == 0 else -5
            detector.inspect(_sample(100 + jitter, 500 + jitter))

        # A huge, sustained spike should clear mean + 3*stdev easily.
        assert detector.inspect(_sample(50_000, 50_000)) is None  # 1st high poll — not sustained yet
        alert = detector.inspect(_sample(50_000, 50_000))  # 2nd — fires
        assert alert is not None
        assert alert.alert_type == 'WAN_BANDWIDTH_SPIKE'
        assert alert.severity == 'WARNING'
        assert alert.device_mac is None

    def test_single_high_poll_does_not_alert(self):
        detector = WanBandwidthDetector()
        for i in range(15):
            jitter = 5 if i % 2 == 0 else -5
            detector.inspect(_sample(100 + jitter, 500 + jitter))
        assert detector.inspect(_sample(50_000, 50_000)) is None

    def test_no_re_alert_within_the_cooldown(self):
        detector = WanBandwidthDetector()
        for i in range(15):
            jitter = 5 if i % 2 == 0 else -5
            detector.inspect(_sample(100 + jitter, 500 + jitter))
        detector.inspect(_sample(50_000, 50_000))
        first_alert = detector.inspect(_sample(50_000, 50_000))
        assert first_alert is not None

        detector.inspect(_sample(50_000, 50_000))
        second_alert = detector.inspect(_sample(50_000, 50_000))
        assert second_alert is None  # still cooling down

    def test_zero_variance_baseline_never_alerts(self):
        """A perfectly flat baseline (stdev=0) has no meaningful notion of
        'outlier' yet — must not fire on the first bit of real variation."""
        detector = WanBandwidthDetector()
        for _ in range(15):
            detector.inspect(_sample(100, 500))
        assert detector.inspect(_sample(50_000, 50_000)) is None
        assert detector.inspect(_sample(50_000, 50_000)) is None
