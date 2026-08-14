import os
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.adapter.models import WanStats
from sentinel.db.models import Alert
from sentinel.db.repositories import AlertRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.wan_bandwidth import WanBandwidthDetector

pytestmark = pytest.mark.asyncio

_ALERT_TYPE = 'WAN_BANDWIDTH_SPIKE'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    """inspect() is now async and resolve() calls are real DB I/O once an
    alert has been open — every test in this file needs the DB."""
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Alert).where(Alert.device_mac.is_(None), Alert.alert_type == _ALERT_TYPE))
    await get_engine().dispose()


def _sample(up: int, down: int) -> WanStats:
    return WanStats(
        timestamp=datetime.now(timezone.utc),
        bytes_sent_delta=0,
        bytes_recv_delta=0,
        throughput_up_kbps=up,
        throughput_dn_kbps=down,
    )


class TestInspect:
    async def test_no_alert_during_the_baseline_warmup_period(self):
        detector = WanBandwidthDetector()
        for _ in range(9):
            assert await detector.inspect(_sample(100, 500)) is None

    async def test_steady_traffic_never_alerts(self):
        detector = WanBandwidthDetector()
        for _ in range(50):
            assert await detector.inspect(_sample(100, 500)) is None

    async def test_sustained_spike_alerts(self):
        detector = WanBandwidthDetector()
        # Establish a low-variance baseline first — a little jitter so
        # stdev isn't exactly zero (which the detector treats as "not
        # enough real variation to judge an outlier against" and never fires).
        for i in range(15):
            jitter = 5 if i % 2 == 0 else -5
            await detector.inspect(_sample(100 + jitter, 500 + jitter))

        # A huge, sustained spike should clear mean + 3*stdev easily.
        assert await detector.inspect(_sample(50_000, 50_000)) is None  # 1st high poll — not sustained yet
        alert = await detector.inspect(_sample(50_000, 50_000))  # 2nd — fires
        assert alert is not None
        assert alert.alert_type == 'WAN_BANDWIDTH_SPIKE'
        assert alert.severity == 'WARNING'
        assert alert.device_mac is None

    async def test_single_high_poll_does_not_alert(self):
        detector = WanBandwidthDetector()
        for i in range(15):
            jitter = 5 if i % 2 == 0 else -5
            await detector.inspect(_sample(100 + jitter, 500 + jitter))
        assert await detector.inspect(_sample(50_000, 50_000)) is None

    async def test_fires_again_on_a_second_sustained_spike_no_cooldown(self):
        """Dedup for a continuously-elevated household total is now
        AlertRepository.upsert()'s job (at the poll_cycle level) — this
        detector has no cooldown of its own, so once real traffic has
        settled back to baseline (refilling the WINDOW_SIZE rolling window
        and un-skewing mean/stdev — immediately repeating the spike would
        itself inflate stdev enough to mask a second spike, an orthogonal
        statistical effect, not a cooldown), a fresh sustained spike must
        fire again."""
        detector = WanBandwidthDetector()
        for i in range(15):
            jitter = 5 if i % 2 == 0 else -5
            await detector.inspect(_sample(100 + jitter, 500 + jitter))
        await detector.inspect(_sample(50_000, 50_000))
        first_alert = await detector.inspect(_sample(50_000, 50_000))
        assert first_alert is not None

        # Back to baseline for a full WINDOW_SIZE stretch — ages the spike
        # values out of the rolling window entirely.
        for i in range(20):
            jitter = 5 if i % 2 == 0 else -5
            await detector.inspect(_sample(100 + jitter, 500 + jitter))

        await detector.inspect(_sample(50_000, 50_000))
        second_alert = await detector.inspect(_sample(50_000, 50_000))
        assert second_alert is not None

    async def test_drop_back_under_threshold_resolves_the_open_alert_row(self):
        alert, _ = await AlertRepository().upsert(
            device_mac=None, alert_type=_ALERT_TYPE, severity='WARNING', description='seed',
        )

        detector = WanBandwidthDetector()
        for i in range(15):
            jitter = 5 if i % 2 == 0 else -5
            await detector.inspect(_sample(100 + jitter, 500 + jitter))
        await detector.inspect(_sample(50_000, 50_000))
        await detector.inspect(_sample(50_000, 50_000))  # fires
        assert detector._alert_open is True

        await detector.inspect(_sample(100, 500))  # back to baseline

        async with get_session() as session:
            refreshed = await session.get(Alert, alert.id)
            assert refreshed.resolved is True
        assert detector._alert_open is False

    async def test_resolve_is_not_called_when_nothing_was_ever_open(self, monkeypatch):
        called = False

        async def _boom(*args, **kwargs):
            nonlocal called
            called = True
            return True

        monkeypatch.setattr(AlertRepository, 'resolve', _boom)
        detector = WanBandwidthDetector()
        for _ in range(15):
            await detector.inspect(_sample(100, 500))
        assert called is False

    async def test_zero_variance_baseline_never_alerts(self):
        """A perfectly flat baseline (stdev=0) has no meaningful notion of
        'outlier' yet — must not fire on the first bit of real variation."""
        detector = WanBandwidthDetector()
        for _ in range(15):
            await detector.inspect(_sample(100, 500))
        assert await detector.inspect(_sample(50_000, 50_000)) is None
        assert await detector.inspect(_sample(50_000, 50_000)) is None
