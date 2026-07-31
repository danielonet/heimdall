"""Pure unit tests for SentinelScheduler.metrics_snapshot() — a function of
self._thread/_last_poll_duration_s/_last_poll_at only, so no DB/adapter is
needed (see health_snapshot's equivalent tests for the same reasoning)."""
from datetime import datetime, timedelta, timezone

from sentinel.scheduler.scheduler import SentinelScheduler


def _scheduler(**overrides):
    sched = object.__new__(SentinelScheduler)
    sched._thread = None
    sched._last_poll_duration_s = None
    sched._last_poll_at = None
    for key, value in overrides.items():
        setattr(sched, key, value)
    return sched


class TestMetricsSnapshot:
    def test_scheduler_not_started_reports_not_running(self):
        snapshot = _scheduler().metrics_snapshot()
        assert snapshot['scheduler_running'] is False
        assert snapshot['last_poll_duration_s'] is None
        assert snapshot['last_poll_age_s'] is None

    def test_running_thread_reports_running(self):
        class _FakeThread:
            def is_alive(self):
                return True

        snapshot = _scheduler(_thread=_FakeThread()).metrics_snapshot()
        assert snapshot['scheduler_running'] is True

    def test_dead_thread_reports_not_running(self):
        class _FakeThread:
            def is_alive(self):
                return False

        snapshot = _scheduler(_thread=_FakeThread()).metrics_snapshot()
        assert snapshot['scheduler_running'] is False

    def test_reports_last_poll_duration(self):
        snapshot = _scheduler(_last_poll_duration_s=1.234).metrics_snapshot()
        assert snapshot['last_poll_duration_s'] == 1.234

    def test_reports_last_poll_age_in_seconds(self):
        ten_seconds_ago = datetime.now(timezone.utc) - timedelta(seconds=10)
        snapshot = _scheduler(_last_poll_at=ten_seconds_ago).metrics_snapshot()
        assert snapshot['last_poll_age_s'] >= 10
        assert snapshot['last_poll_age_s'] < 12  # generous upper bound for test execution time
