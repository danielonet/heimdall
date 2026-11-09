"""SentinelScheduler._switch_poll_job: wiring only. The monitor's behaviour is covered in tests/test_switches."""
import logging

import pytest

from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio


class FakeMonitor:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls = 0
        self.error = error

    async def poll_due(self) -> None:
        self.calls += 1
        if self.error:
            raise self.error


def bare_scheduler() -> SentinelScheduler:
    return object.__new__(SentinelScheduler)     # scheduler tests build doubles without __init__


async def test_the_job_polls_the_monitor():
    scheduler = bare_scheduler()
    scheduler._switch_monitor = FakeMonitor()
    await scheduler._switch_poll_job()
    assert scheduler._switch_monitor.calls == 1


async def test_a_monitor_failure_never_escapes_the_job(caplog):
    scheduler = bare_scheduler()
    scheduler._switch_monitor = FakeMonitor(RuntimeError('boom'))
    with caplog.at_level(logging.ERROR):
        await scheduler._switch_poll_job()       # must not raise: APScheduler would log and skip the next run
    assert 'Switch poll cycle failed' in caplog.text


async def test_the_monitor_is_created_on_first_use(monkeypatch):
    created = []

    class Recorder(FakeMonitor):
        def __init__(self) -> None:
            super().__init__()
            created.append(self)

    monkeypatch.setattr('sentinel.switches.core.monitor.SwitchMonitor', Recorder)
    scheduler = bare_scheduler()
    assert scheduler._switch_monitor is None
    await scheduler._switch_poll_job()
    await scheduler._switch_poll_job()
    assert len(created) == 1 and created[0].calls == 2


async def test_the_nightly_retention_prunes_the_switch_hypertable():
    """A new hypertable that the retention job does not name grows forever."""
    import inspect
    source = inspect.getsource(SentinelScheduler._data_retention_job)
    assert "drop_chunks('switch_port_stats'" in source
