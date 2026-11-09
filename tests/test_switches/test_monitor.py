"""SwitchMonitor with fake drivers, repository and clock: scheduling, back-off, isolation, reconfiguration."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from sentinel.switches.core.monitor import SwitchMonitor
from sentinel.switches.source import SwitchAuthError, SwitchParseError, SwitchUnreachable
from tests.test_switches.helpers import snap

pytestmark = pytest.mark.asyncio

A = '02:00:00:00:00:0a'


class FakeRepo:
    def __init__(self, targets):
        self.targets = targets
        self.ok: list[tuple] = []
        self.failures: list[tuple] = []

    async def list_enabled(self):
        return list(self.targets)

    async def record_ok(self, target_id, *, model, firmware, now):
        self.ok.append((target_id, model, firmware))

    async def record_failure(self, target_id, error):
        self.failures.append((target_id, error))
        return len(self.failures)


class FakeSource:
    """Plays back a script: each poll() returns a snapshot or raises the exception in the script."""

    def __init__(self, script):
        self.script = list(script)
        self.polls = 0
        self.closed = False

    async def poll(self):
        self.polls += 1
        step = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(step, BaseException):
            raise step
        return step

    async def aclose(self):
        self.closed = True


class Harness:
    def __init__(self, targets, scripts, passwords=None):
        self.now = 1000.0
        self.repo = FakeRepo(targets)
        self.persisted: list[tuple] = []
        self.built: list[tuple] = []
        self.sources: dict[int, FakeSource] = {}
        self.scripts = scripts
        self.passwords = passwords if passwords is not None else {t.id: 'pw' for t in targets}

        async def persist(target_id, name, attribution, taken_at):
            self.persisted.append((target_id, name, attribution))
            return []

        def build(spec, host, username, password):
            target_id = next(t.id for t in targets if t.host == host)
            self.built.append((target_id, password))
            source = FakeSource(self.scripts[target_id])
            self.sources[target_id] = source
            return source

        self.monitor = SwitchMonitor(
            repo=self.repo, persist=persist, read_password=lambda tid: self.passwords.get(tid, ''),
            build=build, clock=lambda: self.now,
        )


def target(tid=1, name='sw', interval=15, host=None, spec='hc-swtgw218as'):
    return SimpleNamespace(id=tid, name=name, spec_id=spec, host=host or f'192.168.0.{tid + 1}', username='admin', poll_interval_s=interval)


GOOD_1 = snap({'1': (0, 0)}, [(A, '1')])
GOOD_2 = snap({'1': (50, 4000)}, [(A, '1')])


async def test_a_switch_is_polled_when_its_interval_is_up_and_not_before():
    h = Harness([target()], {1: [GOOD_1]})
    await h.monitor.poll_due()
    assert h.sources[1].polls == 1
    h.now += 10
    await h.monitor.poll_due()
    assert h.sources[1].polls == 1                  # 10 s < 15 s
    h.now += 5
    await h.monitor.poll_due()
    assert h.sources[1].polls == 2


async def test_the_first_poll_is_a_baseline_and_the_second_stores_a_device_sample():
    h = Harness([target()], {1: [GOOD_1, GOOD_2]})
    await h.monitor.poll_due()
    assert h.persisted[0][2].samples == []
    h.now += 15
    await h.monitor.poll_due()
    [sample] = h.persisted[1][2].samples
    assert (sample.mac_address, sample.bytes_sent_delta, sample.bytes_recv_delta) == (A, 50, 4000)
    assert h.repo.ok[-1] == (1, 'TEST-1', 'v1')


async def test_a_minimum_interval_is_enforced():
    h = Harness([target(interval=1)], {1: [GOOD_1]})
    await h.monitor.poll_due()
    h.now += 5
    await h.monitor.poll_due()
    assert h.sources[1].polls == 1                  # SWITCH_MIN_POLL_SECONDS (10) applies, not 1


async def test_failures_back_off_and_a_success_resets_them():
    h = Harness([target()], {1: [SwitchUnreachable('no answer')] * 4 + [GOOD_1]})
    waits = []
    for _ in range(4):
        before = h.now
        await h.monitor.poll_due()
        waits.append(h.monitor._runtime[1].next_due - before)
        h.now = h.monitor._runtime[1].next_due
    assert waits == [15.0, 60.0, 120.0, 240.0]      # first failure: normal interval; then 60 s doubling
    await h.monitor.poll_due()
    assert h.monitor._runtime[1].failures == 0
    assert [f[1] for f in h.repo.failures] == ['no answer'] * 4
    assert h.repo.ok


async def test_the_back_off_is_capped():
    h = Harness([target()], {1: [SwitchUnreachable('x')]})
    for _ in range(20):
        await h.monitor.poll_due()
        h.now = h.monitor._runtime[1].next_due
    assert h.monitor._runtime[1].next_due - h.now <= 900.0


async def test_a_rejected_login_is_recorded_and_not_retried_before_its_back_off():
    h = Harness([target()], {1: [SwitchAuthError('the switch rejected the login: check the user name and password')]})
    await h.monitor.poll_due()
    await h.monitor.poll_due()                      # same instant: not due
    assert h.sources[1].polls == 1
    assert 'rejected the login' in h.repo.failures[0][1]


async def test_a_changed_password_builds_a_new_driver_and_closes_the_old_one():
    h = Harness([target()], {1: [GOOD_1]})
    await h.monitor.poll_due()
    first = h.sources[1]
    h.passwords[1] = 'new-password'
    h.now += 15
    await h.monitor.poll_due()
    assert first.closed and h.sources[1] is not first
    assert [b[1] for b in h.built] == ['pw', 'new-password']


async def test_an_unchanged_configuration_keeps_the_same_driver():
    h = Harness([target()], {1: [GOOD_1]})
    for _ in range(3):
        await h.monitor.poll_due()
        h.now += 15
    assert len(h.built) == 1


async def test_no_saved_password_is_a_clear_error_and_nothing_is_built():
    h = Harness([target()], {1: [GOOD_1]}, passwords={})
    await h.monitor.poll_due()
    assert h.built == []
    assert h.repo.failures == [(1, 'no password is saved for this switch')]
    await h.monitor.poll_due()                      # not retried every cycle
    assert len(h.repo.failures) == 1


async def test_saving_the_missing_password_starts_polling_on_the_next_due_time():
    h = Harness([target()], {1: [GOOD_1]}, passwords={})
    await h.monitor.poll_due()
    h.passwords[1] = 'pw'
    h.now += 15
    await h.monitor.poll_due()
    assert h.sources[1].polls == 1


async def test_an_unknown_switch_type_is_reported():
    h = Harness([target(spec='no-such-switch')], {1: [GOOD_1]})
    await h.monitor.poll_due()
    assert 'unknown or unsupported' in h.repo.failures[0][1]


async def test_a_removed_switch_is_closed_and_forgotten():
    t = target()
    h = Harness([t], {1: [GOOD_1]})
    await h.monitor.poll_due()
    source = h.sources[1]
    h.repo.targets = []
    await h.monitor.poll_due()
    assert source.closed and h.monitor._runtime == {}


async def test_one_broken_switch_does_not_stop_the_others():
    h = Harness([target(1), target(2)], {1: [SwitchParseError('layout changed')], 2: [GOOD_1]})
    await h.monitor.poll_due()
    assert h.sources[2].polls == 1 and [p[0] for p in h.persisted] == [2]
    assert h.repo.failures[0][0] == 1


async def test_an_unexpected_exception_is_contained_and_logged_not_raised(caplog):
    h = Harness([target()], {1: [RuntimeError('boom')]})
    await h.monitor.poll_due()                      # must not raise
    assert 'unexpected error' in caplog.text


async def test_two_switches_keep_separate_counters():
    h = Harness([target(1), target(2)], {1: [GOOD_1, GOOD_2], 2: [GOOD_1, GOOD_2]})
    await h.monitor.poll_due()
    h.now += 15
    await h.monitor.poll_due()
    assert [len(p[2].samples) for p in h.persisted] == [0, 0, 1, 1]
