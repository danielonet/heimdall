from sentinel.switches.core.counters import CounterTracker


def test_first_reading_only_sets_a_baseline():
    assert CounterTracker().update('p', 1000, 0.0) is None


def test_normal_increase():
    t = CounterTracker()
    t.update('p', 1000, 0.0)
    d = t.update('p', 1600, 10.0)
    assert (d.delta, d.elapsed_s, d.wrapped, d.reset) == (600, 10.0, False, False)


def test_64_bit_counter_going_backwards_is_a_reset_and_the_delta_is_the_new_value():
    t = CounterTracker()
    t.update('p', 5_000_000, 0.0)
    d = t.update('p', 1200, 10.0)
    assert d.reset and not d.wrapped and d.delta == 1200


def test_32_bit_wrap_is_added_back_when_plausible_for_the_link():
    t = CounterTracker()
    prev = (1 << 32) - 1_000_000
    t.update('p', prev, 0.0, bits=32, link_bps=1_000_000_000)
    d = t.update('p', 4_000_000, 10.0, bits=32, link_bps=1_000_000_000)
    assert d.wrapped and not d.reset and d.delta == 4_000_000 + 1_000_000


def test_32_bit_decrease_that_would_exceed_the_link_speed_is_a_reset_not_a_wrap():
    """A 100 Mb/s port cannot move 4 GB in 10 s: a reboot or a cleared counter, not a wrap."""
    t = CounterTracker()
    t.update('p', 3_000_000_000, 0.0, bits=32, link_bps=100_000_000)
    d = t.update('p', 5_000, 10.0, bits=32, link_bps=100_000_000)
    assert d.reset and not d.wrapped and d.delta == 5_000


def test_32_bit_without_a_link_speed_accepts_a_wrap_only_below_half_the_range():
    t = CounterTracker()
    t.update('p', (1 << 32) - 10, 0.0, bits=32)
    assert t.update('p', 20, 10.0, bits=32).wrapped
    t2 = CounterTracker()
    t2.update('p', 3_000_000_000, 0.0, bits=32)
    assert t2.update('p', 1_000_000_000, 10.0, bits=32).reset


def test_keys_are_independent_and_forget_drops_state():
    t = CounterTracker()
    t.update('a', 10, 0.0)
    t.update('b', 99, 0.0)
    assert t.update('a', 15, 5.0).delta == 5
    t.forget('b')
    assert t.update('b', 120, 5.0) is None
    assert t.keys() == {'a', 'b'}
