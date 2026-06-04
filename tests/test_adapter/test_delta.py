import pytest

from sentinel.adapter.models import TrafficGranularity
from sentinel.adapter.sagemcom.delta import TrafficDeltaCalculator


class TestComputeFirstCall:
    """On the very first call for a key there is no previous snapshot."""

    def test_deltas_are_zero_on_first_call(self):
        calc = TrafficDeltaCalculator()
        sample = calc.compute('aa:bb:cc:dd:ee:ff', 1_000_000, 5_000_000, TrafficGranularity.PER_DEVICE)
        assert sample.bytes_sent_delta == 0
        assert sample.bytes_recv_delta == 0

    def test_throughput_is_zero_on_first_call(self):
        calc = TrafficDeltaCalculator()
        sample = calc.compute('mac', 1_000, 2_000, TrafficGranularity.PER_DEVICE)
        assert sample.throughput_up_kbps == 0
        assert sample.throughput_dn_kbps == 0

    def test_mac_address_stored_correctly(self):
        calc = TrafficDeltaCalculator()
        sample = calc.compute('de:ad:be:ef:00:01', 0, 0, TrafficGranularity.PER_DEVICE)
        assert sample.mac_address == 'de:ad:be:ef:00:01'

    def test_granularity_stored(self):
        calc = TrafficDeltaCalculator()
        sample = calc.compute('k', 0, 0, TrafficGranularity.PER_PORT, port_alias='PHY5')
        assert sample.granularity == TrafficGranularity.PER_PORT

    def test_port_alias_stored(self):
        calc = TrafficDeltaCalculator()
        sample = calc.compute('PHY5', 0, 0, TrafficGranularity.PER_PORT, port_alias='PHY5')
        assert sample.port_alias == 'PHY5'


class TestComputeNormalDelta:
    """Normal case: counters increase between polls."""

    def test_sent_delta_correct(self):
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 1_000, 2_000, TrafficGranularity.PER_DEVICE)
        sample = calc.compute('mac', 1_100, 2_000, TrafficGranularity.PER_DEVICE)
        assert sample.bytes_sent_delta == 100

    def test_recv_delta_correct(self):
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 1_000, 2_000, TrafficGranularity.PER_DEVICE)
        sample = calc.compute('mac', 1_000, 2_500, TrafficGranularity.PER_DEVICE)
        assert sample.bytes_recv_delta == 500

    def test_throughput_up_kbps(self):
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 0, 0, TrafficGranularity.PER_DEVICE, poll_interval_s=1)
        # 128 000 bytes sent in 1 second = 128 000 * 8 / 1024 = 1000 kbps
        sample = calc.compute('mac', 128_000, 0, TrafficGranularity.PER_DEVICE, poll_interval_s=1)
        assert sample.throughput_up_kbps == 1000

    def test_throughput_dn_kbps(self):
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 0, 0, TrafficGranularity.PER_DEVICE, poll_interval_s=1)
        sample = calc.compute('mac', 0, 256_000, TrafficGranularity.PER_DEVICE, poll_interval_s=1)
        assert sample.throughput_dn_kbps == 2000

    def test_throughput_uses_poll_interval(self):
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 0, 0, TrafficGranularity.PER_DEVICE, poll_interval_s=15)
        # 15 * 128 000 bytes in 15 seconds = 128 000 * 8 / 1024 = 1000 kbps
        sample = calc.compute(
            'mac', 15 * 128_000, 0, TrafficGranularity.PER_DEVICE, poll_interval_s=15
        )
        assert sample.throughput_up_kbps == 1000

    def test_zero_delta_when_counters_unchanged(self):
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 999, 888, TrafficGranularity.PER_DEVICE)
        sample = calc.compute('mac', 999, 888, TrafficGranularity.PER_DEVICE)
        assert sample.bytes_sent_delta == 0
        assert sample.bytes_recv_delta == 0

    def test_independent_keys_tracked_separately(self):
        calc = TrafficDeltaCalculator()
        calc.compute('mac_a', 0, 0, TrafficGranularity.PER_DEVICE)
        calc.compute('mac_b', 0, 0, TrafficGranularity.PER_DEVICE)
        sample_a = calc.compute('mac_a', 500, 0, TrafficGranularity.PER_DEVICE)
        sample_b = calc.compute('mac_b', 0, 300, TrafficGranularity.PER_DEVICE)
        assert sample_a.bytes_sent_delta == 500
        assert sample_b.bytes_recv_delta == 300


class TestComputeCounterReset:
    """Counter reset guard: new value < previous value means router rebooted."""

    def test_sent_reset_uses_new_value_as_delta(self):
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 1_000_000, 0, TrafficGranularity.PER_DEVICE)
        # Counter reset: new value is 50 000 (far below previous 1 000 000)
        sample = calc.compute('mac', 50_000, 0, TrafficGranularity.PER_DEVICE)
        assert sample.bytes_sent_delta == 50_000

    def test_recv_reset_uses_new_value_as_delta(self):
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 0, 5_000_000, TrafficGranularity.PER_DEVICE)
        sample = calc.compute('mac', 0, 100, TrafficGranularity.PER_DEVICE)
        assert sample.bytes_recv_delta == 100

    def test_only_reset_counter_is_affected(self):
        """If only one counter resets, the other is computed normally."""
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 1_000_000, 500_000, TrafficGranularity.PER_DEVICE)
        # sent resets, recv grows normally
        sample = calc.compute('mac', 100, 600_000, TrafficGranularity.PER_DEVICE)
        assert sample.bytes_sent_delta == 100      # reset: use new value
        assert sample.bytes_recv_delta == 100_000  # normal delta

    def test_exact_same_value_is_not_a_reset(self):
        """Counter unchanged (delta == 0) is NOT a reset."""
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 1_000, 0, TrafficGranularity.PER_DEVICE)
        sample = calc.compute('mac', 1_000, 0, TrafficGranularity.PER_DEVICE)
        assert sample.bytes_sent_delta == 0  # not a reset, just no new traffic

    def test_reset_to_zero(self):
        """Counter resetting all the way to zero is handled correctly."""
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 9_999_999, 0, TrafficGranularity.PER_DEVICE)
        sample = calc.compute('mac', 0, 0, TrafficGranularity.PER_DEVICE)
        assert sample.bytes_sent_delta == 0


class TestClear:
    def test_clear_removes_state(self):
        calc = TrafficDeltaCalculator()
        calc.compute('mac', 1000, 2000, TrafficGranularity.PER_DEVICE)
        calc.clear('mac')
        # After clear, next call should behave as if it's the first call
        sample = calc.compute('mac', 500, 1000, TrafficGranularity.PER_DEVICE)
        assert sample.bytes_sent_delta == 0
        assert sample.bytes_recv_delta == 0

    def test_clear_nonexistent_key_is_safe(self):
        calc = TrafficDeltaCalculator()
        calc.clear('no-such-key')  # must not raise
