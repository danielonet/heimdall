from sentinel.adapter.models import TrafficGranularity
from sentinel.switches.core.attribution import attribute, port_occupancy
from sentinel.switches.core.counters import CounterTracker
from sentinel.switches.models import MacEntry

from tests.test_switches.helpers import SELF_MAC as SELF
from tests.test_switches.helpers import snap

A, B, C, D = ('02:00:00:00:00:0a', '02:00:00:00:00:0b', '02:00:00:00:00:0c', '02:00:00:00:00:0d')


def two_polls(first, second, seconds=10.0):
    tracker = CounterTracker()
    attribute(first, tracker, 0.0, 'sw')
    return attribute(second, tracker, seconds, 'sw')


def test_one_mac_on_a_port_gets_that_ports_traffic_as_per_device():
    result = two_polls(snap({'1': (100, 1000)}, [(A, '1')]), snap({'1': (150, 5000)}, [(A, '1')]))
    [sample] = result.samples
    assert sample.mac_address == A and sample.granularity is TrafficGranularity.PER_DEVICE


def test_direction_the_ports_rx_is_the_devices_upload_and_tx_its_download():
    """Port rx = received BY the switch = sent by the device. Getting this backwards inverts HighUploadDetector."""
    result = two_polls(snap({'1': (100, 1000)}, [(A, '1')]), snap({'1': (150, 5000)}, [(A, '1')]))
    [sample] = result.samples
    assert sample.bytes_sent_delta == 50        # the device uploaded 50
    assert sample.bytes_recv_delta == 4000      # the device downloaded 4000


def test_a_port_with_several_macs_is_credited_to_nobody():
    macs = [(A, '8'), (B, '8'), (C, '8')]
    result = two_polls(snap({'8': (0, 0)}, macs), snap({'8': (900, 9000)}, macs))
    assert result.samples == []
    [reading] = result.ports
    assert reading.attributed_mac is None and len(reading.macs) == 3 and reading.bytes_out_delta == 9000


def test_a_port_with_no_learned_mac_is_a_port_total_only():
    result = two_polls(snap({'2': (0, 0)}, []), snap({'2': (0, 500)}, []))
    assert result.samples == [] and result.ports[0].bytes_out_delta == 500


def test_the_switchs_own_mac_and_the_cpu_port_are_not_devices():
    macs = [MacEntry(mac=SELF, port='CPU'), MacEntry(mac=SELF, port='3'), MacEntry(mac=A, port='3')]
    assert port_occupancy(snap({'3': (0, 0)}, macs)) == {'3': [A]}


def test_the_same_mac_in_two_vlans_counts_once():
    macs = [MacEntry(mac=A, port='3', vlan=1), MacEntry(mac=A, port='3', vlan=20)]
    assert port_occupancy(snap({'3': (0, 0)}, macs)) == {'3': [A]}


def test_static_entries_do_not_make_a_device():
    macs = [MacEntry(mac=A, port='3', dynamic=False)]
    assert port_occupancy(snap({'3': (0, 0)}, macs)) == {}


def test_a_stale_second_mac_makes_the_port_shared_the_safe_direction():
    result = two_polls(snap({'3': (0, 0)}, [(A, '3'), (B, '3')]), snap({'3': (10, 10)}, [(A, '3'), (B, '3')]))
    assert result.samples == []


def test_first_poll_is_only_a_baseline():
    result = attribute(snap({'1': (100, 1000)}, [(A, '1')]), CounterTracker(), 0.0, 'sw')
    assert result.samples == []
    assert result.ports[0].bytes_in_delta is None and result.ports[0].attributed_mac == A


def test_throughput_uses_the_measured_elapsed_time():
    result = two_polls(snap({'1': (0, 0)}, [(A, '1')]), snap({'1': (0, 10 * 1024 * 1024 // 8)}, [(A, '1')]), seconds=10.0)
    assert result.samples[0].throughput_dn_kbps == 1024      # 1 Mbit/s = 1024 "kbit/s" in this codebase's unit
    assert result.samples[0].poll_interval_s == 10


def test_a_port_that_disappears_is_forgotten_by_the_tracker():
    tracker = CounterTracker()
    attribute(snap({'1': (1, 1), '2': (1, 1)}, []), tracker, 0.0, 'sw')
    attribute(snap({'1': (2, 2)}, []), tracker, 5.0, 'sw')
    assert tracker.keys() == {'sw:1:rx', 'sw:1:tx'}


def test_two_switches_do_not_share_counters():
    tracker = CounterTracker()
    attribute(snap({'1': (100, 100)}, []), tracker, 0.0, 'sw1')
    result = attribute(snap({'1': (5, 5)}, []), tracker, 5.0, 'sw2')   # first reading of sw2: baseline, not a reset of sw1
    assert result.ports[0].bytes_in_delta is None
