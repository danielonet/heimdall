"""Tests for sentinel/adapter/discovery.py:discover_local_ips() — the
self-block safeguard's IP source (see SentinelScheduler._is_own_host).
Mocks subprocess.check_output rather than depending on this test runner's
own real network config.
"""
from unittest.mock import patch

from sentinel.adapter.discovery import discover_local_ips

# Real `ip -4 addr show` output shape (trimmed), matching this project's
# actual dev host: a loopback plus two real LAN interfaces (wired + WiFi).
_IP_ADDR_OUTPUT = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 10.100.102.36/24 brd 10.100.102.255 scope global dynamic noprefixroute enp3s0
       valid_lft 3600sec preferred_lft 3600sec
3: wlp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    inet 10.100.102.24/24 brd 10.100.102.255 scope global dynamic noprefixroute wlp2s0
       valid_lft 3600sec preferred_lft 3600sec
4: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
"""


class TestDiscoverLocalIps:
    def test_returns_every_non_loopback_ipv4_address(self):
        with patch('sentinel.adapter.discovery.subprocess.check_output', return_value=_IP_ADDR_OUTPUT):
            ips = discover_local_ips()
        assert ips == {'10.100.102.36', '10.100.102.24', '172.17.0.1'}

    def test_excludes_loopback(self):
        with patch('sentinel.adapter.discovery.subprocess.check_output', return_value=_IP_ADDR_OUTPUT):
            ips = discover_local_ips()
        assert '127.0.0.1' not in ips

    def test_multi_homed_host_returns_more_than_one_ip(self):
        """The real-world case this function exists for: a host with both a
        wired and WiFi interface — a detector misfiring on either one must
        be recognized as self, not just the default-route interface."""
        with patch('sentinel.adapter.discovery.subprocess.check_output', return_value=_IP_ADDR_OUTPUT):
            ips = discover_local_ips()
        assert len(ips) > 1

    def test_command_failure_returns_empty_set_not_raises(self):
        with patch('sentinel.adapter.discovery.subprocess.check_output', side_effect=OSError('no ip binary')):
            assert discover_local_ips() == set()

    def test_no_interfaces_returns_empty_set(self):
        with patch('sentinel.adapter.discovery.subprocess.check_output', return_value='1: lo: ...\n'):
            assert discover_local_ips() == set()
