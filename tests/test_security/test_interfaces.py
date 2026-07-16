from sentinel.security.interfaces import list_network_interfaces


class TestListNetworkInterfaces:
    def test_returns_a_sorted_list(self):
        interfaces = list_network_interfaces()
        assert interfaces == sorted(interfaces)

    def test_excludes_loopback(self):
        assert 'lo' not in list_network_interfaces()

    def test_returns_at_least_one_interface(self):
        """Any host running this test has at least one real NIC — a totally
        empty result would mean the discovery mechanism itself is broken."""
        assert len(list_network_interfaces()) >= 1
