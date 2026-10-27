from sentinel.deployment_tiers import active_service_keys, services_for_tier


class TestServicesForTier:
    def test_minimal_has_no_docker_backed_services(self):
        services = services_for_tier('minimal')
        assert services == {
            'opencanary': False, 'zeek': False, 'clamav': False, 'suricata': False,
        }

    def test_intermediate_adds_only_opencanary(self):
        services = services_for_tier('intermediate')
        assert services['opencanary'] is True
        assert services['zeek'] is False
        assert services['clamav'] is False
        assert services['suricata'] is False

    def test_full_enables_everything(self):
        services = services_for_tier('full')
        assert all(services.values())

    def test_unknown_tier_falls_back_to_minimal(self):
        assert services_for_tier('bogus-tier') == services_for_tier('minimal')

    def test_blank_tier_falls_back_to_minimal(self):
        assert services_for_tier('') == services_for_tier('minimal')


class TestActiveServiceKeys:
    def test_minimal_only_has_always_on_services(self):
        keys = active_service_keys('minimal')
        assert set(keys) == {
            'postgres', 'redis', 'router_poll', 'arp_watch', 'dhcp_watch',
            'fingerprint', 'nmap', 'threat_intel', 'wifi_monitor',
        }

    def test_intermediate_adds_opencanary(self):
        keys = active_service_keys('intermediate')
        assert 'opencanary' in keys
        assert 'zeek_dns' not in keys
        assert 'clamav' not in keys
        assert 'suricata' not in keys

    def test_full_includes_every_row(self):
        keys = active_service_keys('full')
        assert set(keys) == {
            'postgres', 'redis', 'router_poll', 'arp_watch', 'dhcp_watch',
            'fingerprint', 'nmap', 'threat_intel', 'opencanary', 'zeek_dns',
            'zeek_beacon', 'clamav', 'suricata', 'wifi_monitor',
        }

    def test_unknown_tier_falls_back_to_minimal(self):
        assert active_service_keys('bogus-tier') == active_service_keys('minimal')
