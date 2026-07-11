from scapy.all import ARP

from sentinel.security.arp_watch import ArpWatcher


def _arp_reply(ip: str, mac: str) -> ARP:
    return ARP(op=2, psrc=ip, hwsrc=mac)


def _arp_request(ip: str, mac: str) -> ARP:
    return ARP(op=1, psrc=ip, hwsrc=mac)


class TestIsActive:
    def test_defaults_false(self):
        watcher = ArpWatcher(alert_callback=lambda e: None, iface='eth0')
        assert watcher.is_active is False


class TestSeed:
    def test_seed_populates_table_lowercased(self):
        watcher = ArpWatcher(alert_callback=lambda e: None, iface='eth0')
        watcher.seed([('10.0.0.5', 'AA:BB:CC:DD:EE:FF')])
        assert watcher._table['10.0.0.5'] == 'aa:bb:cc:dd:ee:ff'

    def test_seed_skips_blank_ips(self):
        watcher = ArpWatcher(alert_callback=lambda e: None, iface='eth0')
        watcher.seed([('', 'aa:bb:cc:dd:ee:ff')])
        assert watcher._table == {}


class TestProcess:
    def test_mac_change_for_known_ip_fires_alert(self):
        alerts = []
        watcher = ArpWatcher(alert_callback=alerts.append, iface='eth0')
        watcher.seed([('10.0.0.5', 'aa:aa:aa:aa:aa:aa')])

        watcher._process(_arp_reply('10.0.0.5', 'bb:bb:bb:bb:bb:bb'))

        assert len(alerts) == 1
        assert alerts[0]['type'] == 'ARP_SPOOF'
        assert alerts[0]['severity'] == 'CRITICAL'
        assert alerts[0]['old_mac'] == 'aa:aa:aa:aa:aa:aa'
        assert alerts[0]['new_mac'] == 'bb:bb:bb:bb:bb:bb'

    def test_same_mac_does_not_fire(self):
        alerts = []
        watcher = ArpWatcher(alert_callback=alerts.append, iface='eth0')
        watcher.seed([('10.0.0.5', 'aa:aa:aa:aa:aa:aa')])

        watcher._process(_arp_reply('10.0.0.5', 'aa:aa:aa:aa:aa:aa'))

        assert alerts == []

    def test_unknown_ip_does_not_fire_but_is_learned(self):
        alerts = []
        watcher = ArpWatcher(alert_callback=alerts.append, iface='eth0')

        watcher._process(_arp_reply('10.0.0.9', 'cc:cc:cc:cc:cc:cc'))

        assert alerts == []
        assert watcher._table['10.0.0.9'] == 'cc:cc:cc:cc:cc:cc'

    def test_arp_request_is_ignored(self):
        alerts = []
        watcher = ArpWatcher(alert_callback=alerts.append, iface='eth0')
        watcher.seed([('10.0.0.5', 'aa:aa:aa:aa:aa:aa')])

        watcher._process(_arp_request('10.0.0.5', 'bb:bb:bb:bb:bb:bb'))

        assert alerts == []  # op=1 (request), not a reply — ignored entirely

    def test_table_updates_after_alert(self):
        watcher = ArpWatcher(alert_callback=lambda e: None, iface='eth0')
        watcher.seed([('10.0.0.5', 'aa:aa:aa:aa:aa:aa')])

        watcher._process(_arp_reply('10.0.0.5', 'bb:bb:bb:bb:bb:bb'))

        assert watcher._table['10.0.0.5'] == 'bb:bb:bb:bb:bb:bb'
