import threading

from scapy.all import BOOTP, DHCP, Ether, IP, UDP

from sentinel.security.dhcp_watch import DhcpWatcher

_ROUTER_IP = '10.100.102.1'


def _dhcp_offer(server_ip: str, server_mac: str = 'aa:bb:cc:dd:ee:ff') -> Ether:
    """Builds a DHCP OFFER and round-trips it through raw bytes — scapy only
    decodes the message-type option to its integer form (2 = OFFER) when
    dissecting real wire bytes, not when a packet is hand-constructed in
    memory (there it stays the human-readable string 'offer'), and
    DhcpWatcher._process expects the dissected (int) form since that's what
    a real sniffed packet looks like."""
    pkt = (
        Ether(src=server_mac, dst='ff:ff:ff:ff:ff:ff') /
        IP(src=server_ip, dst='255.255.255.255') /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr='10.100.102.50') /
        DHCP(options=[('message-type', 'offer'), 'end'])
    )
    return Ether(bytes(pkt))


def _dhcp_discover() -> Ether:
    pkt = (
        Ether(src='11:22:33:44:55:66', dst='ff:ff:ff:ff:ff:ff') /
        IP(src='0.0.0.0', dst='255.255.255.255') /
        UDP(sport=68, dport=67) /
        BOOTP(op=1) /
        DHCP(options=[('message-type', 'discover'), 'end'])
    )
    return Ether(bytes(pkt))


class _FinishedThread:
    """A stand-in for AsyncSniffer with a .thread that's already exited —
    see test_arp_watch.py's identical helper for why."""

    def __init__(self, *args, exception=None, **kwargs):
        self.thread = threading.Thread(target=lambda: None)
        self.thread.start()
        self.thread.join()
        self.exception = exception

    def start(self) -> None:
        pass

    def stop(self, join: bool = True) -> None:
        pass


class TestIsActive:
    def test_defaults_false(self):
        watcher = DhcpWatcher(alert_callback=lambda e: None, iface='eth0', expected_server_ip=_ROUTER_IP)
        assert watcher.is_active is False

    def test_watch_for_failure_marks_inactive_on_exception(self):
        watcher = DhcpWatcher(alert_callback=lambda e: None, iface='eth0', expected_server_ip=_ROUTER_IP)
        watcher._active = True
        fake_sniffer = _FinishedThread(exception=ValueError("Interface 'eth0' not found !"))
        watcher._sniffer = fake_sniffer

        watcher._watch_for_failure(fake_sniffer, threading.Event())

        assert watcher.is_active is False

    def test_watch_for_failure_is_a_no_op_for_an_intentional_stop(self):
        watcher = DhcpWatcher(alert_callback=lambda e: None, iface='eth0', expected_server_ip=_ROUTER_IP)
        watcher._active = True
        fake_sniffer = _FinishedThread(exception=None)
        watcher._sniffer = fake_sniffer
        stop_requested = threading.Event()
        stop_requested.set()

        watcher._watch_for_failure(fake_sniffer, stop_requested)

        assert watcher.is_active is False

    def test_stop_without_ever_starting_is_a_no_op(self):
        watcher = DhcpWatcher(alert_callback=lambda e: None, iface='eth0', expected_server_ip=_ROUTER_IP)
        watcher.stop()  # must not raise
        assert watcher.is_active is False

    def test_restart_updates_iface(self, monkeypatch):
        monkeypatch.setattr('sentinel.security.dhcp_watch.AsyncSniffer', lambda *a, **k: _FinishedThread())
        watcher = DhcpWatcher(alert_callback=lambda e: None, iface='eth0', expected_server_ip=_ROUTER_IP)
        watcher.restart('eth1')
        assert watcher.iface == 'eth1'


class TestProcess:
    def test_offer_from_router_does_not_fire(self):
        alerts = []
        watcher = DhcpWatcher(alert_callback=alerts.append, iface='eth0', expected_server_ip=_ROUTER_IP)

        watcher._process(_dhcp_offer(_ROUTER_IP))

        assert alerts == []

    def test_offer_from_unexpected_ip_fires_alert(self):
        alerts = []
        watcher = DhcpWatcher(alert_callback=alerts.append, iface='eth0', expected_server_ip=_ROUTER_IP)

        watcher._process(_dhcp_offer('10.100.102.66', server_mac='de:ad:be:ef:00:01'))

        assert len(alerts) == 1
        assert alerts[0]['type'] == 'ROGUE_DHCP_SERVER'
        assert alerts[0]['severity'] == 'CRITICAL'
        assert alerts[0]['ip'] == '10.100.102.66'
        assert alerts[0]['mac'] == 'de:ad:be:ef:00:01'
        assert _ROUTER_IP in alerts[0]['description']

    def test_discover_is_ignored(self):
        """Only OFFER (a server announcing itself) is a signal — DISCOVER is
        a client broadcasting a request, not a server responding."""
        alerts = []
        watcher = DhcpWatcher(alert_callback=alerts.append, iface='eth0', expected_server_ip=_ROUTER_IP)

        watcher._process(_dhcp_discover())

        assert alerts == []

    def test_non_dhcp_packet_is_ignored(self):
        alerts = []
        watcher = DhcpWatcher(alert_callback=alerts.append, iface='eth0', expected_server_ip=_ROUTER_IP)

        watcher._process(Ether() / IP(src='10.100.102.1', dst='10.100.102.50'))

        assert alerts == []
