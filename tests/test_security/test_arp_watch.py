import threading

from scapy.all import ARP

from sentinel.security.arp_watch import ArpWatcher


def _arp_reply(ip: str, mac: str) -> ARP:
    return ARP(op=2, psrc=ip, hwsrc=mac)


def _arp_request(ip: str, mac: str) -> ARP:
    return ARP(op=1, psrc=ip, hwsrc=mac)


class _FinishedThread:
    """A stand-in for AsyncSniffer with a .thread that's already exited —
    so _watch_for_failure's join() returns immediately, making these tests
    deterministic instead of racing a real background sniffer thread. Also
    doubles as a fake AsyncSniffer class (start()/stop() no-ops) so it can
    stand in for `AsyncSniffer(...)` itself in restart()/start() tests."""

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
        watcher = ArpWatcher(alert_callback=lambda e: None, iface='eth0')
        assert watcher.is_active is False

    def test_watch_for_failure_marks_inactive_on_exception(self):
        """Scapy raises ValueError (not OSError) for a bad iface name — a
        misconfigured SNIFF_IFACE must still be reported as inactive."""
        watcher = ArpWatcher(alert_callback=lambda e: None, iface='eth0')
        watcher._active = True  # pretend sniffing had started
        fake_sniffer = _FinishedThread(exception=ValueError("Interface 'eth0' not found !"))
        watcher._sniffer = fake_sniffer

        watcher._watch_for_failure(fake_sniffer, threading.Event())

        assert watcher.is_active is False

    def test_watch_for_failure_is_a_no_op_for_an_intentional_stop(self):
        """stop()/restart() set the Event before tearing down — must not log
        a spurious failure for a deliberate stop."""
        watcher = ArpWatcher(alert_callback=lambda e: None, iface='eth0')
        watcher._active = True
        fake_sniffer = _FinishedThread(exception=None)
        watcher._sniffer = fake_sniffer
        stop_requested = threading.Event()
        stop_requested.set()

        watcher._watch_for_failure(fake_sniffer, stop_requested)

        assert watcher.is_active is False  # still updated...

    def test_stop_without_ever_starting_is_a_no_op(self):
        watcher = ArpWatcher(alert_callback=lambda e: None, iface='eth0')
        watcher.stop()  # must not raise
        assert watcher.is_active is False

    def test_restart_updates_iface(self, monkeypatch):
        """restart() must switch to the new interface even if the sniffer
        itself can't actually be exercised in this sandbox (no NET_RAW)."""
        monkeypatch.setattr('sentinel.security.arp_watch.AsyncSniffer', lambda *a, **k: _FinishedThread())
        watcher = ArpWatcher(alert_callback=lambda e: None, iface='eth0')
        watcher.restart('eth1')
        assert watcher.iface == 'eth1'


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

    def test_unknown_ip_fires_a_new_ip_event_not_a_spoof_alert(self):
        """Not a mismatch (nothing was "known" to conflict with), so not
        ARP_SPOOF — but a passive "something just connected" signal is
        still useful (see SentinelScheduler._handle_arp_new_ip), distinct
        from a real security finding."""
        events = []
        watcher = ArpWatcher(alert_callback=events.append, iface='eth0')

        watcher._process(_arp_reply('10.0.0.9', 'cc:cc:cc:cc:cc:cc'))

        assert len(events) == 1
        assert events[0] == {'type': 'ARP_NEW_IP', 'ip': '10.0.0.9', 'mac': 'cc:cc:cc:cc:cc:cc'}
        assert watcher._table['10.0.0.9'] == 'cc:cc:cc:cc:cc:cc'

    def test_new_ip_event_does_not_fire_again_for_the_same_ip(self):
        events = []
        watcher = ArpWatcher(alert_callback=events.append, iface='eth0')

        watcher._process(_arp_reply('10.0.0.9', 'cc:cc:cc:cc:cc:cc'))
        watcher._process(_arp_reply('10.0.0.9', 'cc:cc:cc:cc:cc:cc'))  # same IP, same MAC, seen again

        assert len(events) == 1  # only the first sighting counts as "new"

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

    def test_table_is_capped_evicting_the_least_recently_updated_ip(self, monkeypatch):
        """Regression: this table used to grow forever — confirmed live,
        21 -> 233 entries over 3 days — since nothing ever evicted an IP
        that stopped being seen. Now capped via LRU eviction."""
        monkeypatch.setattr('sentinel.security.arp_watch._MAX_TRACKED_IPS', 3)
        watcher = ArpWatcher(alert_callback=lambda e: None, iface='eth0')

        watcher._process(_arp_reply('10.0.0.1', 'aa:aa:aa:aa:aa:a1'))
        watcher._process(_arp_reply('10.0.0.2', 'aa:aa:aa:aa:aa:a2'))
        watcher._process(_arp_reply('10.0.0.3', 'aa:aa:aa:aa:aa:a3'))
        watcher._process(_arp_reply('10.0.0.4', 'aa:aa:aa:aa:aa:a4'))  # pushes past the cap of 3

        assert len(watcher._table) == 3
        assert '10.0.0.1' not in watcher._table  # oldest-updated, evicted first
        assert '10.0.0.4' in watcher._table

    def test_touching_an_existing_ip_keeps_it_from_being_evicted(self, monkeypatch):
        monkeypatch.setattr('sentinel.security.arp_watch._MAX_TRACKED_IPS', 3)
        watcher = ArpWatcher(alert_callback=lambda e: None, iface='eth0')

        watcher._process(_arp_reply('10.0.0.1', 'aa:aa:aa:aa:aa:a1'))
        watcher._process(_arp_reply('10.0.0.2', 'aa:aa:aa:aa:aa:a2'))
        watcher._process(_arp_reply('10.0.0.3', 'aa:aa:aa:aa:aa:a3'))
        watcher._process(_arp_reply('10.0.0.1', 'aa:aa:aa:aa:aa:a1'))  # re-touch — now the most recent
        watcher._process(_arp_reply('10.0.0.4', 'aa:aa:aa:aa:aa:a4'))  # pushes past the cap of 3

        assert '10.0.0.1' in watcher._table       # was re-touched, survives
        assert '10.0.0.2' not in watcher._table   # untouched since, evicted instead
