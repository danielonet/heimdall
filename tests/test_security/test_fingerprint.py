import threading

from scapy.all import IP, TCP, UDP

from sentinel.security.fingerprint import PassiveFingerprinter


def _syn(src: str, ttl: int, window: int) -> IP:
    return IP(src=src, ttl=ttl) / TCP(sport=1234, dport=80, flags='S', window=window)


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
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: None, iface='eth0')
        assert fp.is_active is False

    def test_watch_for_failure_marks_inactive_on_exception(self):
        """Scapy raises ValueError (not OSError) for a bad iface name — a
        misconfigured SNIFF_IFACE must still be reported as inactive."""
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: None, iface='eth0')
        fp._active = True  # pretend sniffing had started
        fake_sniffer = _FinishedThread(exception=ValueError("Interface 'eth0' not found !"))
        fp._sniffer = fake_sniffer

        fp._watch_for_failure(fake_sniffer, threading.Event())

        assert fp.is_active is False

    def test_watch_for_failure_is_a_no_op_for_an_intentional_stop(self):
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: None, iface='eth0')
        fp._active = True
        fake_sniffer = _FinishedThread(exception=None)
        fp._sniffer = fake_sniffer
        stop_requested = threading.Event()
        stop_requested.set()

        fp._watch_for_failure(fake_sniffer, stop_requested)

        assert fp.is_active is False

    def test_stop_without_ever_starting_is_a_no_op(self):
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: None, iface='eth0')
        fp.stop()  # must not raise
        assert fp.is_active is False

    def test_restart_updates_iface(self, monkeypatch):
        monkeypatch.setattr('sentinel.security.fingerprint.AsyncSniffer', lambda *a, **k: _FinishedThread())
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: None, iface='eth0')
        fp.restart('eth1')
        assert fp.iface == 'eth1'


class TestProcess:
    def test_known_signature_linux(self):
        results = []
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: results.append((ip, os)), iface='eth0')
        fp._process(_syn('10.0.0.5', ttl=64, window=65535))
        assert results == [('10.0.0.5', 'Linux / Android')]

    def test_known_signature_windows(self):
        results = []
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: results.append((ip, os)), iface='eth0')
        fp._process(_syn('10.0.0.6', ttl=128, window=65535))
        assert results == [('10.0.0.6', 'Windows')]

    def test_unknown_signature(self):
        results = []
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: results.append((ip, os)), iface='eth0')
        fp._process(_syn('10.0.0.7', ttl=32, window=1024))
        assert results == [('10.0.0.7', 'Unknown')]

    def test_same_ip_same_signature_not_refingerprinted(self):
        results = []
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: results.append((ip, os)), iface='eth0')
        fp._process(_syn('10.0.0.5', ttl=64, window=65535))
        fp._process(_syn('10.0.0.5', ttl=64, window=65535))  # same signature, same IP
        assert len(results) == 1

    def test_same_ip_changed_signature_is_refingerprinted(self):
        """A known IP suddenly presenting a different OS signature must fire
        again (not just once per IP) — the scheduler compares it against the
        device's previously recorded fingerprint to catch a possible
        MAC-cloning attack. See SentinelScheduler._persist_fingerprint."""
        results = []
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: results.append((ip, os)), iface='eth0')
        fp._process(_syn('10.0.0.5', ttl=64, window=65535))
        fp._process(_syn('10.0.0.5', ttl=128, window=65535))  # different signature, same IP
        assert results == [('10.0.0.5', 'Linux / Android'), ('10.0.0.5', 'Windows')]

    def test_non_tcp_packet_ignored(self):
        results = []
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: results.append((ip, os)), iface='eth0')
        pkt = IP(src='10.0.0.8') / UDP(sport=1234, dport=53)
        fp._process(pkt)
        assert results == []

    def test_cache_is_capped_evicting_the_least_recently_updated_ip(self, monkeypatch):
        """Regression: this cache used to grow forever — confirmed live,
        21 -> 233 entries over 3 days — since nothing ever evicted an IP
        that stopped being seen. Now capped via LRU eviction."""
        monkeypatch.setattr('sentinel.security.fingerprint._MAX_TRACKED_IPS', 3)
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: None, iface='eth0')

        fp._process(_syn('10.0.0.1', ttl=64, window=65535))
        fp._process(_syn('10.0.0.2', ttl=64, window=65535))
        fp._process(_syn('10.0.0.3', ttl=64, window=65535))
        fp._process(_syn('10.0.0.4', ttl=64, window=65535))  # pushes past the cap of 3

        assert len(fp._last_guess) == 3
        assert '10.0.0.1' not in fp._last_guess  # oldest-updated, evicted first
        assert '10.0.0.4' in fp._last_guess
