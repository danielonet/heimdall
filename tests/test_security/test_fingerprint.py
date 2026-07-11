from scapy.all import IP, TCP, UDP

from sentinel.security import fingerprint
from sentinel.security.fingerprint import PassiveFingerprinter


def _syn(src: str, ttl: int, window: int) -> IP:
    return IP(src=src, ttl=ttl) / TCP(sport=1234, dport=80, flags='S', window=window)


class TestIsActive:
    def test_defaults_false(self):
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: None, iface='eth0')
        assert fp.is_active is False

    def test_resets_false_when_interface_not_found(self, monkeypatch):
        """Scapy raises ValueError (not OSError) for a bad iface name — a
        misconfigured SNIFF_IFACE must still be reported as inactive."""
        def _raise(*args, **kwargs):
            raise ValueError("Interface 'eth0' not found !")

        monkeypatch.setattr(fingerprint, 'sniff', _raise)
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: None, iface='eth0')
        fp._run()
        assert fp.is_active is False


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

    def test_same_ip_only_fingerprinted_once(self):
        results = []
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: results.append((ip, os)), iface='eth0')
        fp._process(_syn('10.0.0.5', ttl=64, window=65535))
        fp._process(_syn('10.0.0.5', ttl=128, window=65535))  # different signature, same IP
        assert len(results) == 1

    def test_non_tcp_packet_ignored(self):
        results = []
        fp = PassiveFingerprinter(on_fingerprint=lambda ip, os: results.append((ip, os)), iface='eth0')
        pkt = IP(src='10.0.0.8') / UDP(sport=1234, dport=53)
        fp._process(pkt)
        assert results == []
