import threading

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap

from sentinel.security.wifi_monitor import WifiMonitorWatcher

_PROTECTED_SSID = 'MyHomeWiFi'
_TRUSTED_BSSID = 'c4:eb:42:94:80:4c'


def _beacon(ssid: str, bssid: str, signal: int = -55) -> RadioTap:
    """Builds a beacon and round-trips it through raw bytes — same reasoning
    as test_dhcp_watch.py's _dhcp_offer helper: dBm_AntSignal is only
    actually present on the dissected packet (what a real sniff produces)
    once the `present` bitmask is set and the bytes are re-parsed, not on a
    hand-constructed-in-memory packet."""
    pkt = (
        RadioTap(present='dBm_AntSignal', dBm_AntSignal=signal) /
        Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid) /
        Dot11Beacon() /
        Dot11Elt(ID=0, info=ssid.encode())
    )
    return RadioTap(bytes(pkt))


def _probe_req(mac: str, ssid: str = '', signal: int = -60) -> RadioTap:
    pkt = (
        RadioTap(present='dBm_AntSignal', dBm_AntSignal=signal) /
        Dot11(type=0, subtype=4, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3='ff:ff:ff:ff:ff:ff') /
        Dot11ProbeReq() /
        Dot11Elt(ID=0, info=ssid.encode())
    )
    return RadioTap(bytes(pkt))


def _watcher(alerts, sightings, protected_ssids=(_PROTECTED_SSID,), trusted_bssids=(_TRUSTED_BSSID,)):
    return WifiMonitorWatcher(
        alert_callback=alerts.append, sighting_callback=sightings.append,
        iface='wlan0mon', protected_ssids=list(protected_ssids), trusted_bssids=list(trusted_bssids),
    )


class TestProcessBeacon:
    def test_protected_ssid_from_untrusted_bssid_fires_rogue_ap(self):
        alerts, sightings = [], []
        watcher = _watcher(alerts, sightings, trusted_bssids=[_TRUSTED_BSSID])

        watcher._process(_beacon(_PROTECTED_SSID, 'aa:bb:cc:dd:ee:ff'))

        assert len(alerts) == 1
        assert alerts[0]['type'] == 'ROGUE_AP'
        assert alerts[0]['severity'] == 'CRITICAL'
        assert alerts[0]['ssid'] == _PROTECTED_SSID
        assert alerts[0]['bssid'] == 'aa:bb:cc:dd:ee:ff'
        assert alerts[0]['signal'] == -55
        assert _PROTECTED_SSID in alerts[0]['description']
        assert sightings == []

    def test_protected_ssid_from_trusted_bssid_does_not_fire(self):
        alerts, sightings = [], []
        watcher = _watcher(alerts, sightings, trusted_bssids=[_TRUSTED_BSSID])

        watcher._process(_beacon(_PROTECTED_SSID, _TRUSTED_BSSID))

        assert alerts == []

    def test_trusted_bssid_match_is_case_insensitive(self):
        """BSSIDs off the wire are always lowercase (Scapy dissects them
        that way), but an admin might type/paste one in any case in
        Settings — __init__ lowercases trusted_bssids on the way in."""
        alerts, sightings = [], []
        watcher = _watcher(alerts, sightings, trusted_bssids=[_TRUSTED_BSSID.upper()])

        watcher._process(_beacon(_PROTECTED_SSID, _TRUSTED_BSSID))

        assert alerts == []

    def test_unprotected_ssid_does_not_fire(self):
        alerts, sightings = [], []
        watcher = _watcher(alerts, sightings, protected_ssids=[_PROTECTED_SSID])

        watcher._process(_beacon('SomeoneElsesWifi', 'aa:bb:cc:dd:ee:ff'))

        assert alerts == []

    def test_hidden_ssid_beacon_does_not_fire(self):
        """An empty SSID element (hidden-SSID beacons are common and
        legitimate) can never match a non-empty protected SSID — must not
        crash or false-positive on it."""
        alerts, sightings = [], []
        watcher = _watcher(alerts, sightings, protected_ssids=[_PROTECTED_SSID])

        watcher._process(_beacon('', 'aa:bb:cc:dd:ee:ff'))

        assert alerts == []

    def test_empty_protected_list_never_fires(self):
        alerts, sightings = [], []
        watcher = _watcher(alerts, sightings, protected_ssids=[], trusted_bssids=[])

        watcher._process(_beacon(_PROTECTED_SSID, 'aa:bb:cc:dd:ee:ff'))

        assert alerts == []


class TestProcessProbeRequest:
    def test_fires_a_sighting_for_any_mac(self):
        alerts, sightings = [], []
        watcher = _watcher(alerts, sightings)

        watcher._process(_probe_req('11:22:33:44:55:66', ssid='MyPhone', signal=-62))

        assert alerts == []
        assert len(sightings) == 1
        assert sightings[0] == {'mac': '11:22:33:44:55:66', 'ssid': 'MyPhone', 'signal': -62}

    def test_blank_probed_ssid_becomes_none(self):
        alerts, sightings = [], []
        watcher = _watcher(alerts, sightings)

        watcher._process(_probe_req('11:22:33:44:55:66', ssid=''))

        assert sightings[0]['ssid'] is None

    def test_never_treated_as_an_alert_regardless_of_ssid(self):
        """A probe request for a protected SSID is completely normal (any
        device that has ever joined that network keeps probing for it) —
        must never be confused with a beacon impersonating it."""
        alerts, sightings = [], []
        watcher = _watcher(alerts, sightings, protected_ssids=[_PROTECTED_SSID])

        watcher._process(_probe_req('11:22:33:44:55:66', ssid=_PROTECTED_SSID))

        assert alerts == []
        assert len(sightings) == 1


class TestUpdateTargets:
    def test_hot_swaps_without_restarting(self):
        alerts, sightings = [], []
        watcher = _watcher(alerts, sightings, protected_ssids=[], trusted_bssids=[])
        watcher._process(_beacon(_PROTECTED_SSID, 'aa:bb:cc:dd:ee:ff'))
        assert alerts == []  # not protected yet

        watcher.update_targets([_PROTECTED_SSID], [])
        watcher._process(_beacon(_PROTECTED_SSID, 'aa:bb:cc:dd:ee:ff'))
        assert len(alerts) == 1


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
        watcher = _watcher([], [])
        assert watcher.is_active is False

    def test_start_never_sniffs_if_monitor_mode_cannot_be_entered(self, monkeypatch):
        """No NET_ADMIN, no such interface, not monitor-capable — whatever
        the reason, start() must degrade cleanly rather than attempting to
        sniff on an interface still in managed mode."""
        monkeypatch.setattr('sentinel.security.wifi_monitor.enter_monitor_mode', lambda iface: False)
        sniffer_calls = []
        monkeypatch.setattr(
            'sentinel.security.wifi_monitor.AsyncSniffer',
            lambda *a, **k: sniffer_calls.append(1) or _FinishedThread(),
        )
        watcher = _watcher([], [])

        watcher.start()

        assert watcher.is_active is False
        assert sniffer_calls == []

    def test_stop_without_ever_starting_is_a_no_op(self, monkeypatch):
        monkeypatch.setattr('sentinel.security.wifi_monitor.exit_monitor_mode', lambda iface: True)
        watcher = _watcher([], [])
        watcher.stop()  # must not raise
        assert watcher.is_active is False

    def test_watch_for_failure_marks_inactive_on_exception(self):
        watcher = _watcher([], [])
        watcher._active = True
        fake_sniffer = _FinishedThread(exception=ValueError("Interface 'wlan0mon' not found !"))
        watcher._sniffer = fake_sniffer

        watcher._watch_for_failure(fake_sniffer, threading.Event())

        assert watcher.is_active is False
