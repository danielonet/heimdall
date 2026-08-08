"""Tests for sentinel/security/remediation.py:build_mitigation()."""
from sentinel.security.remediation import build_mitigation


class TestBuildMitigation:
    def test_unknown_alert_type_returns_none(self):
        assert build_mitigation('SOME_UNKNOWN_TYPE', {}) is None

    def test_none_raw_data_does_not_raise(self):
        # ARP_SPOOF's builder reads several raw_data keys — must degrade to
        # its fallback wording, not crash, when raw_data is None entirely.
        assert build_mitigation('ARP_SPOOF', None) is not None

    def test_high_risk_port_opened_uses_specific_port_advice(self):
        text = build_mitigation('HIGH_RISK_PORT_OPENED', {'port': 23, 'service': 'Telnet'})
        assert 'telnet' in text.lower()
        assert 'never forward this port' in text.lower()

    def test_high_risk_port_opened_falls_back_for_unlisted_port(self):
        text = build_mitigation('HIGH_RISK_PORT_OPENED', {'port': 9999, 'service': 'Mystery'})
        assert text is not None
        assert 'never forward this port' in text.lower()

    def test_vulnerability_detected_names_the_findings(self):
        text = build_mitigation('VULNERABILITY_DETECTED', {'findings': {'some-vuln-script': 'output'}})
        assert 'some-vuln-script' in text

    def test_credential_exposure_names_the_findings(self):
        text = build_mitigation('CREDENTIAL_EXPOSURE_DETECTED', {'findings': {'default-accounts': 'output'}})
        assert 'default-accounts' in text
        assert 'password' in text.lower()

    def test_arp_spoof_names_both_macs(self):
        text = build_mitigation(
            'ARP_SPOOF', {'ip': '10.0.0.5', 'old_mac': 'aa:aa:aa:aa:aa:aa', 'new_mac': 'bb:bb:bb:bb:bb:bb'}
        )
        assert 'aa:aa:aa:aa:aa:aa' in text
        assert 'bb:bb:bb:bb:bb:bb' in text

    def test_rogue_dhcp_names_the_server_ip(self):
        text = build_mitigation('ROGUE_DHCP_SERVER', {'ip': '10.0.0.99'})
        assert '10.0.0.99' in text

    def test_fingerprint_mismatch_names_both_os_guesses(self):
        text = build_mitigation('FINGERPRINT_MISMATCH', {'previous_os': 'Linux', 'new_os': 'Windows'})
        assert 'Linux' in text
        assert 'Windows' in text

    def test_os_fingerprint_conflict_names_both_os_guesses(self):
        text = build_mitigation('OS_FINGERPRINT_CONFLICT', {'passive_os': 'macOS', 'active_os': 'Windows'})
        assert 'macOS' in text
        assert 'Windows' in text

    def test_honeypot_access_names_the_service(self):
        text = build_mitigation('HONEYPOT_ACCESS', {'logdata': {'SERVICE': 'telnet'}})
        assert 'telnet' in text

    def test_malformed_raw_data_shape_does_not_raise(self):
        """findings/logdata as the wrong type entirely — must degrade to
        None, never propagate an exception into the caller's poll loop."""
        assert build_mitigation('VULNERABILITY_DETECTED', {'findings': 'not-a-dict'}) is None
        assert build_mitigation('HONEYPOT_ACCESS', {'logdata': 'not-a-dict'}) is None
