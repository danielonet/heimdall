import json

from sentinel.security.suricata_parser import SuricataAlertIngester, SuricataEveLogReader


def _alert_event(**overrides) -> str:
    payload = {
        'event_type': 'alert',
        'src_ip': '10.100.102.50',
        'dest_ip': '1.2.3.4',
        'alert': {
            'signature': 'ET MALWARE Generic Trojan Callout Detected',
            'category': 'A Network Trojan was detected',
            'severity': 1,
        },
    }
    payload.update(overrides)
    return json.dumps(payload)


class TestSuricataAlertIngester:
    def test_parses_alert_fields(self):
        ingester = SuricataAlertIngester()
        result = ingester.parse_event(_alert_event())
        assert result == {
            'src_ip': '10.100.102.50',
            'dest_ip': '1.2.3.4',
            'signature': 'ET MALWARE Generic Trojan Callout Detected',
            'category': 'A Network Trojan was detected',
            'severity': 'CRITICAL',
        }

    def test_malformed_json_ignored(self):
        ingester = SuricataAlertIngester()
        assert ingester.parse_event('not json at all {{{') is None

    def test_non_alert_event_type_ignored(self):
        ingester = SuricataAlertIngester()
        for event_type in ('dns', 'http', 'tls', 'flow', 'stats'):
            assert ingester.parse_event(_alert_event(event_type=event_type)) is None

    def test_missing_src_ip_ignored(self):
        ingester = SuricataAlertIngester()
        assert ingester.parse_event(_alert_event(src_ip=None)) is None

    def test_missing_signature_ignored(self):
        ingester = SuricataAlertIngester()
        assert ingester.parse_event(_alert_event(alert={'category': 'x', 'severity': 1})) is None

    def test_missing_category_defaults_to_unknown(self):
        ingester = SuricataAlertIngester()
        result = ingester.parse_event(_alert_event(alert={'signature': 'Test Sig', 'severity': 1}))
        assert result['category'] == 'unknown'

    def test_severity_1_maps_to_critical(self):
        ingester = SuricataAlertIngester()
        result = ingester.parse_event(_alert_event(alert={'signature': 'x', 'severity': 1}))
        assert result['severity'] == 'CRITICAL'

    def test_severity_2_maps_to_warning(self):
        ingester = SuricataAlertIngester()
        result = ingester.parse_event(_alert_event(alert={'signature': 'x', 'severity': 2}))
        assert result['severity'] == 'WARNING'

    def test_severity_3_maps_to_info(self):
        ingester = SuricataAlertIngester()
        result = ingester.parse_event(_alert_event(alert={'signature': 'x', 'severity': 3}))
        assert result['severity'] == 'INFO'

    def test_missing_severity_defaults_to_warning(self):
        ingester = SuricataAlertIngester()
        result = ingester.parse_event(_alert_event(alert={'signature': 'x'}))
        assert result['severity'] == 'WARNING'

    def test_unrecognized_severity_defaults_to_warning(self):
        ingester = SuricataAlertIngester()
        result = ingester.parse_event(_alert_event(alert={'signature': 'x', 'severity': 99}))
        assert result['severity'] == 'WARNING'


class TestSuricataEveLogReader:
    def test_missing_file_returns_empty(self, tmp_path):
        reader = SuricataEveLogReader(str(tmp_path / 'does-not-exist.json'))
        assert reader.read_new_lines() == []

    def test_reads_lines_written_so_far(self, tmp_path):
        log_path = tmp_path / 'eve.json'
        log_path.write_text(_alert_event() + '\n')

        reader = SuricataEveLogReader(str(log_path))
        assert len(reader.read_new_lines()) == 1

    def test_second_read_only_returns_new_lines(self, tmp_path):
        log_path = tmp_path / 'eve.json'
        log_path.write_text(_alert_event() + '\n')

        reader = SuricataEveLogReader(str(log_path))
        reader.read_new_lines()  # consume the first line

        with open(log_path, 'a') as f:
            f.write(_alert_event(src_ip='10.100.102.99') + '\n')

        second = reader.read_new_lines()
        assert len(second) == 1
        assert json.loads(second[0])['src_ip'] == '10.100.102.99'

    def test_blank_lines_are_filtered(self, tmp_path):
        log_path = tmp_path / 'eve.json'
        log_path.write_text(_alert_event() + '\n\n\n')

        reader = SuricataEveLogReader(str(log_path))
        assert len(reader.read_new_lines()) == 1

    def test_truncated_file_resets_offset_instead_of_skipping_or_raising(self, tmp_path):
        """A container restart can recreate eve.json smaller than the last
        tracked offset — must be treated as a fresh file, not silently skip
        real lines or raise from seeking past EOF (same guard as
        ZeekDnsLogReader)."""
        log_path = tmp_path / 'eve.json'
        log_path.write_text(_alert_event() + '\n' + _alert_event(src_ip='10.100.102.51') + '\n')

        reader = SuricataEveLogReader(str(log_path))
        reader.read_new_lines()  # offset now points past both lines

        log_path.write_text(_alert_event(src_ip='10.100.102.52') + '\n')  # shorter than before

        lines = reader.read_new_lines()
        assert len(lines) == 1
        assert json.loads(lines[0])['src_ip'] == '10.100.102.52'
