import json

from sentinel.security.canary import OpenCanaryIngester, OpenCanaryLogReader


def _event(logtype: int = 1000, **overrides) -> str:
    payload = {
        'logtype': logtype,
        'src_host': '10.100.102.50',
        'dst_host': '10.100.102.5',
        'logdata': {'SERVICE': 'ftp'},
    }
    payload.update(overrides)
    return json.dumps(payload)


class TestParseEvent:
    def test_interaction_event_produces_alert(self):
        ingester = OpenCanaryIngester()
        alert = ingester.parse_event(_event(logtype=1000))
        assert alert is not None
        assert alert.alert_type == 'HONEYPOT_ACCESS'
        assert alert.severity == 'CRITICAL'
        assert '10.100.102.50' in alert.description
        assert 'ftp' in alert.description

    def test_non_interaction_logtype_ignored(self):
        ingester = OpenCanaryIngester()
        alert = ingester.parse_event(_event(logtype=9999))
        assert alert is None

    def test_malformed_json_ignored(self):
        ingester = OpenCanaryIngester()
        assert ingester.parse_event('not json at all {{{') is None

    def test_missing_fields_use_defaults(self):
        ingester = OpenCanaryIngester()
        alert = ingester.parse_event(json.dumps({'logtype': 2000}))
        assert alert is not None
        assert 'unknown' in alert.description

    def test_raw_event_preserved_in_raw_data(self):
        ingester = OpenCanaryIngester()
        alert = ingester.parse_event(_event(logtype=3000))
        assert alert.raw_data['logtype'] == 3000


class TestOpenCanaryLogReader:
    def test_missing_file_returns_empty(self, tmp_path):
        reader = OpenCanaryLogReader(str(tmp_path / 'does-not-exist.log'))
        assert reader.read_new_lines() == []

    def test_reads_lines_written_so_far(self, tmp_path):
        log_path = tmp_path / 'opencanary.log'
        log_path.write_text(_event() + '\n')

        reader = OpenCanaryLogReader(str(log_path))
        lines = reader.read_new_lines()
        assert len(lines) == 1

    def test_second_read_only_returns_new_lines(self, tmp_path):
        log_path = tmp_path / 'opencanary.log'
        log_path.write_text(_event() + '\n')

        reader = OpenCanaryLogReader(str(log_path))
        reader.read_new_lines()  # consume the first line

        with open(log_path, 'a') as f:
            f.write(_event(logtype=2000) + '\n')

        second = reader.read_new_lines()
        assert len(second) == 1
        assert json.loads(second[0])['logtype'] == 2000

    def test_blank_lines_are_filtered(self, tmp_path):
        log_path = tmp_path / 'opencanary.log'
        log_path.write_text(_event() + '\n\n\n')

        reader = OpenCanaryLogReader(str(log_path))
        assert len(reader.read_new_lines()) == 1
