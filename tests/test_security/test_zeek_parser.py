import json

from sentinel.security.zeek_parser import (
    ZeekConnBeaconDetector,
    ZeekDnsIngester,
    ZeekDnsLogReader,
    ZeekFileExtractionWatcher,
)


def _dns_event(**overrides) -> str:
    payload = {'id.orig_h': '10.100.102.50', 'id.resp_h': '10.100.102.1', 'query': 'example.com'}
    payload.update(overrides)
    return json.dumps(payload)


class TestZeekDnsIngester:
    def test_parses_source_ip_and_query(self):
        ingester = ZeekDnsIngester()
        result = ingester.parse_event(_dns_event())
        assert result == ('10.100.102.50', 'example.com')

    def test_malformed_json_ignored(self):
        ingester = ZeekDnsIngester()
        assert ingester.parse_event('not json at all {{{') is None

    def test_missing_source_ip_ignored(self):
        ingester = ZeekDnsIngester()
        assert ingester.parse_event(json.dumps({'query': 'example.com'})) is None

    def test_missing_query_ignored(self):
        ingester = ZeekDnsIngester()
        assert ingester.parse_event(json.dumps({'id.orig_h': '10.100.102.50'})) is None


class TestZeekDnsLogReader:
    def test_missing_file_returns_empty(self, tmp_path):
        reader = ZeekDnsLogReader(str(tmp_path / 'does-not-exist.log'))
        assert reader.read_new_lines() == []

    def test_reads_lines_written_so_far(self, tmp_path):
        log_path = tmp_path / 'dns.log'
        log_path.write_text(_dns_event() + '\n')

        reader = ZeekDnsLogReader(str(log_path))
        assert len(reader.read_new_lines()) == 1

    def test_second_read_only_returns_new_lines(self, tmp_path):
        log_path = tmp_path / 'dns.log'
        log_path.write_text(_dns_event() + '\n')

        reader = ZeekDnsLogReader(str(log_path))
        reader.read_new_lines()  # consume the first line

        with open(log_path, 'a') as f:
            f.write(_dns_event(query='second.com') + '\n')

        second = reader.read_new_lines()
        assert len(second) == 1
        assert json.loads(second[0])['query'] == 'second.com'

    def test_blank_lines_are_filtered(self, tmp_path):
        log_path = tmp_path / 'dns.log'
        log_path.write_text(_dns_event() + '\n\n\n')

        reader = ZeekDnsLogReader(str(log_path))
        assert len(reader.read_new_lines()) == 1

    def test_truncated_file_resets_offset_instead_of_skipping_or_raising(self, tmp_path):
        """A container restart (or any rotation not yet confirmed against a
        live Zeek instance — see zeek/local.zeek) can recreate dns.log
        smaller than the last tracked offset. That must be treated as a
        fresh file, not silently skip real lines or raise from seeking past
        EOF."""
        log_path = tmp_path / 'dns.log'
        log_path.write_text(_dns_event() + '\n' + _dns_event(query='two.com') + '\n')

        reader = ZeekDnsLogReader(str(log_path))
        reader.read_new_lines()  # offset now points past both lines

        log_path.write_text(_dns_event(query='fresh.com') + '\n')  # shorter than before

        lines = reader.read_new_lines()
        assert len(lines) == 1
        assert json.loads(lines[0])['query'] == 'fresh.com'


def _conn_row(src: str, dst: str, ts: float) -> dict:
    return {'id.orig_h': src, 'id.resp_h': dst, 'ts': ts}


class TestZeekConnBeaconDetector:
    def test_missing_file_returns_empty(self, tmp_path):
        detector = ZeekConnBeaconDetector(str(tmp_path))
        assert detector.detect() == []

    def test_regular_intervals_flagged_as_suspicious(self, tmp_path):
        log_path = tmp_path / 'conn.log'
        rows = [_conn_row('10.100.102.50', '203.0.113.10', ts=float(i * 60)) for i in range(12)]
        log_path.write_text('\n'.join(json.dumps(r) for r in rows) + '\n')

        detector = ZeekConnBeaconDetector(str(tmp_path), min_count=10, jitter_tolerance_s=2.0)
        results = detector.detect()

        assert len(results) == 1
        assert results[0]['src'] == '10.100.102.50'
        assert results[0]['dst'] == '203.0.113.10'
        assert results[0]['count'] == 12
        assert results[0]['interval_mean_s'] == 60.0

    def test_irregular_intervals_not_flagged(self, tmp_path):
        log_path = tmp_path / 'conn.log'
        offsets = [0, 5, 40, 41, 90, 300, 301, 700, 900, 950, 1400, 3000]
        rows = [_conn_row('10.100.102.50', '203.0.113.10', ts=float(o)) for o in offsets]
        log_path.write_text('\n'.join(json.dumps(r) for r in rows) + '\n')

        detector = ZeekConnBeaconDetector(str(tmp_path), min_count=10, jitter_tolerance_s=2.0)
        assert detector.detect() == []

    def test_below_min_count_not_flagged(self, tmp_path):
        log_path = tmp_path / 'conn.log'
        rows = [_conn_row('10.100.102.50', '203.0.113.10', ts=float(i * 60)) for i in range(5)]
        log_path.write_text('\n'.join(json.dumps(r) for r in rows) + '\n')

        detector = ZeekConnBeaconDetector(str(tmp_path), min_count=10, jitter_tolerance_s=2.0)
        assert detector.detect() == []


class TestZeekFileExtractionWatcher:
    def test_empty_dir_returns_empty(self, tmp_path):
        extract_dir = tmp_path / 'extracted'
        extract_dir.mkdir()
        log_dir = tmp_path / 'logs'
        log_dir.mkdir()

        watcher = ZeekFileExtractionWatcher(str(extract_dir), str(log_dir))
        assert watcher.collect() == []

    def test_collects_file_bytes_and_deletes_after(self, tmp_path):
        extract_dir = tmp_path / 'extracted'
        extract_dir.mkdir()
        log_dir = tmp_path / 'logs'
        log_dir.mkdir()

        extracted_file = extract_dir / 'extract-1700000000-10.100.102.50-Fabc123'
        extracted_file.write_bytes(b'suspicious payload bytes')

        watcher = ZeekFileExtractionWatcher(str(extract_dir), str(log_dir))
        results = watcher.collect()

        assert len(results) == 1
        filename, data, source_ip = results[0]
        assert filename == 'extract-1700000000-10.100.102.50-Fabc123'
        assert data == b'suspicious payload bytes'
        assert not extracted_file.exists()

    def test_attributes_downloaded_file_to_the_lan_client(self, tmp_path):
        """is_orig=False means the file was sent by the connection's
        responder (a normal download: remote server -> LAN client), so the
        receiving/downloading device is id.orig_h. See
        ZeekFileExtractionWatcher._load_fuid_to_source_ip."""
        extract_dir = tmp_path / 'extracted'
        extract_dir.mkdir()
        log_dir = tmp_path / 'logs'
        log_dir.mkdir()

        extracted_file = extract_dir / 'extract-1700000000-HTTP-Fabc123'
        extracted_file.write_bytes(b'data')
        (log_dir / 'files.log').write_text(json.dumps({
            'fuid': 'Fabc123',
            'id.orig_h': '10.100.102.50',
            'id.resp_h': '203.0.113.10',
            'is_orig': False,
        }) + '\n')

        watcher = ZeekFileExtractionWatcher(str(extract_dir), str(log_dir))
        results = watcher.collect()

        assert results[0][2] == '10.100.102.50'

    def test_attributes_uploaded_file_to_the_lan_client(self, tmp_path):
        """is_orig=True means the file was sent by the connection's
        originator (an upload: LAN client -> remote server), so the
        receiving device is id.resp_h."""
        extract_dir = tmp_path / 'extracted'
        extract_dir.mkdir()
        log_dir = tmp_path / 'logs'
        log_dir.mkdir()

        extracted_file = extract_dir / 'extract-1700000000-HTTP-Fxyz789'
        extracted_file.write_bytes(b'data')
        (log_dir / 'files.log').write_text(json.dumps({
            'fuid': 'Fxyz789',
            'id.orig_h': '10.100.102.50',
            'id.resp_h': '203.0.113.10',
            'is_orig': True,
        }) + '\n')

        watcher = ZeekFileExtractionWatcher(str(extract_dir), str(log_dir))
        results = watcher.collect()

        assert results[0][2] == '203.0.113.10'

    def test_unmatched_fuid_yields_none_source_ip(self, tmp_path):
        extract_dir = tmp_path / 'extracted'
        extract_dir.mkdir()
        log_dir = tmp_path / 'logs'
        log_dir.mkdir()

        extracted_file = extract_dir / 'extract-1700000000-x-Funknown'
        extracted_file.write_bytes(b'data')

        watcher = ZeekFileExtractionWatcher(str(extract_dir), str(log_dir))
        results = watcher.collect()

        assert results[0][2] is None
