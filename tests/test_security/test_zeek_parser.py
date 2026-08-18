import json
from datetime import datetime, timezone

from sentinel.security.zeek_parser import (
    ZeekConnBeaconDetector,
    ZeekConnVolumeCorrelator,
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


def _conn_row_full(src: str, dst: str, ts: float, orig_bytes: int = 100, resp_bytes: int = 100) -> dict:
    row = {'id.orig_h': src, 'id.resp_h': dst, 'ts': ts}
    if orig_bytes is not None:
        row['orig_bytes'] = orig_bytes
    if resp_bytes is not None:
        row['resp_bytes'] = resp_bytes
    return row


def _dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


class TestZeekConnVolumeCorrelator:
    def test_missing_file_returns_empty(self, tmp_path):
        correlator = ZeekConnVolumeCorrelator(str(tmp_path))
        result = correlator.top_talkers(local_ips={'10.100.102.50'}, since=_dt(0), until=_dt(1000))
        assert result == []

    def test_finds_top_talker_by_total_bytes(self, tmp_path):
        log_path = tmp_path / 'conn.log'
        rows = [
            _conn_row_full('10.100.102.50', '203.0.113.10', ts=100, orig_bytes=500, resp_bytes=500),
            _conn_row_full('10.100.102.50', '198.51.100.20', ts=110, orig_bytes=10, resp_bytes=10),
        ]
        log_path.write_text('\n'.join(json.dumps(r) for r in rows) + '\n')

        correlator = ZeekConnVolumeCorrelator(str(tmp_path))
        talkers = correlator.top_talkers(local_ips={'10.100.102.50'}, since=_dt(0), until=_dt(1000))

        assert len(talkers) == 2
        assert talkers[0].remote_ip == '203.0.113.10'
        assert talkers[0].local_ip == '10.100.102.50'
        assert talkers[0].total_bytes == 1000
        assert talkers[0].connection_count == 1

    def test_direction_inference_when_local_is_responder(self, tmp_path):
        log_path = tmp_path / 'conn.log'
        row = _conn_row_full('203.0.113.10', '10.100.102.50', ts=100, orig_bytes=300, resp_bytes=200)
        log_path.write_text(json.dumps(row) + '\n')

        correlator = ZeekConnVolumeCorrelator(str(tmp_path))
        talkers = correlator.top_talkers(local_ips={'10.100.102.50'}, since=_dt(0), until=_dt(1000))

        assert len(talkers) == 1
        assert talkers[0].local_ip == '10.100.102.50'
        assert talkers[0].remote_ip == '203.0.113.10'
        assert talkers[0].total_bytes == 500

    def test_both_local_and_neither_local_are_excluded(self, tmp_path):
        log_path = tmp_path / 'conn.log'
        rows = [
            _conn_row_full('10.100.102.50', '10.100.102.51', ts=100),  # both local
            _conn_row_full('203.0.113.10', '198.51.100.20', ts=110),   # neither local
        ]
        log_path.write_text('\n'.join(json.dumps(r) for r in rows) + '\n')

        correlator = ZeekConnVolumeCorrelator(str(tmp_path))
        talkers = correlator.top_talkers(
            local_ips={'10.100.102.50', '10.100.102.51'}, since=_dt(0), until=_dt(1000),
        )
        assert talkers == []

    def test_window_filtering_excludes_rows_outside_range(self, tmp_path):
        log_path = tmp_path / 'conn.log'
        rows = [
            _conn_row_full('10.100.102.50', '203.0.113.10', ts=50, orig_bytes=999, resp_bytes=999),  # before window
            _conn_row_full('10.100.102.50', '203.0.113.10', ts=500, orig_bytes=10, resp_bytes=10),   # inside
            _conn_row_full('10.100.102.50', '203.0.113.10', ts=5000, orig_bytes=999, resp_bytes=999),  # after
        ]
        log_path.write_text('\n'.join(json.dumps(r) for r in rows) + '\n')

        correlator = ZeekConnVolumeCorrelator(str(tmp_path))
        talkers = correlator.top_talkers(local_ips={'10.100.102.50'}, since=_dt(100), until=_dt(1000))

        assert len(talkers) == 1
        assert talkers[0].total_bytes == 20
        assert talkers[0].connection_count == 1

    def test_top_n_truncation(self, tmp_path):
        log_path = tmp_path / 'conn.log'
        rows = [
            _conn_row_full('10.100.102.50', f'203.0.113.{i}', ts=100 + i, orig_bytes=i * 10, resp_bytes=0)
            for i in range(1, 6)
        ]
        log_path.write_text('\n'.join(json.dumps(r) for r in rows) + '\n')

        correlator = ZeekConnVolumeCorrelator(str(tmp_path))
        talkers = correlator.top_talkers(local_ips={'10.100.102.50'}, since=_dt(0), until=_dt(1000), top_n=2)

        assert len(talkers) == 2
        assert talkers[0].remote_ip == '203.0.113.5'
        assert talkers[1].remote_ip == '203.0.113.4'

    def test_missing_byte_fields_default_to_zero(self, tmp_path):
        log_path = tmp_path / 'conn.log'
        row = {'id.orig_h': '10.100.102.50', 'id.resp_h': '203.0.113.10', 'ts': 100}  # no orig_bytes/resp_bytes
        log_path.write_text(json.dumps(row) + '\n')

        correlator = ZeekConnVolumeCorrelator(str(tmp_path))
        talkers = correlator.top_talkers(local_ips={'10.100.102.50'}, since=_dt(0), until=_dt(1000))

        assert len(talkers) == 1
        assert talkers[0].total_bytes == 0

    def test_tail_read_excludes_lines_beyond_tail_bytes(self, tmp_path):
        log_path = tmp_path / 'conn.log'
        # Old row, far enough back it'll fall outside a tiny tail_bytes window.
        old_row = _conn_row_full('10.100.102.50', '203.0.113.10', ts=100, orig_bytes=999, resp_bytes=999)
        padding = '\n'.join(json.dumps(_conn_row_full('10.100.102.99', '10.100.102.98', ts=200 + i)) for i in range(200))
        new_row = _conn_row_full('10.100.102.50', '198.51.100.20', ts=900, orig_bytes=5, resp_bytes=5)
        log_path.write_text(json.dumps(old_row) + '\n' + padding + '\n' + json.dumps(new_row) + '\n')

        correlator = ZeekConnVolumeCorrelator(str(tmp_path), tail_bytes=200)
        talkers = correlator.top_talkers(local_ips={'10.100.102.50'}, since=_dt(0), until=_dt(1000))

        # Only the tail-resident new_row should survive — the old_row (with
        # its much larger byte count) must be excluded by the tail read, not
        # just outrank on total_bytes.
        assert all(t.remote_ip != '203.0.113.10' for t in talkers)


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
