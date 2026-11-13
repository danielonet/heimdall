"""Bounded reading of the append-only logs (sentinel/security/log_tail.py), and the readers built on it.

These logs are never rotated, so a reader that loads "everything from byte 0" grows with the file and is run
again, from byte 0, after every restart. Each test pins one way the read stays bounded.
"""
import json

from sentinel.security.canary import OpenCanaryLogReader
from sentinel.security.log_tail import read_new_lines
from sentinel.security.suricata_parser import SuricataEveLogReader
from sentinel.security.zeek_parser import ZeekDnsLogReader


def line(n: int) -> str:
    return json.dumps({'n': n}) + '\n'


class TestReadNewLines:
    def test_a_small_file_is_read_whole_and_then_only_what_is_new(self, tmp_path):
        p = tmp_path / 'log'
        p.write_text(line(1) + line(2))
        lines, offset = read_new_lines(str(p), 0)
        assert lines == [line(1), line(2)]
        p.write_text(line(1) + line(2) + line(3))
        lines, offset = read_new_lines(str(p), offset)
        assert lines == [line(3)]

    def test_missing_file_keeps_the_offset(self, tmp_path):
        assert read_new_lines(str(tmp_path / 'nope'), 42) == ([], 42)

    def test_a_file_that_shrank_is_read_again_from_the_start(self, tmp_path):
        p = tmp_path / 'log'
        p.write_text(line(1))
        lines, _ = read_new_lines(str(p), 10_000)
        assert lines == [line(1)]

    def test_a_huge_file_is_not_replayed_from_byte_zero(self, tmp_path):
        p = tmp_path / 'log'
        p.write_text(''.join(line(n) for n in range(1000)))
        lines, offset = read_new_lines(str(p), 0, first_read_backlog=500, max_bytes=10_000)
        assert 0 < len(lines) < 100
        assert lines[-1] == line(999)                       # the newest events are the ones kept
        assert all(json.loads(x)['n'] >= 900 for x in lines)    # and none of them is the cut-off partial line
        assert offset == p.stat().st_size

    def test_one_read_never_returns_more_than_max_bytes_and_the_rest_comes_next(self, tmp_path):
        p = tmp_path / 'log'
        p.write_text(''.join(line(n) for n in range(100)))
        got, offset = [], 0
        for _ in range(100):
            lines, offset = read_new_lines(str(p), offset, max_bytes=60)
            assert sum(len(x) for x in lines) <= 60
            got += lines
            if offset == p.stat().st_size:
                break
        assert got == [line(n) for n in range(100)]        # nothing lost, nothing repeated, every line whole

    def test_a_single_line_longer_than_the_limit_is_skipped_not_a_stall(self, tmp_path):
        p = tmp_path / 'log'
        p.write_text('x' * 500 + '\n' + line(1))
        got, offset = [], 0
        for _ in range(50):
            lines, offset = read_new_lines(str(p), offset, max_bytes=100)
            got += lines
            if offset == p.stat().st_size:
                break
        assert got[-1] == line(1) and offset == p.stat().st_size

    def test_an_unfinished_last_line_is_still_returned_as_before(self, tmp_path):
        p = tmp_path / 'log'
        p.write_text(line(1) + '{"n": 2')
        lines, _ = read_new_lines(str(p), 0)
        assert lines == [line(1), '{"n": 2']

    def test_invalid_utf8_does_not_raise(self, tmp_path):
        p = tmp_path / 'log'
        p.write_bytes(b'{"q": "\xff\xfe"}\n')
        lines, _ = read_new_lines(str(p), 0)
        assert len(lines) == 1


class TestReadersAreBounded:
    def test_every_reader_starts_near_the_end_of_a_huge_file(self, tmp_path, monkeypatch):
        import sentinel.security.log_tail as tail
        monkeypatch.setattr(tail, 'FIRST_READ_BACKLOG_BYTES', 400)
        monkeypatch.setattr(tail, 'MAX_READ_BYTES', 400)
        # the defaults are bound at definition time, so patch them on the function as well
        monkeypatch.setattr(tail.read_new_lines, '__kwdefaults__', {'max_bytes': 400, 'first_read_backlog': 400})
        for reader_class in (ZeekDnsLogReader, SuricataEveLogReader, OpenCanaryLogReader):
            p = tmp_path / reader_class.__name__
            p.write_text(''.join(line(n) for n in range(2000)))
            lines = reader_class(str(p)).read_new_lines()
            assert 0 < len(lines) < 50 and json.loads(lines[-1])['n'] == 1999
