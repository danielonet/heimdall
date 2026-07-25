"""Parses Zeek's JSON logs (dns.log, conn.log, files.log) for three distinct
capabilities — see docs/architecture/06-security-services.md and zeek/local.zeek:

- DNS query visibility: tail dns.log incrementally, same shape as
  OpenCanaryIngester (see sentinel/security/canary.py) — each line is a
  discrete, immediately-actionable event.
- C2 beaconing detection: re-read conn.log fresh on a periodic schedule and
  look for suspiciously regular connection intervals. Batch, not
  incremental — beaconing is a property of a *window* of connections, not
  a single new line.
- File-extraction handoff to ClamAV: poll the extraction directory Zeek's
  file-analysis framework writes to, cross-referencing files.log to
  attribute each file back to the device that downloaded it.

Verified against a live zeek/zeek:latest container (Zeek 8.2.1, 2026-07-24):
dns.log/conn.log's id.orig_h/id.resp_h/ts/query field names match what's
used below exactly. files.log did not: it was originally written against
tx_hosts/rx_hosts (a schema Zeek replaced in v5.1 with one files.log entry
per connection, sharing a fuid, using id.orig_h/id.resp_h/is_orig instead)
— see ZeekFileExtractionWatcher._load_fuid_to_source_ip for the fix.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)


class ZeekDnsLogReader:
    """Tracks read position in Zeek's dns.log across polls, so each call
    only returns lines written since the last one — same idea as
    OpenCanaryLogReader, plus one thing OpenCanary's log doesn't need: a
    truncation guard. If the file is ever smaller than our stored offset
    (a container restart recreating the log fresh, or a rotation behavior
    not yet confirmed against a live Zeek instance — see zeek/local.zeek),
    seeking to the old offset would skip real lines or raise; resetting to
    0 re-reads from the start instead.
    """

    def __init__(self, log_path: str) -> None:
        self._log_path = log_path
        self._offset = 0

    def read_new_lines(self) -> list[str]:
        """Return complete lines written since the last call. Empty list if
        the file doesn't exist yet (e.g. zeek hasn't logged a query yet)."""
        try:
            size = os.path.getsize(self._log_path)
        except OSError:
            return []

        if size < self._offset:
            logger.warning(
                'dns.log is smaller than the last tracked offset (%d < %d) — '
                'treating it as a fresh file and re-reading from the start.',
                size, self._offset,
            )
            self._offset = 0

        try:
            with open(self._log_path) as f:
                f.seek(self._offset)
                lines = f.readlines()
                self._offset = f.tell()
        except OSError:
            return []
        return [line for line in lines if line.strip()]


class ZeekDnsIngester:
    """Converts Zeek dns.log JSON lines into (source_ip, query) pairs.

    Deliberately doesn't build Alert/DnsQuery rows itself — unlike
    OpenCanaryIngester, every DNS query needs a device_mac resolved (by
    source IP) and a malicious-domain check against ThreatIntelService
    before it's worth persisting, both of which need DB/service access this
    class doesn't have. See SentinelScheduler._zeek_dns_poll_job.
    """

    def parse_event(self, raw: str) -> Optional[tuple[str, str]]:
        """Parse one dns.log line. Returns (source_ip, query), or None for
        a malformed line or one missing the fields we need."""
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            return None

        source_ip = event.get('id.orig_h')
        query = event.get('query')
        if not source_ip or not query:
            return None
        return source_ip, query


class ZeekConnBeaconDetector:
    """Flags connections with suspiciously regular intervals (C2 beaconing)
    by re-reading Zeek's conn.log fresh each run. Per docs/architecture/
    06-security-services.md's design — reused near-verbatim here.
    """

    def __init__(
        self, log_dir: str, min_count: int = 10, jitter_tolerance_s: float = 2.0,
    ) -> None:
        self._log_path = Path(log_dir) / 'conn.log'
        self._min_count = min_count
        self._jitter_tolerance_s = jitter_tolerance_s

    def detect(self) -> list[dict]:
        """Returns a list of {src, dst, count, interval_mean_s, interval_std_s}
        dicts for (source, destination) pairs whose connection timing is
        suspiciously regular. Empty list if conn.log doesn't exist yet or
        has nothing to analyze."""
        try:
            df = pd.read_json(self._log_path, lines=True)
        except (ValueError, FileNotFoundError, OSError):
            return []

        if df.empty or 'id.orig_h' not in df.columns or 'id.resp_h' not in df.columns:
            return []

        suspicious = []
        for (src, dst), group in df.groupby(['id.orig_h', 'id.resp_h']):
            if len(group) < self._min_count:
                continue
            intervals = group['ts'].sort_values().diff().dropna()
            if len(intervals) < 2:
                continue  # can't compute a meaningful stddev from one interval
            if intervals.std() < self._jitter_tolerance_s:
                suspicious.append({
                    'src': src,
                    'dst': dst,
                    'count': len(group),
                    'interval_mean_s': round(intervals.mean(), 2),
                    'interval_std_s': round(intervals.std(), 2),
                })
        return suspicious


class ZeekFileExtractionWatcher:
    """Polls Zeek's file-extraction directory for newly-written files, reads
    their bytes for ClamAV scanning, and cross-references files.log (by
    Zeek's file UID, embedded in the extracted filename) to attribute each
    file back to the LAN device that downloaded it.

    Every file is read exactly once and deleted immediately after — no
    "already scanned" tracking needed, and it keeps the extraction
    directory from growing unbounded (an unbounded on-disk queue is a worse
    failure mode here than an unbounded in-memory dict — it can fill the
    disk, not just RAM).
    """

    def __init__(self, extract_dir: str, log_dir: str) -> None:
        self._extract_dir = Path(extract_dir)
        self._log_dir = Path(log_dir)

    def collect(self) -> list[tuple[str, bytes, Optional[str]]]:
        """Returns (filename, data, source_ip) for every file currently in
        the extraction directory. source_ip is None if it couldn't be
        matched against files.log (e.g. files.log hasn't been flushed yet,
        or an unrecognized filename format)."""
        try:
            entries = [e for e in os.scandir(self._extract_dir) if e.is_file()]
        except OSError:
            return []
        if not entries:
            return []

        fuid_to_ip = self._load_fuid_to_source_ip()

        results: list[tuple[str, bytes, Optional[str]]] = []
        for entry in entries:
            try:
                with open(entry.path, 'rb') as f:
                    data = f.read()
            except OSError:
                continue
            finally:
                try:
                    os.remove(entry.path)
                except OSError:
                    logger.warning('Failed to remove scanned extracted file %s', entry.path)

            fuid = self._extract_fuid(entry.name)
            source_ip = fuid_to_ip.get(fuid) if fuid else None
            results.append((entry.name, data, source_ip))
        return results

    @staticmethod
    def _extract_fuid(filename: str) -> Optional[str]:
        """Zeek's file-extraction analyzer names files like
        'extract-<timestamp>-<source>-<fuid>' — the fuid is always the last
        '-'-separated segment."""
        if '-' not in filename:
            return None
        return filename.rsplit('-', 1)[-1]

    def _load_fuid_to_source_ip(self) -> dict[str, str]:
        """Derives the receiving (i.e. LAN-side downloading) endpoint from
        files.log's per-connection id.orig_h/id.resp_h + is_orig fields.

        Originally written against tx_hosts/rx_hosts, a files.log schema
        that Zeek replaced in v5.1 with one entry per connection sharing a
        fuid — confirmed missing (both fields simply absent) against a live
        Zeek 8.2.1 container. is_orig=True means the file was sent BY the
        connection's originator (id.orig_h), so the *receiver* is
        id.resp_h; is_orig=False means the responder sent it (e.g. a normal
        web download, server -> client), so the receiver is id.orig_h.
        """
        path = self._log_dir / 'files.log'
        mapping: dict[str, str] = {}
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    fuid = entry.get('fuid')
                    orig_h = entry.get('id.orig_h')
                    resp_h = entry.get('id.resp_h')
                    is_orig = entry.get('is_orig')
                    if fuid is None or is_orig is None or orig_h is None or resp_h is None:
                        continue
                    mapping[fuid] = resp_h if is_orig else orig_h
        except OSError:
            pass
        return mapping
