# Wire up ClamAV + build the Zeek log parser for real

*Recovered from the plan-mode scratch file (`~/.claude/plans/i-would-like-you-delightful-origami.md`),
which gets overwritten by whatever plan is written there next — this is
the second time that's happened this session (see `docs/capability-review.md`'s
own recovery note). Saved here so it survives future planning rounds.*

## Context

The whole-app capability review (previous session) found that Zeek and
ClamAV sit at opposite ends of the same gap: `sentinel/security/
clamav_scanner.py` is a fully correct, complete integration with **zero
callers**, while the Zeek log parser described in `docs/architecture/
06-security-services.md` was never actually built — no file, no container.
Closing both together is the natural move: Zeek is ClamAV's missing file
source, and adding it also finally activates two other pieces of code that
already exist but do nothing today:

- `sentinel/db/migrations/versions/d57a12ca025d_initial_schema.py` already
  created a `dns_queries` hypertable (`time, device_mac, query, blocked,
  list_name`) on day one — completely unused since.
- `ThreatIntelService.is_domain_malicious()` (`sentinel/security/
  threat_intel.py`) is fully coded (backed by the URLhaus feed already
  refreshed nightly) — nothing has ever called it.
- `GET /api/threats/dns-stats` (`sentinel/api/routes/threats.py`) explicitly
  returns HTTP 501 — "no DNS query source is configured."

User confirmed scope: build all three Zeek-unlocked capabilities (DNS/
malicious-domain alerting + the dns-stats endpoint, conn.log beaconing
detection, file-extraction feeding ClamAV), with a **curated** file-
extraction policy (executables/archives/generic downloads only, not every
image/video/web asset Zeek sees) to keep disk and CPU cost reasonable on a
home-network box.

**Honest caveat**: unlike the router work earlier this engagement, there's
no live Zeek instance available in this session to verify real log output
against. The design below follows Zeek's well-documented standard log
schema (`id.orig_h`/`id.resp_h`/`ts`/`query`/`qtype_name` etc., matching the
field names already used in the docs' own `detect_beaconing()` sketch), but
the first real integration test should be watching actual `dns.log`/
`conn.log` output after `docker compose up zeek` to confirm field names and
JSON shape before trusting the parser in production.

*(That verification did happen later the same session, against a real
`zeek/zeek:latest` container running Zeek 8.2.1 — dns.log/conn.log matched
this plan's assumptions exactly, but files.log did not: it turned out to
use a different, newer schema than assumed below (`id.orig_h`/`id.resp_h`/
`is_orig` per-connection entries, not the `tx_hosts`/`rx_hosts` sets this
plan describes — that schema was replaced in Zeek v5.1). The final,
corrected version of that logic lives in `sentinel/security/
zeek_parser.py`'s `ZeekFileExtractionWatcher._load_fuid_to_source_ip` and
is documented in `docs/architecture/09-docker-compose.md`'s "Zeek
configuration" section — this file is kept as the historical plan record,
not the current design reference for that one piece.)*

---

## Reused code — do not rebuild these patterns

- **`sentinel/security/canary.py` + its scheduler wiring** is the exact
  template for incremental log-tailing of discrete events (DNS queries):
  `OpenCanaryLogReader` (byte-offset tracking), `OpenCanaryIngester`
  (JSON-line → `Alert`), and in `sentinel/scheduler/scheduler.py`: instance
  construction (~L162-163), the `canary_poll` interval job (~L200-205), the
  poll job + persist method (~L355-368), and the health snapshot fields
  (~L586-587). Zeek's DNS ingestion mirrors this shape.
- **`docs/architecture/06-security-services.md`'s `detect_beaconing()`**
  sketch (pandas groupby on `(id.orig_h, id.resp_h)`, interval stddev) —
  reuse near-verbatim for the beaconing detector.
- **`SentinelScheduler._raise_threat_alert()`** (already built for ARP
  spoofing / fingerprint mismatch / nmap findings) is the single place
  "attack identified → alert (+ maybe auto-block)" flows through — DNS
  malicious-domain hits, beaconing, and malware detections should all go
  through it too, not build a parallel alerting path.
- **`sentinel/db/models.py`'s `TrafficSample`** — the composite
  `time`+`mac_address` primary-key, no-DB-constraint pattern for a
  TimescaleDB hypertable — mirror this exactly for the new `DnsQuery` model.
- **`docker-compose.yml`'s `opencanary`/`suricata` services** — the pattern
  for a security-tool container with a mounted config file + a named log
  volume shared read-only into `sentinel-backend`.
- **`tests/test_security/test_canary.py`** — the test structure to mirror
  for the new ingester/reader tests.

---

## Implementation

### 1. Docker Compose (`docker-compose.yml`, `docs/architecture/09-docker-compose.md`)
Add a `zeek` service: official `zeek/zeek` image, `network_mode: host`,
`cap_add: [NET_ADMIN, NET_RAW]` (same as `suricata`), mounts a new
`./zeek/local.zeek` config read-only and writes to two new named volumes:
`zeek-logs` (JSON logs) and `zeek-extracted` (extracted files). Command runs
zeek on `${SNIFF_IFACE}` with the local script loaded. Mount `zeek-logs`
read-only into `sentinel-backend` at `/var/log/zeek/current` (matches the
docs' `ZEEK_LOG_DIR` constant) and `zeek-extracted` read-only at
`/var/zeek/extracted`. Add both to the top-level `volumes:` block. Update
`09-docker-compose.md` to match, same as it already documents `opencanary`/
`suricata`.

### 2. New `./zeek/local.zeek` config
`redef LogAscii::use_json = T;` for JSON logs (matches the docs). Plus a
curated file-extraction policy: a `file_sniff` event handler that checks
`f$info$mime_type` against the curated set (`application/x-dosexec`,
`application/x-executable`, `application/zip`, `application/x-rar-
compressed`, `application/x-7z-compressed`, `application/octet-stream`)
before calling `Files::add_analyzer(f, Files::ANALYZER_EXTRACT, ...)`,
writing into `/var/zeek/extracted/`.

### 3. Config (`sentinel/config.py`)
Add, alongside the existing `OPENCANARY_LOG_PATH`/`CANARY_POLL_INTERVAL_SECONDS`:
`ZEEK_LOG_DIR`, `ZEEK_EXTRACT_DIR`, `ZEEK_DNS_POLL_INTERVAL_SECONDS` (default
10s, matches canary), `ZEEK_BEACON_SCAN_INTERVAL_SECONDS` (default 300s —
beaconing needs a window of history, not per-line reaction),
`CLAMAV_HOST`/`CLAMAV_PORT` (parameterize `ClamAvScanner`'s currently-
hardcoded `localhost:3310` for consistency, defaults unchanged).

### 4. `sentinel/security/zeek_parser.py` (new file)
Three pieces, two patterns:
- **`ZeekDnsLogReader` + `ZeekDnsIngester`** — mirrors `OpenCanaryLogReader`/
  `OpenCanaryIngester` exactly (offset-tracked tailing, JSON-line parsing).
  One addition OpenCanary doesn't need: a truncation-safety check (if file
  size < stored offset, reset to 0) since Zeek rotates `dns.log` hourly by
  default and OpenCanary's log doesn't rotate the same way.
- **`ZeekConnBeaconDetector`** — periodic, not incremental: re-reads the
  current `conn.log` fresh via `pd.read_json(path, lines=True)` each run,
  runs the groupby/interval-stddev logic from the docs' sketch, returns
  suspicious `(src, dst, count, interval stats)` dicts.
- **`ZeekFileExtractionWatcher`** — polls `ZEEK_EXTRACT_DIR`, cross-
  references each extracted filename against `files.log` (`tx_hosts`/
  `rx_hosts` fields, matched by Zeek's file UID embedded in the extracted
  filename) to attribute a file back to a source device IP, reads the
  bytes, and deletes the file after scanning regardless of outcome (no
  in-memory "seen" set needed — scan-then-delete avoids both re-scanning
  and unbounded disk growth).

  *(Superseded — see the caveat above: this ended up using
  `id.orig_h`/`id.resp_h`/`is_orig`, not `tx_hosts`/`rx_hosts`.)*

### 5. `sentinel/db/models.py`
New `DnsQuery` model mapping the **already-existing** `dns_queries`
hypertable (no migration needed — verify the table is present in both
`sentinel` and `sentinel_test` during implementation, since it's been
unused since the very first migration): `time` + `device_mac` composite
identity (mirroring `TrafficSample`), `query`, `blocked`, `list_name`.

### 6. Scheduler wiring (`sentinel/scheduler/scheduler.py`)
Mirrors the canary block precisely: constructor params, instance
construction in `_run_loop`, three new APScheduler jobs (`zeek_dns_poll`,
`zeek_beacon_scan`, `zeek_file_scan`), and job bodies:
- **DNS poll**: tail new lines → resolve `device_mac` from source IP (reuse
  the exact lookup pattern `_persist_canary_alert` already uses) → check
  `threat_intel.is_domain_malicious(query)` → insert a `DnsQuery` row
  (`blocked`/`list_name` set accordingly) → if malicious, also call
  `_raise_threat_alert(mac, 'DNS_MALICIOUS_QUERY', 'CRITICAL', ...)`.
- **Beacon scan**: run the detector, resolve device per suspicious pair,
  `_raise_threat_alert(mac, 'C2_BEACONING', 'CRITICAL', ...)`.
- **File scan**: for each extracted file, `await clamav.scan_bytes(data)`;
  if infected, `_raise_threat_alert(mac, 'MALWARE_DETECTED', 'CRITICAL', ...)`.

Extend `security_services_snapshot()` with Zeek DNS/beacon last-check
timestamps and ClamAV reachability (via `clamav.ping()`, thread-bridged like
other health checks). Thread new settings through `init_scheduler()` the
same way `opencanary_log_path`/`canary_poll_interval_s` already are.

### 7. `sentinel/api/routes/threats.py`
Replace the 501 stub: aggregate `dns_queries` (last 24h) — total queries,
blocked count, top blocked domains/list_names — mirroring the aggregation-
query style already used in `alerts/grouped` (`sentinel/api/routes/alerts.py`).

### 8. Frontend
`ServiceStatusPanel.jsx` currently has a comment stating Zeek/ClamAV rows
are deliberately absent "since nothing in the backend reports their
status" — add "Zeek DNS", "Zeek Beaconing", "ClamAV" rows using the new
health fields (same `Row` component, no new pattern) and remove the stale
comment.

### 9. Dependencies
None new — `pandas` and `pyclamd` are already in `requirements.txt`
(currently unused, per the earlier survey). The Zeek image is pulled at
`docker compose up` time.

---

## Verification
- `docker compose up zeek clamav` (or full stack) — confirm Zeek actually
  writes JSON `dns.log`/`conn.log` to the mounted volume and the extraction
  policy drops files into `zeek-extracted` for a real download of a curated
  MIME type. **Do this early** — it's the one part of this plan not
  verifiable from within this session.
- New unit tests mirroring `tests/test_security/test_canary.py`:
  `ZeekDnsIngester`/`ZeekDnsLogReader` (including the truncation-reset
  case), `ZeekConnBeaconDetector` against a synthetic conn.log DataFrame,
  `ZeekFileExtractionWatcher` against a tmp_path directory.
- Scheduler-level tests following `tests/test_scheduler/test_threat_auto_block.py`'s
  `object.__new__(SentinelScheduler)` pattern to exercise the three new job
  methods in isolation without a full scheduler thread.
- `GET /api/threats/dns-stats` — seed a few `DnsQuery` rows, confirm real
  counts instead of 501.
- Full `pytest tests/` against the isolated `sentinel_test` DB (same
  convention used all session — never the live `sentinel` DB).
- Manual: once the real Zeek/ClamAV containers are up, confirm
  `ServiceStatusPanel` rows go ACTIVE and a real DNS query against a known
  URLhaus-listed domain produces a `DNS_MALICIOUS_QUERY` alert end-to-end.

**Status: fully implemented and verified this session** — see
`sentinel/security/zeek_parser.py`, `sentinel/scheduler/scheduler.py`'s
`_zeek_dns_poll_job`/`_zeek_beacon_scan_job`/`_zeek_file_scan_job`,
`docs/architecture/09-docker-compose.md`'s "Zeek configuration" section,
and `docs/capability-review.md`'s items #1/#2 (marked done).
