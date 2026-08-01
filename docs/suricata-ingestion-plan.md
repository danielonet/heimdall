# Wire Suricata EVE JSON alerts into Heimdall

## Context

The `suricata` container has run in `docker-compose.yml` for a while — AF_PACKET
capture on `SNIFF_IFACE`, configured (`suricata/suricata.yaml`) to write
alert/DNS/HTTP/TLS/flow events to `/var/log/suricata/eve.json` — but nothing in
`sentinel/` reads that file. `docs/architecture/04-detection-pipeline.md`
already names the intended component (`SuricataAlertIngester`), and
`ServiceStatusPanel.jsx` has a comment explicitly noting there's no Suricata
row "since nothing in the backend reports their status." This wires it up,
following the exact same log-tailing pattern already built twice in this
codebase (OpenCanary, Zeek).

**Two things this deliberately does NOT do**, both flagged in the README's
"Known, documented limits" section (which this change will also need to
update, since it currently says Suricata "isn't yet ingested"):
- Verify or tune the actual ruleset. There's no `suricata.rules` file checked
  in and no automated `suricata-update` step in Compose — the doc note says
  to run it manually. The `jasonish/suricata` image's own entrypoint
  typically self-populates Emerging Threats Open on first boot, but that's
  unconfirmed against a live container in this environment. A stock ET Open
  ruleset is tuned for enterprise/ISP traffic and can be noisy on ordinary
  home traffic — tuning/suppression is a live-environment follow-up, out of
  scope here.
- Change `suricata/suricata.yaml`'s EVE `types` list. It already emits
  `alert`/`dns`/`http`/`tls`/`flow`/`stats` — only `event_type: "alert"`
  lines get ingested. DNS visibility is already Zeek's job; ingesting
  Suricata's DNS/HTTP/TLS logs too would be redundant, not more coverage.

**Field-shape caveat**: the exact EVE JSON `alert` object shape below is the
standard Suricata schema, not verified against a live `eve.json` in this
environment (no Suricata container is running in this sandbox — only
zeek/clamav/redis/postgres are). Same "unverified, degrade gracefully"
posture as `get_wan_stats()`/WiFi radio fields elsewhere in this codebase —
the ingester must skip a line it can't parse rather than crash the poll job.

## Design decisions

- **New alert type: `IDS_SIGNATURE_MATCH`**, not `SURICATA_ALERT` — matches
  this codebase's existing convention of naming alert types after *what was
  found* (`C2_BEACONING`, `ARP_SPOOF`), not the mechanism that found it.
  Suricata alerts span too many categories (exploit attempts, policy
  violations, trojans, scans) to map onto one Heimdall-specific phrase the
  way `C2_BEACONING` does, so this is deliberately generic — analogous to
  `RULE_TRIGGERED` being the generic type for `RuleEngine` matches.
- **Severity mapping**: Suricata/ET convention numbers severity 1 (highest)
  to 3 (lowest) — inverted from intuition. Map `1 → CRITICAL`, `2 → WARNING`,
  `3 → INFO`. Unknown/missing severity defaults to `WARNING` (matches this
  codebase's general default-to-middle posture elsewhere).
- **Auto-block eligible**: routes through `_raise_threat_alert` like most
  other integrations (Zeek DNS/beacon/file-scan all do; only
  `HONEYPOT_ACCESS` deliberately bypasses it). Given the noise caveat above,
  this is the one call worth flagging explicitly at plan-review time rather
  than silently deciding — happy to make `IDS_SIGNATURE_MATCH` bypass
  auto-block instead (alert-only) if the untuned-ruleset risk is a concern
  before the rules get tuned live.

## Backend

**New file `sentinel/security/suricata_parser.py`** (mirrors
`sentinel/security/zeek_parser.py`'s `ZeekDnsLogReader`/`ZeekDnsIngester`
shape exactly):
- `SuricataEveLogReader(log_path)` — `read_new_lines()`, same truncation-safe
  tail as `ZeekDnsLogReader` (`os.path.getsize` vs. stored offset, reset to 0
  with a warning log if the file shrank — a container restart recreating
  `eve.json` fresh is the same risk Zeek's logs have).
- `SuricataAlertIngester` — `parse_event(raw: str) -> Optional[dict]`:
  `json.loads`, skip if `event_type != "alert"` or the line is malformed,
  extract `src_ip`, `dest_ip`, `alert.signature`, `alert.category`,
  `alert.severity` (mapped per above), return a plain dict (not an `Alert`
  directly — mirrors `ZeekDnsIngester`'s choice, since device_mac resolution
  needs DB access this class doesn't have).

**`sentinel/config.py`** (new block after the Zeek/ClamAV settings, before
`BLOCK_EXPIRY_CHECK_INTERVAL_SECONDS`):
```python
SURICATA_EVE_LOG_PATH: str = '/var/log/suricata/eve.json'
SURICATA_POLL_INTERVAL_SECONDS: int = 15
```

**`sentinel/scheduler/scheduler.py`**:
- `__init__`: new `suricata_eve_log_path: str, suricata_poll_interval_s: int`
  params; `self._last_suricata_check_at: datetime | None = None`.
- `_run_loop`: construct `self._suricata_reader = SuricataEveLogReader(...)`,
  `self._suricata_ingester = SuricataAlertIngester()`; register
  `self._suricata_poll_job` as an `'interval'` job (mirrors
  `zeek_dns_poll`'s registration exactly).
- New `_suricata_poll_job`: tails new lines, parses each, resolves
  `device_mac` via the existing `_mac_for_ip(src_ip)` helper (reused
  as-is — same lookup OpenCanary/Zeek already use), calls
  `_raise_threat_alert(mac, 'IDS_SIGNATURE_MATCH', severity, description,
  raw_data=parsed)` where `description` is built from the signature/category
  (e.g. `f'{src_ip} triggered Suricata rule "{signature}" ({category})'`).
  Wrap the per-line body in `try/except` + `logger.exception`, matching
  `_canary_poll_job`'s per-line isolation (one bad line shouldn't drop the
  rest of the batch).
- `security_services_snapshot()`: add
  `'suricata_last_check_at': self._last_suricata_check_at.isoformat() if ... else None`.
- `init_scheduler()`: thread the two new config values through, mirroring
  `opencanary_log_path`/`canary_poll_interval_s`.

No DB migration needed — `Alert.alert_type` is an unconstrained `String(50)`.

## Frontend

- **`frontend/src/components/dashboard/ServiceIcons.jsx`**: new hand-drawn
  glyph, e.g. `SirenIcon` or `RadioTowerIcon` (matches this panel's existing
  style — real, distinct icons per service, not a generic shield reused
  everywhere).
- **`frontend/src/components/dashboard/ServiceStatusPanel.jsx`**: remove the
  "no Suricata/Pi-hole rows" comment (now half-inaccurate); add a new row
  mirroring the "Zeek DNS" row exactly — `ok={!!sec.suricata_last_check_at}`,
  `detail={sec.suricata_last_check_at ? <TimeAgo .../> : 'PENDING'}`.

No other frontend change needed — the Alerts page already renders any
`alert_type` generically.

## Tests

- **`tests/test_security/test_suricata_parser.py`** — mirrors
  `tests/test_security/test_zeek_parser.py`'s reader/ingester test shape:
  truncation-guard (file shrinks → re-read from 0, with the warning log),
  missing-file → empty list, malformed JSON line → `None`, non-`"alert"`
  `event_type` (`dns`/`flow`/`stats`) → `None`, severity 1/2/3/missing →
  CRITICAL/WARNING/INFO/WARNING mapping, correct `src_ip`/`dest_ip`/
  `signature`/`category` extraction from a realistic sample EVE alert line.
- **`tests/test_scheduler/test_suricata_job.py`** — mirrors
  `_zeek_dns_poll_job`/`_persist_dns_query`'s existing test pattern
  (`object.__new__(SentinelScheduler)`, fake reader/ingester or real DB +
  `MockSagemcomAdapter`): a parsed alert line produces an
  `IDS_SIGNATURE_MATCH` alert attributed to the right `device_mac` by source
  IP, severity mapping reaches the persisted `Alert.severity`, and (per the
  auto-block decision above) auto-block behavior when `auto_block_on_threat`
  is armed.

## Docs

- **`README.md`**: update the "Known, documented limits" bullet — Suricata
  now *is* wired (move it out of that section, or add it to the Deep Traffic
  Inspection / Threat Intelligence area of the Defenses table instead).
- **`docs/capability-review.md`**: the intro's "Survey findings" bullet
  already calls this out as "an unlisted follow-up" — add a line noting it's
  now done, consistent with how every other shipped item in that doc is
  annotated.
- **`docs/testing/heimdall_verification.md`**: optionally add one new Kali
  test scenario exercising it (e.g. an nmap `--script vuln` run, or any
  traffic matching a common ET signature, to confirm `IDS_SIGNATURE_MATCH`
  fires) — flagged as a nice-to-have, not blocking.

## Verification

- `python3 -m py_compile` on every new/changed file.
- New unit tests (parser + scheduler job) pass in isolation.
- Full `pytest tests/ -q` against `sentinel_test` — expect only the same 5
  pre-existing unrelated `test_data_retention.py` failures.
- `npm run lint && npm run build`.
- Can't verify live EVE JSON parsing against a real Suricata container in
  this sandbox (none running here) — flagged as a live-environment check
  for the user to confirm once deployed, same posture as the WAN-stats/
  WiFi-radio-field caveats already documented elsewhere in this codebase.
