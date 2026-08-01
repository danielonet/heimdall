# Heimdall — Capability Review & Suggestions

## Context

The user asked for a whole-application review of Heimdall as a security tool —
not a single feature request. The goal: identify overlooked capabilities,
underused existing code, more WiFi/router hardware data we could extract,
additional defenses, and additional Python libraries/tools worth adding,
grounded in what's *actually* in the codebase today (not duplicating things
that already exist, and not proposing things the current router/stack can't
support).

This document is the deliverable itself — a categorized, prioritized
suggestions list. It is not an implementation plan for one feature; nothing
gets built until the user picks items from this list. A codebase survey
(via a research subagent) confirmed, file-by-file, what's real, what's a
disconnected stub, and what's only mentioned in docs — that grounding is
reflected in each item below.

**Survey findings that shaped this list** (real vs. stub vs. doc-only):
- `ClamAV` integration (`sentinel/security/clamav_scanner.py`) — fully coded, **never called from anywhere**.
- `OpenCanary` integration — **real**, fully wired (scheduler job, DB persistence, health status).
- Zeek log parser — **doc-only**, described in `docs/architecture/06-security-services.md`, file doesn't exist.
- `GET /api/threats/dns-stats` — **stubbed**, explicit HTTP 501, "dropped from this project."
- `ThreatIntelService.is_domain_malicious()` — **fully coded, never called** (nothing currently feeds it a domain to check).
- Dependencies installed but with no callers found: `pyclamd`, `pyshark`, `dpkt`, `pandas` (Zeek-only use case, never built).
- Router capabilities never probed at all (not even flagged TBD in the XMO docs): QoS, port forwarding, DDNS, VPN passthrough, guest-network isolation enforcement, WiFi channel/interference monitoring.
- A possible existing bug: wired Ethernet PHY stats may have the same Sent/Received direction swap that was found and fixed for WiFi `AssociatedDevices` — flagged as untested in the docs, never verified.
- ✅ *Done* — a `suricata` service exists in `docker-compose.yml` (with a `suricata-logs` volume); `sentinel/security/suricata_parser.py` now tails its `eve.json` and ingests `event_type=="alert"` lines as `IDS_SIGNATURE_MATCH` alerts (same log-tailing pattern as Zeek/OpenCanary — see `docs/suricata-ingestion-plan.md`). The actual ruleset (Emerging Threats or otherwise) is still unmanaged by Heimdall — this only wires ingestion, not rule fetching/tuning.

**Implementation status of the items below** (updated after re-surveying the code):
- ✅ Done: #1 (ClamAV wired), #2 (Zeek parser + real `/dns-stats` + `is_domain_malicious` now called), #3 (superseded by #2), #5 (rogue DHCP), #6 (WAN bandwidth), #7 (AP-alias visibility, descoped), #8 (WiFi channel visibility), #9 (wired-PHY direction fix), #10 (device-type thresholds), #11 (active/passive OS cross-check), #12 (nmap default-accounts NSE), #13 (time-limited auto-block), #14 (quarantine tier), #15 (cross-alert correlation), #16 (security digest), #17 (`/metrics` endpoint), #18 (CSV alert export), #19 (AP grouping + trust-crossing detector).
- ⬜ Not yet built: #4.
- ✅ Done: #20 (dependency cleanup — `pyclamd`/`pandas` in active use; `pyshark`/`dpkt` removed).

---

## A. Finish what's already built but disconnected (highest ROI, no new dependencies)

1. **Wire up ClamAV.** ✅ *Done — ClamAV is now wired via Zeek's file-extraction analyzer; see item 2.* The scanner class is complete and correct; it just has zero callers. Needs a file-capture source to actually scan bytes — see #2 (Zeek) for the natural source. Without Zeek, the only other file-capture point available today would be an OpenCanary honeypot download, which is a much narrower win. Recommend pairing with #2 rather than doing alone.

2. **Add the Zeek log parser for real.** ✅ *Done — `sentinel/security/zeek_parser.py`, the `zeek` Compose service, and the three scheduler jobs (DNS/beaconing/file-scan) all shipped.* It's already designed (`docs/architecture/06-security-services.md`) and Zeek is a natural fit for this Docker Compose stack (same pattern as the OpenCanary container). Adding it unlocks three things at once:
   - `dns.log` → finally implement `GET /api/threats/dns-stats` (currently a 501 stub) and feed `ThreatIntelService.is_domain_malicious()` (coded, currently unused) — turns your existing malicious-domain feeds into an actual DNS-level detector.
   - `conn.log` → real C2 beaconing detection (`detect_beaconing()` is literally already sketched in the docs — regular-interval connection patterns).
   - `files.log`/file extraction → real input for ClamAV (#1).
   - Cost: one more container, plus an ingestion module (`sentinel/security/zeek_parser.py` doesn't exist yet — this is a genuine build, not just wiring).

3. **Cheaper beaconing detection without Zeek.** *(Superseded by #2 actually shipping — no longer needed.)* If you don't want to add a Zeek container yet, a lightweight approximation is buildable today from data you already collect: `traffic_samples` already has regular per-device throughput at your poll interval. A new detector could flag devices with suspiciously *low-variance, periodic* small-packet traffic (classic beacon signature) using only existing DB data — much weaker than real connection-log analysis, but zero new infrastructure.

---

## B. Extract more from the router/WiFi hardware (uses existing adapter pattern, mostly no new libs)

4. **Rogue AP / "evil twin" detection.** ❌ *Skipped — confirmed blocked, not just unbuilt.* Passively sniff 802.11 beacon frames (scapy `Dot11Beacon`, same sniffing pattern as `ArpWatcher`/`PassiveFingerprinter` already use) for another AP broadcasting your own SSID nearby. **Caveat confirmed true**: needs the sniffing NIC in monitor mode; the current `SNIFF_IFACE` (`eth0` by default) is a normal wired/LAN promiscuous interface, and monitor mode needs a separate radio nothing in this codebase sets up. Revisit only if a spare monitor-mode-capable WiFi adapter becomes available.

5. **Rogue DHCP server detection.** ✅ *Done — `sentinel/security/dhcp_watch.py`'s `DhcpWatcher`, wired into the scheduler exactly like `ArpWatcher`.* Watches for DHCP OFFER packets whose source IP isn't the known router (resolved the same way `create_router_adapter()` resolves `ROUTER_IP`), raising `ROGUE_DHCP_SERVER`.

6. **WAN/household bandwidth tracking.** ✅ *Done, defensively.* `SagemcomXmoAdapter.get_wan_stats()` reads the unverified `IP_DATA/Stats/*` xpath and degrades to `None` (logging once, not every poll) if it doesn't resolve as expected — same posture as Zeek's file-analysis framework. A new `wan_stats` hypertable, dashboard throughput tile, and a rolling-baseline `WanBandwidthDetector` (`WAN_BANDWIDTH_SPIKE`) are wired in. **Still needs live verification** against the real router — see `docs/router/sagemcom-xmo-api.md`'s "Remaining captures needed".

7. **Guest network isolation check.** ⚠️ *Descoped to AP-alias visibility — confirmed a true isolation check isn't buildable.* The XMO API has no traffic-flow/netflow data and no confirmed guest-vs-private subnet split, so "did a guest device reach the private LAN" isn't answerable from this router's API. What shipped instead: the adapter was already fetching each device's AP alias while merging `AssociatedDevices` and discarding it before `DeviceSnapshot` — that plumbing gap is now fixed (`ap_alias` field, DB column, UI badge), making item #19's original claim ("you already know which AP each device is on") actually true.

8. **WiFi channel/interference visibility.** ✅ *Done.* `Device/WiFi/Radios/Radio` is now read in the same batched `get_router_info()` call, surfaced on the Settings page. Field-level names (`Channel`/`TransmitPower`/`OperatingStandards`) are a best-guess against standard TR-181 conventions, not observed live — needs the same live-verification follow-up as #6.

9. **Verify/fix the wired-PHY direction gotcha.** ✅ *Fixed, on the WiFi fix's precedent — not independently re-verified.* Applied the same Sent/Received swap to `get_port_stats()`/`_get_port_traffic_samples()` without a live capture first (explicit user call: fix now, verify later). First real check once live: compare a known wired device's actual upload/download against the Ports page.

---

## C. New detection logic using data you already collect (no new libraries)

10. **Device-type-aware thresholds.** ✅ *Done — `sentinel/detection/device_profiles.py` defines per-type profiles (NAS, IP Camera, Printer, Smartphone) and both `AnomalousVolumeDetector` and `HighUploadDetector` look up their thresholds via `get_profile(snapshot.device_type)` (shipped in commit `65cd50f`).* The `device_type` field opened this up directly: `AnomalousVolumeDetector`/`HighUploadDetector` previously used one flat threshold for every device. A "Smart Plug" or "IP Camera" suddenly generating PC-level upload volume is far more suspicious than the same from a "Computer" — per-category baseline tuning meaningfully cuts both false positives (cameras streaming is normal) and false negatives (a smart plug should basically never have high volume).

11. **Active/passive OS-fingerprint cross-check.** ✅ *Done — the nightly nmap job (`sentinel/scheduler/scheduler.py`, `_nmap_scan_job`) now raises an alert when nmap's active OS detection disagrees with `PassiveFingerprinter`'s most recent passive guess.* You already have two independent OS signals per device: nmap's active `-O` detection (`NetworkScanner`, nightly) and the passive TCP fingerprint (`PassiveFingerprinter`). Previously only passive-vs-passive drift was checked (`FINGERPRINT_MISMATCH`); active-vs-passive is now cross-checked as a free additional spoofing signal from data already gathered nightly.

12. **Expand nmap NSE script coverage for credential exposure.** ✅ *Done — `NetworkScanner` now runs `--script default-accounts,http-default-accounts,...` (`sentinel/security/scanner.py`), raised as a distinct alert type from `--script vuln` findings.* This catches devices exposing default/blank credentials, a very common real-world IoT compromise vector, using infrastructure already in place.

---

## D. Extra defenses / response tooling

13. **Time-limited auto-block with review.** ✅ *Done — `Device.blocked_at`/`blocked_until` + `AppSettings.auto_block_expiry_hours` (default 24h, `0` = never expires).* `_raise_threat_alert` (re-)stamps the expiry timer on every successful auto-block, including a re-block of an already-blocked device (the fix for a real race: a fresh threat must always reset the clock). A new interval job, `_block_expiry_job`, sweeps overdue auto-blocks, unblocks them via the adapter, raises a low-severity `AUTO_BLOCK_EXPIRED` alert, and sends a review notification. Manual blocks (`POST /devices/<mac>/block`) never set `blocked_until`, so they stay indefinite by design.

14. **Repurpose the original (wrong-for-blocking) firewall-rule mechanism as a "quarantine" tier.** ✅ *Done — `SagemcomXmoAdapter.quarantine_device`/`unquarantine_device`.* Confirmed there was no dead code to resurrect (the mechanism was previously rejected and removed, only the xpath/payload shape survived in the docs) — this is new adapter code using `addChild` on `Device/Firewall/Chains/Chain[Name="Custom"]/Rules`, scoped to the device's IP. Read-only safety check on `Device/Firewall/Levels/Level[Name="Custom"]/DefaultPolicy` warns (never writes) if the rule won't actually enforce yet — flipping the router's whole active firewall posture is deliberately out of scope for a per-device action. New `Device.is_quarantined` column, `POST /devices/<mac>/quarantine`/`/unquarantine` routes (manual-only — no detector auto-triggers it), and a QUARANTINE/UNQUARANTINE button + badge on the device header, distinct from BLOCKED.

15. **Cross-alert correlation.** ✅ *Done — new standalone `sentinel/detection/correlation.py`, not a `RuleEngine` extension.* Confirmed `RuleEngine`'s condition model has no concept of the `alerts` table at all (it evaluates one live poll snapshot at a time) and that `_raise_threat_alert` is only one of four alert-creation paths — a correlator hooked only into `_raise_threat_alert` would miss `NEW_DEVICE` entirely, the exact pattern named in this item. `CrossAlertCorrelator` instead queries the persisted `alerts` table directly on its own interval job (`_correlation_job`), against a small curated pattern list (`NEW_DEVICE` → spoofing/mismatch within 60min; known exposure → compromise signs within 24h). Matches escalate to a single `COMPROMISE_CHAIN_DETECTED` incident routed through the normal `_raise_threat_alert` path (so it's auto-blockable like any other high-confidence finding), with per-follow-alert dedup so the same pair never re-fires.

16. **Daily/weekly security digest notification.** ✅ *Done — new cron job `_security_digest_job` (`SECURITY_DIGEST_CRON`, default daily 07:00).* Confirmed `NotificationService.notify()` wasn't wired to fire for every alert today — only for alerts matched by an admin-defined `NOTIFY` rule — so this is the first mechanism that reports on every alert type uniformly, reading the `alerts` table directly. Sent unconditionally on every cron fire, with a calmer "all clear" framing when nothing happened since the last digest (tracked via `AppSettings.last_digest_sent_at`).

---

## E. Observability / frontend

17. **Prometheus-style `/metrics` endpoint.** ✅ *Done — `GET /api/metrics`, plain-text exposition format, no new dependencies (hand-rolled, not `prometheus_client`).* Exposes device counts (total/online/blocked/quarantined/trusted), alert rates (total/unacknowledged/last-1h/last-24h, all by severity), and poll latency (`heimdall_poll_last_duration_seconds`, a new real timing added to `_poll_job` via `time.monotonic()` — previously only `last_poll_at`/`last_poll_error` were tracked, no duration) plus `heimdall_scheduler_up`. Deliberately unauthenticated, same posture as `/api/health` — a standard Prometheus static scrape config can't refresh this app's short-lived JWT access tokens, and every metric here is an aggregate count, never a per-device identifying detail.

18. **Alert export (CSV/PDF).** ✅ *Done — CSV only (PDF explicitly scoped out to avoid the new `reportlab` dependency).* New `GET /api/alerts/export`, reusing the same filters as `GET /api/alerts` (severity, device_mac, acknowledged, resolved, from, to), capped at 50,000 rows, joined against `devices` for hostname context. New "EXPORT CSV" link on the Alerts page mirrors whatever severity/ack/date-range filters are currently active in the UI.

19. **Per-device AP/band visualization.** ✅ *Done — both halves shipped.* A "GROUP BY AP" toggle on the Devices page (desktop table + mobile cards, shared grouping/ordering logic in `frontend/src/lib/apGroups.js`) buckets devices by AP alias, guest groups visually distinguished. New `AccessPointCrossingDetector` (`sentinel/detection/detectors/ap_crossing.py`) is the "signal" half: it deliberately does *not* fire on ordinary band-hopping (`PRIV0`<->`VID1`, `GUEST2G`<->`GUEST5G` — normal WiFi roaming/steering, would be pure noise) — only a device crossing the guest/private trust boundary raises `AP_TRUST_CROSSING` (WARNING moving private->guest, CRITICAL moving guest->private, since that direction implies unexplained access escalation).

---

## F. Housekeeping

20. **Resolve the dead dependencies.** ✅ *Done.* `pyclamd` and `pandas` are both in active use (ClamAV scanning, Zeek beacon detection — see #1/#2). `pyshark`/`dpkt` turned out to live only in a stale, entirely unused root-level `requirements.txt` — nothing installs from it (the Dockerfile and `scripts/install.sh` both explicitly use `sentinel/requirements.txt`), and it had drifted badly (it still listed `aioredis`, which CLAUDE.md rule 2 flags as archived/unimportable on Python 3.11+). Deleted rather than patched, since a second unreferenced copy of the dependency list is itself the problem this item was about. While auditing, also found `python-json-logger` genuinely dead in the *real* `sentinel/requirements.txt` — logging actually runs on stdlib `logging.basicConfig` (`sentinel/api/app.py:_configure_logging`), never JSON-formatted — removed that too. `docs/architecture/08-dependencies.md` (a design-era doc that had drifted even further from reality than the stale root file had) rewritten to mirror `sentinel/requirements.txt` exactly.

---

## Suggested next step

This is a menu, not a queue — recommend picking a small number of items (2-4)
to scope as actual implementation plans, rather than attempting all of this
at once. Every "quick win" cluster has now shipped: **#10/#11/#12** (device-
type thresholds, active/passive OS cross-check, default-accounts NSE),
**#5/#6/#7/#8/#9** (rogue DHCP, WAN bandwidth, AP-alias visibility, WiFi
channel visibility, wired-PHY direction fix), and **#13/#14/#15/#16**
(time-limited auto-block, quarantine tier, cross-alert correlation, security
digest), **#17/#18** (metrics endpoint, CSV alert export), and **#19** (AP
grouping + trust-crossing detector) — see each item's status note above.
**#4 (rogue AP)** was evaluated and skipped: it needs a monitor-mode-capable
WiFi radio this deployment doesn't have — the only item left unbuilt. The
**Suricata** EVE-JSON ingestion flagged in the survey findings above has
also since shipped. Remaining follow-up isn't new features so much as
hardening what's already shipped: verifying/tuning the actual Suricata
ruleset against real home traffic (this integration ingests alerts, it
doesn't manage the rule set); live-verifying the best-guess integrations
from earlier rounds (**#6** WAN stats' `IP_DATA/Stats` xpath, **#8** WiFi
radios' TR-181 field names, and **#14**'s quarantine `Rule` object field
names) against the real router; and, if Grafana ever gets pointed at
**#17**'s `/metrics` endpoint, adding a Prometheus scrape config + a
starter dashboard JSON to `docs/` so that setup is copy-paste rather than
built from scratch.
