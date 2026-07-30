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
- A `suricata` service now exists in `docker-compose.yml` (with a `suricata-logs` volume) but has **no Python integration** yet — the only reference in code is a comment in `scheduler.py` listing it among services that get a fabricated health-status row. Wiring a Suricata EVE-JSON log parser (same pattern as the Zeek and OpenCanary ingestion) is an unlisted follow-up.

**Implementation status of the items below** (updated after re-surveying the code):
- ✅ Done: #1 (ClamAV wired), #2 (Zeek parser + real `/dns-stats` + `is_domain_malicious` now called), #3 (superseded by #2), #10 (device-type thresholds), #11 (active/passive OS cross-check), #12 (nmap default-accounts NSE).
- ⬜ Not yet built: #4, #5, #6, #7, #8, #9, #13, #14, #15, #16, #17, #18, #19.
- ◐ Partial: #20 (dependency cleanup — `pyclamd`/`pandas` now in use; `pyshark`/`dpkt` still have no callers).

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

13. **Time-limited auto-block with review.** Blocks are currently indefinite. A block that auto-expires (e.g. 24h) with a review notification would reduce the blast radius of a false positive while still giving the same immediate response.

14. **Repurpose the original (wrong-for-blocking) firewall-rule mechanism as a "quarantine" tier.** The `Device/Firewall/Chains/Chain[Name="Custom"]` rule mechanism discovered earlier doesn't stop LAN-local traffic — which made it *wrong* for the full-block use case, but makes it *exactly right* for a softer "cut internet, allow LAN" quarantine response for suspect-but-unconfirmed devices, as a middle ground below full `BlacklistedSchedule` block.

15. **Cross-alert correlation.** `RuleEngine` already has a condition/action framework; extending it (or adding a small correlation layer) to recognize patterns like "NEW_DEVICE immediately followed by ARP_SPOOF from the same MAC" and escalate to a single higher-severity incident would cut noise and surface real compromise chains instead of isolated alerts.

16. **Daily/weekly security digest notification.** `NotificationService` (ntfy + SMTP) already exists for live alerts; a scheduled summary job (reuses existing scheduler + notification infra, zero new dependencies) would give a periodic "here's what happened" digest distinct from real-time pings.

---

## E. Observability / frontend

17. **Prometheus-style `/metrics` endpoint.** The `/api/debug/memory` endpoint already exposes internal state cleanly; a lightweight `/metrics` extension (device counts, alert rates, poll latency) would let the user point Grafana/Prometheus at Heimdall if they already run home-lab monitoring.

18. **Alert export (CSV/PDF).** Useful for the user's own pentest record-keeping (matches what they've been doing with the Kali VM this whole engagement) or general audit trail. CSV is dependency-free; PDF would need a small new library (e.g. `reportlab`).

19. **Per-device AP/band visualization.** You already know which AP alias (`PRIV0`/`VID1`/`GUEST2G`/`GUEST5G`/`AP_BACKHAUL`) each device is on — a simple grouped view (or a device switching bands unexpectedly as a signal) would use data that's already collected but not really surfaced today.

---

## F. Housekeeping

20. **Resolve the dead dependencies.** `pyclamd` (until #1 is done), `pyshark`, `dpkt`, and `pandas`'s only listed use case (Zeek) currently have no callers — either commit to using them (#1/#2) or remove them to keep `requirements.txt` honest about what's actually running. *Status: `pyclamd` and `pandas` are now both in active use (ClamAV scanning, Zeek beacon detection). `pyshark`/`dpkt` are still unused.*

---

## Suggested next step

This is a menu, not a queue — recommend picking a small number of items (2-4)
to scope as actual implementation plans, rather than attempting all of this
at once. The original "quick win" cluster (**#10 device-type thresholds**,
**#11 active/passive OS cross-check**, plus **#12 default-accounts NSE**) has
now shipped. With those done, the strongest remaining candidates are:
**#4/#5 (rogue AP / rogue DHCP)** — the highest-impact *new* capability for a
home security tool specifically, contingent on confirming monitor-mode
hardware support; **#15 (cross-alert correlation)** — turns the isolated
alerts these new detectors produce into correlated incidents; and wiring the
**Suricata** service that's already in the Compose file but has no parser yet.
