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

4. **Rogue AP / "evil twin" detection.** Passively sniff 802.11 beacon frames (scapy `Dot11Beacon`, same sniffing pattern as `ArpWatcher`/`PassiveFingerprinter` already use) for another AP broadcasting your own SSID nearby — a classic impersonation attack, and a natural extension of the "nearby devices" work just shipped. **Caveat**: needs the sniffing NIC in monitor mode to see beacon frames from APs you're not associated with; your current `SNIFF_IFACE` is a LAN-facing interface, not necessarily monitor-capable — worth confirming hardware supports this before committing.

5. **Rogue DHCP server detection.** Same sniffing infrastructure as `ArpWatcher` — watch for DHCP OFFER packets from a MAC that isn't your router. A classic MITM technique (rogue DHCP handing out a malicious gateway/DNS), cheap to add since the packet-capture plumbing already exists.

6. **WAN/household bandwidth tracking.** `IP_DATA/Stats/*` xpaths are flagged unverified in `docs/router/sagemcom-xmo-api.md` but never explored — would enable a total-bandwidth dashboard widget and a "household bandwidth spike" alert, distinct from per-device anomaly detection.

7. **Guest network isolation check.** `GUEST2G`/`GUEST5G` AccessPoint aliases are already queryable (used for device data) but nothing currently verifies guest devices *can't* reach the private LAN. A detector that checks for guest-SSID devices communicating with private-LAN IPs would catch a misconfigured/bypassed guest network — a real, distinct security property this router type is supposed to enforce.

8. **WiFi channel/interference visibility.** `Device/WiFi/Radios/Radio` (channel, TX power, standard) is already read for device classification but never surfaced as its own signal — a simple channel-utilization/interference panel would be a nice-to-have for network health, secondary priority vs. the security items above.

9. **Verify/fix the wired-PHY direction gotcha.** Flagged as untested in the docs since the WiFi `AssociatedDevices` Sent/Received swap was found and fixed earlier — if Ethernet has the same issue, wired devices' upload/download could currently be displayed backwards. Quick to verify (capture real traffic on a known wired device, compare direction), cheap to fix if confirmed.

---

## C. New detection logic using data you already collect (no new libraries)

10. **Device-type-aware thresholds.** The `device_type` field just shipped opens this up directly: `AnomalousVolumeDetector`/`HighUploadDetector` currently use one flat threshold for every device. A "Smart Plug" or "IP Camera" suddenly generating PC-level upload volume is far more suspicious than the same from a "Computer" — per-category baseline tuning would meaningfully cut both false positives (cameras streaming is normal) and false negatives (a smart plug should basically never have high volume).

11. **Active/passive OS-fingerprint cross-check.** You already have two independent OS signals per device: nmap's active `-O` detection (`NetworkScanner`, nightly) and the passive TCP fingerprint (`PassiveFingerprinter`). Currently only passive-vs-passive drift is checked (`FINGERPRINT_MISMATCH`). Cross-checking active vs. passive results (do they agree?) is a free additional spoofing signal from data you already gather nightly.

12. **Expand nmap NSE script coverage for credential exposure.** `NetworkScanner.vuln_scan()` already runs `--script vuln`; adding `--script default-accounts` (or a curated auth-focused script list — `http-default-accounts`, `mysql-empty-password`, etc.) would catch devices exposing default/blank credentials, a very common real-world IoT compromise vector, using infrastructure you already have.

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
at once. The strongest "quick win" cluster, if the user wants a starting
point: **#10 (device-type-aware thresholds)** and **#11 (active/passive OS
cross-check)** use only data already being collected, no new infra, and
directly extend detectors already fixed this session. **#4/#5 (rogue AP /
rogue DHCP)** are the highest-impact *new* capability for a home security
tool specifically, contingent on confirming monitor-mode hardware support.
