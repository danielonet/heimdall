# Heimdall Security Guard — Penetration Testing Verification Report

**Device:** LG X140 Netbook
**Testing Platform:** Kali Linux (Xfce)
**Purpose:** Verify Heimdall Security Guard detection and protection capabilities
**Tester:** Authorized network owner

---

## Heimdall Protected Features Under Test

| Feature | Description |
|--------|-------------|
| ARP Watch | Detects a known IP suddenly presenting a different MAC (ARP spoofing signature) |
| Rogue DHCP Watch | Detects DHCP OFFER packets from a source that isn't the known router |
| Passive Fingerprint Detection | Guesses a device's OS from raw TCP SYN characteristics, no active scanning |
| Nightly Nmap Scan | Active OS/service detection, newly-opened high-risk ports, `--script vuln`, default-credential NSE scripts (all run once nightly, not on demand) |
| Network Traffic Anomaly Detection | Per-device ML models (IsolationForest + LOF) flag outlier traffic volume |
| High-Ratio Upload Detection | Flags a sustained high upload/download ratio (possible exfiltration) |
| Hostname/Vendor Mismatch | Flags a hostname implying a different vendor than the device's OUI |
| OpenCanary | Honeypot trap — any interaction with a fake service is CRITICAL |
| Zeek DNS Visibility | Passive DNS query logging + malicious-domain alerting (URLhaus feed) |
| Zeek C2 Beaconing Detection | Flags suspiciously regular-interval connections to the same remote host |
| ClamAV Malware Scanning | Scans files Zeek extracts from observed cleartext downloads |
| Cross-Alert Correlation | Escalates a matching pair of alerts on the same device into one higher-severity incident |
| Time-Limited Auto-Block | An auto-block (not a manual one) expires after a configurable window and re-notifies |
| Quarantine Tier | WAN-only block — cuts internet, leaves the device reachable on the LAN |
| Signal-Strength Anomaly | Flags a WiFi device's RSSI shifting and holding at a new level (possible MAC-spoofed swap) — see Test 22 |
| Suricata IDS | Signature-based IDS tailing its own EVE JSON log — matches live traffic against a maintained rule set (see Test 19) |
| WAN-Wide Bandwidth Spike | Household-total throughput (all devices combined) outlier vs. a rolling baseline — distinct from the per-device detectors in Test 6 (see Test 20) |
| AP Trust-Boundary Crossing | Flags a device moving between guest and private Wi-Fi SSIDs, escalating CRITICAL on a guest→private move (see Test 21) |
| Custom Detection Rules | User-authored condition→action rules (DeviceSnapshot/TrafficSample triggers; ALERT/BLOCK_DEVICE/NOTIFY/TAG_DEVICE/RATE_LIMIT actions) (see Test 23) |
| Malicious Traffic Destination | Correlates a traffic-spike alert to the remote IP it was headed to via Zeek's conn.log, checks it against threat intel, escalates a real match (see Test 24) |
| Device Identity Auto-Linking | Recognizes MAC-randomization roaming (same hostname, ARP-confirmed) and merges duplicate device rows — housekeeping, not an attack signal (see Check D) |
| Device Archive Sweep | Soft-archives devices with no activity for a configurable window — housekeeping, not an attack signal (see Check E) |

---

## Section A — Real-Time Passive Detection

### Test 1 — ARP Spoofing Attack

**Objective:** Verify Heimdall's ARP watcher detects a known IP suddenly presenting a different MAC.

**Kali Tool:** arpspoof / bettercap
**GUI App:** Ettercap (`sudo ettercap -G`)

**Command Line:**
```bash
# Method 1 - arpspoof
sudo arpspoof -i eth0 -t <gateway_ip> <target_ip>

# Method 2 - bettercap
sudo bettercap -iface eth0
# Then inside bettercap console:
net.probe on
arp.spoof on
```

**Ettercap GUI Steps:**
1. Launch `sudo ettercap -G`
2. Select Sniff → Unified Sniffing → eth0
3. Scan for hosts → Host List
4. Set Target 1 as gateway, Target 2 as victim
5. Mitm → ARP Poisoning → OK

**Expected Heimdall Response:**
- `ARP_SPOOF` CRITICAL alert, naming the IP and its new/old MAC
- If `auto_block_on_threat` is armed: the attacking MAC is auto-blocked — this
  removes it from the network entirely via the router's own device-block
  mechanism (`BlacklistedSchedule`, 24/7), not an inline "ARP packet filter" —
  there is no packet-level ARP firewall in this codebase, so on a
  disarmed/false setting the spoofing itself is never interrupted, only
  alerted on
- `Device.blocked_at`/`blocked_until` get stamped (see Test 14)

**Caveat — trusted-device exception**: if the MAC now holding the IP is
already in Heimdall's trusted-devices registry, none of the above happens.
`ArpWatcher` can't distinguish "attacker impersonating a known IP" from "two
of the user's own devices both statically configured with the same IP" — it
only sees a MAC change. A trusted new MAC is treated as the latter: it is
**never** auto-blocked, and instead of a CRITICAL `ARP_SPOOF` alert you get a
single INFO-severity `IP_CONFLICT` alert, suppressed on repeat flaps of the
*same* IP for `IP_CONFLICT_QUIET_MINUTES` (default 30). For this test to
exercise the real CRITICAL/auto-block path, run it from a device that is
**not** marked trusted in Heimdall — which is the normal case for an
external Kali attacker anyway. Worth a second, deliberate run against a
trusted device's IP too, to confirm the downgrade itself works and nothing
gets blocked.

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 2 — Rogue DHCP Server

**Objective:** Verify Heimdall's DHCP watcher detects a DHCP OFFER from a
source that isn't the known router.

**Kali Tool:** dnsmasq / Yersinia / a manually-configured `isc-dhcp-server`

**Command Line:**
```bash
# Quick rogue DHCP server via dnsmasq (don't leave this running — it will
# actually hand out leases to real devices on the segment if unbounded;
# a small deliberately-wrong range keeps the blast radius contained)
sudo apt install -y dnsmasq
sudo dnsmasq --interface=eth0 --no-daemon --dhcp-range=192.168.1.200,192.168.1.210,1h \
    --port=0 --bind-interfaces

# Or via Yersinia's DHCP module for a rogue-server/starvation combo
sudo yersinia -G   # DHCP tab → rogue server
```

**Expected Heimdall Response:**
- `ROGUE_DHCP_SERVER` CRITICAL alert naming the offering IP/MAC, distinct
  from the router's own configured IP (resolved the same way the router
  adapter itself resolves it — `ROUTER_IP` if set, else the default-route
  gateway)
- If `auto_block_on_threat` is armed: the Kali MAC is auto-blocked

**Note:** `DhcpWatcher` only starts once the scheduler can resolve the real
router's IP — check the Service Status panel's "DHCP Watch" row is ACTIVE
before running this test, otherwise there is nothing listening to compare
against.

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 3 — Hostname/Vendor Spoofing

**Objective:** Verify Heimdall flags a device whose DHCP hostname strongly
implies a different vendor than its actual MAC OUI.

**Kali Tool:** `hostnamectl` / `dhclient`

**Command Line:**
```bash
# Set a hostname that implies Apple/Samsung/Google/Amazon/Microsoft/Sony
# hardware, then force a fresh DHCP request so the router/Heimdall sees the
# new name — Kali's own MAC OUI is virtually never one of those vendors
sudo hostnamectl set-hostname iphone-test
sudo dhclient -r eth0 && sudo dhclient -H iphone-test eth0
```

**Expected Heimdall Response:**
- `VENDOR_MISMATCH` WARNING alert: `Hostname "iphone-test" implies vendor
  "apple" but the router reports OUI vendor "<real OUI vendor, or blank>"`
- Not auto-blocked — this detector is a heuristic-only signal (hostnames are
  user-editable, OUI databases are incomplete), never routed through the
  auto-block path

**Note:** Matches on a curated keyword list (`iphone`/`ipad`/`macbook`/
`imac`/`appletv` → apple, `galaxy`/`samsung` → samsung, `pixel` → google,
`kindle`/`echo`/`alexa`/`firetv` → amazon, `xbox`/`surface` → microsoft,
`playstation`/`ps5`/`ps4` → sony) — pick a hostname containing one of these
exact substrings.

**Note — a second, distinct alert_type from the same detector:** the same
`VendorMismatchDetector` also produces `VENDOR_UNVERIFIED` (INFO severity)
when a device's MAC OUI can't be resolved to any vendor at all (a blank/
unknown OUI, not a hostname/vendor mismatch) — not worth a dedicated attack
simulation, but don't be surprised to see this alert_type appear on a
locally-administered/randomized MAC (Kali's own vendor NIC is normally
resolvable, but a spoofed or randomized MAC may not be).

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 4 — OpenCanary Honeypot Trigger

**Objective:** Verify Heimdall's OpenCanary honeypot detects and alerts on intrusion attempts to fake services.

**Kali Tool:** nmap / netcat / browser
**GUI App:** Zenmap, Firefox browser

**Command Line:**
```bash
# Probe common honeypot ports
nmap -sV -p 21,22,23,80,443,3306,8080 <heimdall_ip>

# Attempt FTP connection to honeypot
ftp <heimdall_ip>

# Attempt Telnet connection
telnet <heimdall_ip> 23

# Attempt SSH connection
ssh user@<heimdall_ip>

# HTTP probe
curl http://<heimdall_ip>:8080
```

**Expected Heimdall Response:**
- `HONEYPOT_ACCESS` CRITICAL alert logged immediately for each real
  connection attempt (a bare port probe with no protocol interaction may not
  register — OpenCanary alerts on actual service interaction, not just a
  TCP connect)
- Source IP of attacker recorded, attributed to a known device_mac if the
  source IP matches one
- Not auto-blocked — HONEYPOT_ACCESS is persisted directly, independent of
  the `auto_block_on_threat` path

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 5 — Passive Fingerprint & New-Device Visibility

**Objective:** Verify Heimdall's passive fingerprinter records an OS guess
from the Kali box's raw TCP SYN packets, and that the Kali device itself
gets picked up as a new device — **without conflating the two**: these are
independent mechanisms with independent alert conditions.

**Kali Tool:** curl / ping (to generate a TCP SYN and general traffic)
**GUI App:** Wireshark (to observe what Heimdall itself would see)

**Command Line:**
```bash
curl http://192.168.1.1
ping -c 5 192.168.1.1
```

**Wireshark GUI Steps (observational only):**
1. Launch `wireshark`, select the LAN interface, start capture
2. Filter: `tcp[tcpflags] & tcp-syn != 0` — this is the exact filter
   `PassiveFingerprinter` sniffs on
3. Observe: TTL and TCP window size on Kali's first SYN are what Heimdall
   buckets into an OS guess (64/65535→"Linux / Android",
   128/65535→"Windows", 64/65536→"macOS / iOS"; anything else→"Unknown")

**Expected Heimdall Response:**
- The Kali device appears in the device list with `os_fingerprint` set to
  its passive guess (`Linux / Android` for a stock Kali TCP/IP stack) —
  **no alert fires for this first-ever fingerprint**, it's just recorded
  (confirmed regression-tested: a device's *first* passive fingerprint is
  never treated as a mismatch)
- Separately, once Kali is actually online (not just glimpsed), `NEW_DEVICE`
  CRITICAL fires the first time its MAC connects — unless the system is
  still in its post-install LEARNING window (`ML_LEARNING_PERIOD_HOURS`,
  default 72h), during which every newly-connecting device is silently
  auto-trusted instead of alerted on
- A **later** re-test where Kali's IP presents a *different* signature than
  its own last-recorded one (e.g. spoofing a static IP previously used by a
  Windows device) fires `FINGERPRINT_MISMATCH` WARNING instead — this is
  the actual "known device's fingerprint changed" signal, distinct from the
  first-sighting case above

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 6 — Traffic Volume / Upload-Ratio Anomaly

**Objective:** Verify Heimdall's ML-based volume detector and ratio-based
upload detector flag abnormal traffic from the Kali box.

**Kali Tool:** hping3

**Command Line:**
```bash
# Sustained outbound flood — high upload volume, low/no return traffic
sudo hping3 -1 --flood 192.168.1.1
sudo hping3 -S --flood -p 80 192.168.1.1
sudo hping3 -2 --flood -p 53 192.168.1.1
```

**Expected Heimdall Response:**
- `ANOMALOUS_VOLUME` WARNING (ML models agree the traffic is an outlier) and/or
  `HIGH_UPLOAD` WARNING (sustained upload/download ratio above the
  device-type threshold) — **not both reliably on every run**, and **no
  auto-block, rate-limiting, or inline packet blocking of any kind happens
  for either of these two alert types** (unlike Section A/C's other alerts,
  neither routes through the auto-block path)
- Both detectors require several **consecutive** polls above threshold
  before firing (not a single spike — `SUSTAINED_POLLS`), then go quiet for
  a 30-minute cooldown per device even if the flood continues, so re-running
  this test repeatedly against the same device inside 30 minutes of a prior
  fire will correctly produce nothing new
- `AnomalousVolumeDetector` is additionally suppressed for the first
  `ML_LEARNING_PERIOD_HOURS` (default **72 hours**) after a device's first
  connection — on a fresh install, or a Kali box that just connected for
  the first time, expect **no** `ANOMALOUS_VOLUME` alert until that window
  passes, even under an obvious flood

**Note:** this test only covers *per-device* volume/ratio anomalies. The
household-wide analog — total WAN throughput across every device combined —
is a separate detector with its own alert_type; see Test 20.

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Section B — Nightly Active-Scan-Triggered Findings

These four alert types are only ever produced by Heimdall's **own** nightly
active nmap job against every device it already knows about (`NMAP_SCAN_CRON`,
default `02:00` daily) — there is no on-demand trigger anywhere in the API.
**To test any of Section B same-day**, temporarily set a near-future cron
(e.g. `NMAP_SCAN_CRON=*/5 * * * *` in `.env`) and restart the
`sentinel-backend` container, then restore the real schedule afterward.

### Test 7 — Newly-Opened High-Risk Port

**Objective:** Verify Heimdall flags a device exposing a port that has no
business being open on an ordinary LAN client.

**Kali Tool:** netcat / a deliberately-exposed service

**Command Line:**
```bash
# Any of these ports triggers it: 21 (FTP), 23 (Telnet), 135 (MSRPC),
# 139 (NetBIOS), 445 (SMB), 512/513/514 (rexec/rlogin/rsh), 1433 (MSSQL),
# 3389 (RDP), 5900 (VNC), 4444 (Metasploit default handler), 31337 ("elite")
sudo nc -lvp 23
```

**Expected Heimdall Response:**
- On the next nightly scan (or the temporary short cron above), a
  `HIGH_RISK_PORT_OPENED` CRITICAL alert fires naming the IP, port, and
  service label — this fires on the device's **very first** scan too (an
  empty scan history counts every currently-open high-risk port as "newly"
  opened), not only on a second scan showing a change
- If `auto_block_on_threat` is armed: the device is auto-blocked

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 8 — Vulnerability & Default-Credential Findings

**Objective:** Verify Heimdall's nightly `--script vuln` and default-account
NSE scripts flag a genuinely vulnerable/misconfigured target.

**Kali Tool:** any deliberately-vulnerable service (Metasploitable2/3 VM,
`vsftpd` with anonymous login enabled, a test MySQL/MongoDB instance with a
blank password)

**Command Line (example: anonymous FTP, the simplest to stand up):**
```bash
sudo apt install -y vsftpd
sudo sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf
sudo systemctl restart vsftpd
```

**Expected Heimdall Response:**
- `CREDENTIAL_EXPOSURE_DETECTED` CRITICAL for the anonymous-FTP/default-account
  case (NSE scripts: `default-accounts`, `http-default-accounts`, `ftp-anon`,
  `mongodb-info`, `mysql-empty-password`) — or `VULNERABILITY_DETECTED`
  CRITICAL for a genuine CVE finding from `--script vuln` (a Metasploitable
  VM is the reliable way to guarantee a real hit here)
- If `auto_block_on_threat` is armed: the device is auto-blocked

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 9 — Active/Passive OS-Fingerprint Conflict *(advanced, best-effort)*

**Objective:** Verify Heimdall flags a device whose nightly active nmap `-O`
result disagrees, at the OS-family level, with its last-recorded passive
fingerprint.

**Why this one is hard to force deterministically:** `PassiveFingerprinter`
keeps updating a device's stored fingerprint on *every* TCP SYN it sees from
it, right up until the nightly scan runs — so for the conflict to still be
present at scan time, nothing may sniff a fresh SYN from the device in
between that would silently correct it back into agreement. This is a
genuine edge case, not a routinely-reproducible one.

**Kali Tool:** a second Linux device's real, unspoofed OS (Kali's own OS is
usually enough) + an IP takeover

**Command Line:**
```bash
# 1. Pick an IP Heimdall has previously fingerprinted as something OTHER
#    than 'linux_android' (e.g. a Windows laptop's normal IP, while it's
#    powered off) — check the device's os_fingerprint via GET /api/devices
# 2. Take that IP on the Kali box instead (a real Linux TCP/IP stack)
sudo ip addr add <target_ip>/24 dev eth0
# 3. Immediately generate one connection so Heimdall's own OWN passive
#    fingerprinting doesn't race ahead — but avoid MORE traffic than needed,
#    since further SYNs before the nightly scan will just re-correct it
curl -m 3 http://192.168.1.1 || true
# 4. Wait for (or force, per Section B's header note) the nightly scan
```

**Expected Heimdall Response:**
- `OS_FINGERPRINT_CONFLICT` WARNING naming both the previously-recorded
  passive OS and nmap's active-scan OS, only when both bucket into
  different families (`windows` / `macos_ios` / `linux_android` / `other`) —
  a passive "Windows" vs. active "Linux 5.x" is a real conflict; two
  differently-worded strings that bucket into the *same* family (e.g.
  passive "Linux / Android" vs. active "Linux 3.10 - 4.11") is **not**
  treated as a conflict
- If `auto_block_on_threat` is armed: the device is auto-blocked

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Section C — Multi-Stage & Response-Policy Verification

### Test 10 — Malicious Domain DNS Query (Zeek DNS + Threat Intel)

**Objective:** Verify Heimdall's Zeek DNS visibility logs every DNS query it
observes on the wire, and raises a `DNS_MALICIOUS_QUERY` alert when a query
resolves against a domain on the URLhaus threat feed.

**Kali Tool:** dig / curl

**Command Line:**
```bash
# Baseline: any query should show up in dns-stats and advance the Zeek DNS
# service-status timestamp, whether or not it's malicious
dig example.com

# Malicious-domain check: pick a domain CURRENTLY listed at
# https://urlhaus.abuse.ch/browse/ before testing — entries rotate daily,
# so a domain from an old test run will no longer be flagged
dig <current-urlhaus-domain>
curl -m 5 http://<current-urlhaus-domain>/
```

**Note:** The Threat Intel panel on the dashboard shows when the `urlhaus`
feed last refreshed (nightly, `THREAT_FEED_REFRESH_CRON`) — confirm it's
recent before picking a test domain, otherwise the feed may not yet include
it. Only cleartext DNS (UDP/53) is visible to Zeek; a device using
DNS-over-HTTPS/TLS bypasses this test entirely, which is an expected blind
spot, not a Heimdall bug.

**Expected Heimdall Response:**
- Zeek DNS row in the dashboard's Service Status panel goes ACTIVE and its
  timestamp advances
- `GET /api/threats/dns-stats` shows `total_queries` incrementing
- For the URLhaus domain specifically: a `DNS_MALICIOUS_QUERY` CRITICAL
  alert is raised naming the querying device and domain; the query appears
  in `dns-stats`' `blocked_queries` / `top_blocked_domains`; the device is
  auto-blocked if `auto_block_on_threat` is armed

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 11 — C2 Beaconing Simulation (Zeek conn.log Analysis)

**Objective:** Verify Heimdall flags a device making suspiciously
regular-interval connections to the same remote host — a common command-
and-control beacon signature — even though no single connection looks
malicious on its own.

**Kali Tool:** bash loop + curl (or netcat against a listener you control)

**Command Line:**
```bash
# 15 connections to the same remote host at a fixed 60s interval — comfortably
# above the detector's default min_count (10) with low jitter (<2s stddev)
for i in $(seq 1 15); do
    curl -s -o /dev/null -m 5 http://<remote_test_host>/
    sleep 60
done
```

**Note:** Runs for ~15 minutes. `<remote_test_host>` needs to be something
the Kali box can reach reliably every cycle (a host you control is safest —
this only tests timing regularity, not the destination's reputation). The
beacon scan itself runs every `ZEEK_BEACON_SCAN_INTERVAL_SECONDS` (default
300s/5min), so allow up to 5 extra minutes after the loop finishes before
checking for the alert.

**Expected Heimdall Response:**
- Zeek Beaconing row's timestamp advances every scan cycle regardless of
  outcome
- A `C2_BEACONING` CRITICAL alert is raised naming the source device,
  destination host, connection count, and interval mean/stddev
- Device auto-blocked if `auto_block_on_threat` is armed

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 12 — Malware File Download (Zeek Extraction + ClamAV)

**Objective:** Verify Zeek's file-extraction analyzer captures a downloaded
file of a curated MIME type and ClamAV flags it as malicious.

**Kali Tool:** curl / a local HTTP server for the test file

**Command Line:**
```bash
# EICAR: the industry-standard synthetic AV test string, recognized by every
# antivirus engine (including ClamAV) as "malware" without being real
# malware — safe to use even on a live network.
curl -o eicar.com http://secure.eicar.org/eicar.com

# If external access isn't available, serve it from the Kali box instead:
python3 -m http.server 8000 --directory /tmp   # with eicar.com placed there
curl -o eicar.com http://<kali_ip>:8000/eicar.com
```

**Note:** Must be plain HTTP, not HTTPS — this pipeline inspects cleartext
file transfers only, no TLS interception is configured (a known, expected
blind spot). The download's `Content-Type` needs to land in
`zeek/local.zeek`'s curated extraction set (`application/octet-stream`
covers most plain test-file downloads); if a test server reports something
outside that set (e.g. `text/plain`), Zeek won't extract it — that's the
extraction policy working as designed (see the ClamAV section of
`docs/architecture/06-security-services.md`), not a failure to fix.

**Expected Heimdall Response:**
- File appears in `/var/zeek/extracted/` briefly (deleted immediately after
  scanning, whether clean or infected — check ClamAV row activity, not the
  directory contents, to confirm the scan ran)
- ClamAV flags the EICAR signature
- A `MALWARE_DETECTED` CRITICAL alert is raised naming the filename, source
  device, and ClamAV's verdict; device auto-blocked if
  `auto_block_on_threat` is armed
- ClamAV row in Service Status shows REACHABLE with a recent timestamp

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 13 — Cross-Alert Correlation (Compromise Chain)

**Objective:** Verify Heimdall escalates two specific alerts on the same
device, close together in time, into one higher-severity
`COMPROMISE_CHAIN_DETECTED` incident instead of leaving them as two
unrelated rows.

**Kali Tool:** whatever produced the two underlying alerts (reuses Tests 1
and 5, or Tests 7/8 and 12)

**Command Line:**
```bash
# Pattern 1 — NEW_DEVICE_THEN_SPOOFING (60-minute window):
# connect the Kali box to the network for the first time (fires NEW_DEVICE —
# only outside the LEARNING window, see Test 5), then within the hour, run
# Test 1's ARP spoof from that same MAC.

# Pattern 2 — EXPOSURE_THEN_COMPROMISE (24-hour window):
# get a HIGH_RISK_PORT_OPENED/VULNERABILITY_DETECTED/CREDENTIAL_EXPOSURE_DETECTED
# finding (Section B) on a device, then within 24h get a MALWARE_DETECTED or
# C2_BEACONING finding (Tests 11/12) on that SAME device.
```

**Expected Heimdall Response:**
- A new `COMPROMISE_CHAIN_DETECTED` CRITICAL alert, naming both the trigger
  and follow alert and describing the pattern matched — appears within
  `CORRELATION_SCAN_INTERVAL_SECONDS` (default 300s/5min) of the second
  alert landing
- The same trigger→follow pair never produces a second
  `COMPROMISE_CHAIN_DETECTED` on a later scan (dedup) — but a *different*,
  later follow-alert on the same device (e.g. a second, unrelated spoof)
  can still produce a fresh incident
- Device auto-blocked if `auto_block_on_threat` is armed (this routes
  through the same auto-block path as any other high-confidence finding)

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 14 — Time-Limited Auto-Block Expiry

**Objective:** Verify an auto-block (as opposed to a manual admin block)
automatically expires after its configured window and generates a review
notification — rather than staying blocked forever.

**Kali Tool:** whatever produces an auto-block (e.g. Test 1's ARP spoof)

**Testing tip:** `auto_block_expiry_hours` (default **24**) has no Settings-page
UI yet — set it directly for testing purposes:
```bash
docker compose exec postgres psql -U sentinel -d sentinel \
    -c "UPDATE app_settings SET auto_block_expiry_hours = 0;"   # (no expiry) or a small non-zero value
```
The expiry sweep itself runs on `BLOCK_EXPIRY_CHECK_INTERVAL_SECONDS`
(default 900s/15min), so even a "1 hour" expiry setting can take up to 15
extra minutes past the hour mark to actually fire.

**Command Line:**
```bash
# Trigger an auto-block (e.g. re-run Test 1's ARP spoof with
# auto_block_on_threat armed), then wait past the configured expiry window
# plus one BLOCK_EXPIRY_CHECK_INTERVAL_SECONDS cycle
```

**Expected Heimdall Response:**
- Immediately after the auto-block: the device's detail view shows an
  "auto-unblocks in Xh Ym" indicator (manual blocks show nothing here —
  they never expire by design)
- A **re-block** for a fresh reason resets the expiry clock rather than
  leaving the original timer running — verify by re-triggering the same
  attack partway through the window and confirming the countdown restarts
- Once the window elapses: the device is unblocked automatically, a
  low-severity `AUTO_BLOCK_EXPIRED` alert is raised, and (if ntfy/SMTP is
  configured on the Settings page) a "Auto-block expired — review and
  re-block if still suspicious" notification is sent

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 15 — Quarantine Tier (WAN Cut, LAN Preserved)

**Objective:** Verify the admin-triggered quarantine action cuts a device's
internet access while leaving it reachable on the LAN — a softer tier than
a full block, and verify the reverse (unquarantine) restores internet
access.

**Kali Tool:** ping / curl (as the target being quarantined, to observe the
effect from inside)

**Setup (admin action, not an attack):**
1. Log into the Heimdall dashboard, find the Kali device, click
   **◐ QUARANTINE** on its detail page (or `POST
   /api/devices/<kali_mac>/quarantine` with a bearer token)

**Command Line (run from the Kali box after being quarantined):**
```bash
# LAN reachability — should still work
ping -c 3 <router_lan_ip>
ping -c 3 <another_lan_device_ip>

# WAN reachability — should now fail
ping -c 3 8.8.8.8
curl -m 5 http://example.com
```

**Expected Heimdall Response:**
- Device shows an amber "QUARANTINED" badge, distinct from a red "BLOCKED" one
- LAN pings succeed; WAN pings/HTTP requests fail
- **Known live-verification caveat**: the underlying router mechanism (a
  Custom-chain firewall rule matched to the device's IP) only actually
  enforces if the router's own active Security Level is itself set to
  "Custom" — Heimdall reads and warns in its logs if that precondition
  isn't met, but never changes that router-wide setting itself. If WAN
  traffic is *not* actually cut despite a successful "QUARANTINED" badge,
  check the router's own admin UI for its Security Level setting before
  treating this as a Heimdall failure.
- `POST /api/devices/<mac>/unquarantine` (or the ✓ UNQUARANTINE button)
  restores WAN access

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Section D — Documented Gaps (Expected Non-Detections)

These are deliberately included so a "no alert fired" result reads as a
**pass** against the documented architecture, not an unexplained miss.
Confirm the *absence* of an alert for each, then move on — chasing a
missing detection here is chasing a feature that doesn't exist yet.

### Test 16 — Active Port-Scan Detection *(no alert expected)*

**Objective:** Confirm Heimdall does **not** raise any alert purely because
Kali ran an nmap scan against the LAN — there is no "an nmap scan just
happened" signature anywhere in this codebase. `PassiveFingerprinter` only
ever compares OS *guesses* over time; it has no concept of "I am currently
being scanned." Heimdall's own nightly nmap job (Section B) scans devices
*it* already tracks — it does not detect scans run *against* it.

**Kali Tool:** nmap
**GUI App:** Zenmap

**Command Line:**
```bash
sudo nmap -sn 192.168.1.0/24
sudo nmap -sS -O 192.168.1.0/24
sudo nmap -A -T4 192.168.1.0/24
```

**Expected Heimdall Response:**
- No dedicated "scan detected" alert of any kind
- The Kali box itself may still separately trigger `NEW_DEVICE` (first time
  online, Test 5) the moment it starts sending traffic — that's a side
  effect of it being on the network at all, not a detection of the scan

**Result:** ☐ Confirmed gap (expected) &nbsp;&nbsp; ☐ Unexpected alert fired (investigate)

**Notes:** _______________________________________________

---

### Test 17 — DNS Reconnaissance *(no alert expected)*

**Objective:** Confirm Heimdall does **not** raise any alert for DNS
enumeration/brute-force activity — there is no query-volume or
enumeration-pattern detector in this codebase. `DNS_MALICIOUS_QUERY` (Test
10) only fires against a specific known-malicious domain via the URLhaus
feed, never on query *volume* or *pattern*.

**Kali Tool:** dnsrecon / dnsenum

**Command Line:**
```bash
dnsrecon -d local -t std
dnsenum 192.168.1.1
nmap -sn -R 192.168.1.0/24
```

**Expected Heimdall Response:**
- Zeek DNS's `total_queries` counter increments (it logs every query it
  sees, benign or not) — but no dedicated reconnaissance/enumeration alert
  fires

**Result:** ☐ Confirmed gap (expected) &nbsp;&nbsp; ☐ Unexpected alert fired (investigate)

**Notes:** _______________________________________________

---

### Test 18 — WiFi Reconnaissance / Rogue AP *(no alert expected — hardware-blocked)*

**Objective:** Confirm Heimdall does **not** detect 802.11 monitor-mode
reconnaissance or a rogue "evil twin" AP. This is a known, deliberately
unbuilt gap (capability review item #4): detecting it needs the sniffing
NIC in 802.11 monitor mode, and this deployment's `SNIFF_IFACE` is a normal
wired/LAN promiscuous interface with no monitor-mode-capable WiFi radio
attached.

**Kali Tool:** airodump-ng / kismet

**Command Line:**
```bash
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
sudo airodump-ng -c <channel> --bssid <AP_MAC> wlan0mon
sudo airmon-ng stop wlan0mon
```

**Expected Heimdall Response:**
- No alert of any kind — 802.11 probe/beacon frames aren't visible to
  Heimdall's sniffing interface at all, whether or not `SNIFF_IFACE` is
  correctly configured

**Result:** ☐ Confirmed gap (expected) &nbsp;&nbsp; ☐ Unexpected alert fired (investigate)

**Notes:** _______________________________________________

---

### Test 19 — Suricata IDS Signature Match

**Objective:** Verify Heimdall ingests Suricata's own EVE JSON alerts and
raises an `IDS_SIGNATURE_MATCH` alert for a real-time signature match —
conceptually a Section A real-time test (Suricata inspects live traffic
continuously, not on a schedule), numbered last here since it was wired up
after the rest of this document.

**Kali Tool:** nmap `--script vuln`, or any traffic matching a common
Emerging Threats signature (e.g. an EICAR-style test string over plain HTTP
also tends to match ET's own malware-signature rules, independent of
ClamAV's separate detection in Test 12)

**Command Line:**
```bash
sudo nmap --script vuln <heimdall_ip>
```

**Before testing**, confirm Suricata's ruleset actually loaded — this
integration only *ingests* whatever alerts the container produces, it
doesn't fetch or verify the ruleset itself:
```bash
docker exec <suricata-container> ls /var/lib/suricata/rules/
```
An empty or missing `suricata.rules` means there's nothing to match against
regardless of how the Kali box behaves — that's a Suricata/ruleset problem,
not a Heimdall ingestion problem, and worth ruling out before treating a
"no alert" result as a Heimdall failure.

**Expected Heimdall Response:**
- Suricata IDS row in the dashboard's Service Status panel goes ACTIVE and
  its timestamp advances on Suricata's own poll cadence
  (`SURICATA_POLL_INTERVAL_SECONDS`, default 15s) — independent of whether
  any rule actually matched
- On a genuine signature match: an `IDS_SIGNATURE_MATCH` alert naming the
  source IP, the matched rule's signature text, and its category; severity
  mapped from the rule's own priority (1→CRITICAL, 2→WARNING, 3→INFO)
- Device auto-blocked if `auto_block_on_threat` is armed — same as most
  other integrations in this document (only `HONEYPOT_ACCESS` deliberately
  never auto-blocks)

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Section C.2 — Additional Detectors (Added Since Initial Verification)

Numbered to continue the sequence rather than renumbering Tests 1-19 — same
precedent as Test 19 itself, appended after Section D when it was wired up
later. These five cover every alert_type introduced since this document's
first pass; cross-checked against the full current `sentinel/` codebase.

### Test 20 — WAN-Wide Bandwidth Spike

**Objective:** Verify Heimdall's household-wide (not per-device) traffic
detector flags a spike in *total* WAN throughput across every device
combined — a separate detector/alert_type from Test 6's per-device checks.

**Kali Tool:** iperf3 (cleaner sustained-throughput generator than a flood
tool for this test) or hping3, run from **two or more** devices at once

**Command Line:**
```bash
# Option 1 — iperf3 against a server you control (avoids DoS-flavored
# traffic against a target you don't own)
iperf3 -c <your_iperf3_server> -t 60 -P 4

# Option 2 — reuse Test 6's hping3 flood, but from multiple devices
# simultaneously so the *combined* household total clears the threshold
sudo hping3 -1 --flood 192.168.1.1
```

**Note:** `WanBandwidthDetector` keeps a rolling 20-poll (~5min at the
default 15s interval) baseline, needs at least 10 samples before judging,
and fires after `mean + 3×stdev` is exceeded for 2 **consecutive** polls
(~30s sustained). No cooldown timer — it resolves the moment total
throughput drops back under threshold, so a short burst may both fire and
auto-resolve before you check the Alerts page.

**Expected Heimdall Response:**
- `WAN_BANDWIDTH_SPIKE` WARNING alert, `device_mac` is **null** (household-
  wide, not attributable to one device) — naming total/baseline mean/stdev
  in `raw_data`
- No auto-block (never routes through the confirmed-attack pipeline)
- On the Zeek/full tier, this can also feed Test 24's correlation — see below

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 21 — AP Trust-Boundary Crossing

**Objective:** Verify Heimdall flags a device roaming between a guest SSID
and a private SSID — not ordinary band-hopping (e.g. 2.4GHz↔5GHz on the same
private network, which must NOT fire).

**Kali Tool:** none — this needs a real WiFi client physically reassociating
to a different SSID (a laptop/phone's own WiFi settings, or `nmcli`/
`iwconfig` from a WiFi-capable Kali box)

**Command Line (example via nmcli, if the Kali box has a WiFi adapter):**
```bash
# 1. Connect to a private SSID, let Heimdall poll at least once (up to one
#    POLL_INTERVAL_SECONDS, default 15s)
nmcli dev wifi connect "<private_ssid>" password "<private_psk>"
sleep 20

# 2. Reassociate to a guest SSID
nmcli dev wifi connect "<guest_ssid>" password "<guest_psk>"
sleep 20

# 3. (Optional, for the CRITICAL direction) reassociate back to private
nmcli dev wifi connect "<private_ssid>" password "<private_psk>"
```

**Note:** Trust tier is derived purely from the AP alias: anything starting
with `GUEST` (`GUEST2G`/`GUEST5G`) is the guest tier, everything else
(`PRIV0`/`VID1`/etc.) is private. Needs two full poll cycles with a genuine
AP change recorded in between — check the device's `ap_alias` via
`GET /api/devices` if the alert doesn't fire on the first attempt.

**Expected Heimdall Response:**
- Private → guest move: `AP_TRUST_CROSSING` **WARNING**
- Guest → private move: `AP_TRUST_CROSSING` **CRITICAL** (flagged as an
  unexpected access escalation — nothing in Heimdall legitimately
  auto-promotes a device from guest to private)
- No auto-block

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 22 — WiFi Signal-Strength Anomaly

**Objective:** Verify Heimdall flags a WiFi device's RSSI shifting and
holding at a new level — a possible signature of a MAC-spoofed device swap
(same MAC, different physical radio/location).

**Kali Tool:** none — this is read directly from the router's own per-client
RSSI report each poll; there is no software/packet-level way to fake it

**Command Line:** n/a — physically move a WiFi test device far enough from
the AP (or back toward it) to shift RSSI by more than 15 dBm, and hold the
new position for at least two consecutive polls (~30s at the default 15s
interval)

**Note:** Suppressed for a device's first `ML_LEARNING_PERIOD_HOURS`
(default **72h**) after its first connection — use a device that's been on
the network for several days, not a freshly-added one, or this will
silently do nothing regardless of how far you move it. Wired devices report
`signal_strength_dbm=0` and are always skipped — this only applies to WiFi.

**Expected Heimdall Response:**
- `SIGNAL_ANOMALY` WARNING alert once the shift holds for 2 consecutive polls
- No auto-block

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 23 — Custom Detection Rule (Rule Engine)

**Objective:** Verify a user-authored rule (not a built-in detector) fires
its configured action when its condition matches — Heimdall's own
rule-authoring feature, not a built-in threat signature.

**Kali Tool:** curl (this exercises the API directly, not a network attack)

**Command Line:**
```bash
# 1. Log in to get a bearer token
TOKEN=$(curl -s -X POST http://<heimdall_ip>:5000/api/login \
    -H 'Content-Type: application/json' \
    -d '{"username": "<admin_username>", "password": "<admin_password>"}' \
    | jq -r .access_token)

# 2. Create the simplest possible always-true rule: fires on the very next
#    poll for every currently-online device, no network condition needed —
#    good for confirming the rule engine wiring itself, not for testing a
#    specific detection scenario
curl -s -X POST http://<heimdall_ip>:5000/api/rules \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{
      "name": "test-rule-always-fires",
      "condition_json": {"trigger": "DEVICE_SNAPSHOT", "field": "is_online", "op": "EQ", "value": true, "window_polls": 1},
      "action_json": {"type": "ALERT", "severity": "WARNING"},
      "enabled": true
    }'

# 3. (Optional) dry-run any rule's condition read-only before enabling it —
#    evaluates against the last 100 rows, executes nothing, persists nothing
curl -s -X POST http://<heimdall_ip>:5000/api/rules/<rule_id>/test \
    -H "Authorization: Bearer $TOKEN"
```

**Note:** `condition_json.trigger` is `DEVICE_SNAPSHOT` (fields: `mac_address`,
`ip_address`, `hostname`, `vendor_name`, `interface_name`,
`signal_strength_dbm`, `signal_rate_mbps`, `is_online`, `port_alias`,
`device_type`, `ap_alias`) or `TRAFFIC_SAMPLE` (fields: `mac_address`,
`bytes_sent_delta`, `bytes_recv_delta`, `throughput_up_kbps`,
`throughput_dn_kbps`, `granularity`, `port_alias`, `poll_interval_s`) —
`op` is one of `GT|LT|GTE|LTE|EQ|NEQ|CONTAINS|IN`. `action_json.type` is one
of `ALERT|BLOCK_DEVICE|NOTIFY|TAG_DEVICE|RATE_LIMIT`. A `BLOCK_DEVICE` action
calls the router adapter directly — it does **not** route through the same
confirmed-attack choke point as every built-in detector, so it won't get the
`blocked_at`/`blocked_until` auto-expiry stamping Test 14 exercises; a
rule-triggered block should be treated as indefinite until manually
unblocked. **Remember to delete or disable this test rule afterward** — an
always-true `DEVICE_SNAPSHOT`/`is_online` condition will otherwise keep
firing on every poll indefinitely.

**Expected Heimdall Response:**
- `RULE_TRIGGERED` alert (severity per `action_json.severity`) for every
  currently-online device, within one poll cycle
- The dry-run endpoint returns `matched`/`evaluated` counts and up to 20
  sample matches, without creating any alert

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

### Test 24 — Malicious Traffic Destination (Zeek Conn-Log + Threat Intel Correlation)

**Objective:** Verify Heimdall correlates a traffic-spike alert
(`ANOMALOUS_VOLUME`/`HIGH_UPLOAD`/`WAN_BANDWIDTH_SPIKE`) to the remote IP it
was actually headed to, via Zeek's conn.log, and escalates a genuine
threat-intel match to a new CRITICAL, auto-block-eligible finding.

**Requires the `full` deployment tier (Zeek container running)** — the
enrichment job no-ops entirely on `minimal`/`intermediate`.

**Kali Tool:** whatever produced the underlying spike (Test 6 or Test 20) +
either real internet egress to a currently-listed threat-feed IP, or a
direct DB cache seed for a controlled test IP

**Command Line:**
```bash
# Step 1 — produce a feeder alert first (reuse Test 6 or Test 20)
sudo hping3 -1 --flood 192.168.1.1

# Step 2a — REAL feed option: from the SAME device, generate outbound
# traffic to a currently-listed Tor exit node or Feodo C2 IP (check
# https://feodotracker.abuse.ch/ or a current Tor exit list at test time —
# these rotate, do not hardcode an old IP) while the spike is active/recent
curl -m 5 http://<current-feodo-or-tor-exit-ip>/ || true

# Step 2b — CONTROLLED option (no internet dependency): seed a fake
# verdict directly into the threat-intel cache for a test IP, so the
# enrichment job finds a "malicious" match regardless of real feed content.
# Pick <test-ip> as whatever IP the spike device actually talked to
# recently (check Zeek's conn.log directly, or wait for the enrichment job's
# first pass to populate the spike alert's own raw_data.remote_ip field,
# then re-seed the cache for THAT ip and wait for the next pass) — the
# cache is keyed by IP, so seeding an unrelated IP the device never
# actually contacted won't correlate.
docker compose exec postgres psql -U sentinel -d sentinel -c \
    "INSERT INTO threat_intel_cache (ip_or_domain, is_malicious, threat_type, source_feed, score, cached_at, expires_at) \
     VALUES ('<test-ip>', true, 'blocklist', 'blocklist', 1, now(), now() + interval '24 hours') \
     ON CONFLICT (ip_or_domain) DO UPDATE SET is_malicious = true;"
```

**Note:** The enrichment job runs every `SPIKE_IP_ENRICHMENT_INTERVAL_SECONDS`
(default 300s/5min) and only looks at spike alerts from the last 30 minutes,
correlating a ±15min/+5min window of conn.log around when the spike fired —
allow up to ~5 extra minutes after seeding the cache for the next job run to
pick it up. Each spike alert is enriched **at most once**
(`raw_data.ip_enrichment_done`), so re-running this test against the exact
same still-open spike alert won't re-fire — trigger a fresh spike (a new
alert row) for a repeat test. `GET /api/threats/lookup/<ip>` is a read-only
way to check/prime a real verdict for a specific IP without the INSERT above,
but it won't force a false verdict — it only reflects genuine feed/OTX data.

**Expected Heimdall Response:**
- The original spike alert's `raw_data` gets enriched with `remote_ip`,
  `remote_ip_bytes`, `remote_ip_connections`, `remote_ip_malicious` — visible
  on the Alerts page as a "REMOTE IP:" note under the original alert
- On a malicious verdict: a new `MALICIOUS_TRAFFIC_DESTINATION` **CRITICAL**
  alert, `dedup_key` = the remote IP, referencing the trigger alert in
  `raw_data` — device auto-blocked if `auto_block_on_threat` is armed
- This can also feed `COMPROMISE_CHAIN_DETECTED` (Test 13) if the same
  device already has a `VULNERABILITY_DETECTED`/`CREDENTIAL_EXPOSURE_DETECTED`/
  `HIGH_RISK_PORT_OPENED` finding within the prior 24h

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Section E — Operational / Audit Verification *(not attacks — skip if only scoring detection capability)*

### Check A — Prometheus `/metrics` Endpoint

```bash
curl http://<heimdall_ip>:5000/api/metrics
```
Confirm plain-text output with `heimdall_devices_total`, `heimdall_alerts_total{severity="..."}`,
`heimdall_scheduler_up`, and (once the scheduler has polled at least once)
`heimdall_poll_last_duration_seconds`. Unauthenticated by design (see
`sentinel/api/routes/metrics.py`) — this is not a vulnerability to report,
it mirrors `/api/health`'s existing posture and exposes only aggregate counts.

### Check B — Alert CSV Export

From the Alerts page, click **EXPORT CSV** (or `curl
'http://<heimdall_ip>:5000/api/alerts/export?severity=CRITICAL'`) and
confirm the downloaded file's rows match whatever filters were active.

### Check C — Security Digest Notification

If ntfy/SMTP is configured on the Settings page, confirm a daily digest
notification arrives (`SECURITY_DIGEST_CRON`, default 07:00) summarizing
alert counts since the last digest — including an "all clear" message on a
day with zero alerts, not silence.

### Check D — Device Identity Auto-Linking (Duplicate MAC Merge)

Housekeeping, not a security signal — recognizes when WiFi MAC-address
randomization (iOS Private Wi-Fi Address / Android per-network MAC) makes
one physical device look like several rows, and auto-merges them.

**Setup:** a phone with MAC randomization enabled (default on modern iOS/
Android), a custom hostname set on it so the DHCP hostname is stable and
identifiable across reconnects.

**Steps:**
1. Connect the phone, let it get polled, note its current MAC in the device list.
2. Force a MAC rotation: on iOS, "Forget This Network" then rejoin the same
   SSID; on Android, similarly forget/rejoin (or wait for the OS's periodic
   rotation). The **old** MAC's IP must go genuinely unreachable (the device
   is actually off that lease) — this only links when exactly one of the
   candidate group answers an ARP probe.
3. Wait up to `DEVICE_IDENTITY_LINK_SCAN_INTERVAL_SECONDS` (default 5min).

**Expected Heimdall Response:**
- A `DEVICE_IDENTITY_LINKED` INFO alert on the new MAC
- The old MAC's device row disappears from the default device list (hidden,
  not deleted) but remains visible via its own detail page, with an UNLINK
  button to reverse the merge if the guess was wrong
- Candidates only group by matching hostname + both being locally-
  administered (randomized) MACs, within a 24h lookback — this will not
  trigger for two genuinely different devices that happen to share a hostname
  unless both also present randomized MACs

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

### Check E — Device Archive Sweep (Soft-Delete)

Housekeeping, not a security signal — soft-archives (hides, doesn't delete)
devices with no activity for a configurable window.

**Setup — lower the threshold for testing** (Settings page, or directly):
```bash
TOKEN=$(curl -s -X POST http://<heimdall_ip>:5000/api/login \
    -H 'Content-Type: application/json' \
    -d '{"username": "<admin_username>", "password": "<admin_password>"}' \
    | jq -r .access_token)
curl -s -X PATCH http://<heimdall_ip>:5000/api/settings \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"device_archive_after_days": 7}'   # minimum allowed value
```

**Steps:**
1. Pick (or make) a test device whose `last_seen` is already older than the
   configured threshold — must be **untrusted, unblocked, unquarantined,
   and not already linked-away** (Check D), or it's permanently exempt.
   There's no fast-forward: either genuinely wait, or directly update that
   device's `last_seen` in the DB for test purposes.
2. Wait up to `DEVICE_ARCHIVE_SWEEP_INTERVAL_SECONDS` (default hourly).

**Expected Heimdall Response:**
- The device disappears from the default `GET /api/devices` list
- It reappears under `GET /api/devices?archived=true`
- `POST /api/devices/<mac>/unarchive` restores it to the default list
  immediately (no wait needed for the reverse direction)
- No alert is raised for an archive event (deliberately silent/routine)

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Summary Results

| Test | Feature Tested | Result | Notes |
|------|---------------|--------|-------|
| 1 | ARP Spoofing | ☐ Pass ☐ Fail ☐ Partial | |
| 2 | Rogue DHCP Server | ☐ Pass ☐ Fail ☐ Partial | |
| 3 | Hostname/Vendor Spoofing | ☐ Pass ☐ Fail ☐ Partial | |
| 4 | OpenCanary Honeypot | ☐ Pass ☐ Fail ☐ Partial | |
| 5 | Passive Fingerprint / New Device | ☐ Pass ☐ Fail ☐ Partial | |
| 6 | Traffic Volume / Upload-Ratio Anomaly | ☐ Pass ☐ Fail ☐ Partial | |
| 7 | Newly-Opened High-Risk Port | ☐ Pass ☐ Fail ☐ Partial | |
| 8 | Vulnerability / Credential Exposure | ☐ Pass ☐ Fail ☐ Partial | |
| 9 | OS-Fingerprint Conflict (advanced) | ☐ Pass ☐ Fail ☐ Partial | |
| 10 | Zeek DNS / Malicious Domain | ☐ Pass ☐ Fail ☐ Partial | |
| 11 | Zeek C2 Beaconing | ☐ Pass ☐ Fail ☐ Partial | |
| 12 | ClamAV Malware Scan | ☐ Pass ☐ Fail ☐ Partial | |
| 13 | Cross-Alert Correlation | ☐ Pass ☐ Fail ☐ Partial | |
| 14 | Auto-Block Expiry | ☐ Pass ☐ Fail ☐ Partial | |
| 15 | Quarantine Tier | ☐ Pass ☐ Fail ☐ Partial | |
| 16 | Port-Scan Detection Gap | ☐ Confirmed ☐ Unexpected | |
| 17 | DNS Reconnaissance Gap | ☐ Confirmed ☐ Unexpected | |
| 18 | WiFi/Rogue-AP Gap | ☐ Confirmed ☐ Unexpected | |
| 19 | Suricata IDS Signature Match | ☐ Pass ☐ Fail ☐ Partial | |
| 20 | WAN-Wide Bandwidth Spike | ☐ Pass ☐ Fail ☐ Partial | |
| 21 | AP Trust-Boundary Crossing | ☐ Pass ☐ Fail ☐ Partial | |
| 22 | WiFi Signal-Strength Anomaly | ☐ Pass ☐ Fail ☐ Partial | |
| 23 | Custom Detection Rule | ☐ Pass ☐ Fail ☐ Partial | |
| 24 | Malicious Traffic Destination | ☐ Pass ☐ Fail ☐ Partial | |

*(Section E's Checks A-E are operational/housekeeping verifications, not attack tests — not scored here, same as the existing convention for Checks A-C.)*

---

## Kali Linux Tools Reference

| Tool | Type | Purpose | Launch Command |
|------|------|---------|---------------|
| nmap | CLI | Port scanning & OS detection | `sudo nmap` |
| Zenmap | GUI | nmap graphical frontend | `sudo zenmap` |
| Ettercap | GUI/CLI | ARP spoofing & MITM | `sudo ettercap -G` |
| bettercap | CLI | Network attacks framework | `sudo bettercap` |
| arpspoof | CLI | ARP poisoning | `sudo arpspoof` |
| dnsmasq | CLI | Rogue DHCP server (Test 2) | `sudo dnsmasq --interface=... --dhcp-range=...` |
| Yersinia | GUI/CLI | L2 attacks incl. DHCP rogue/starvation | `sudo yersinia -G` |
| hostnamectl / dhclient | CLI | Hostname spoofing (Test 3) | `sudo hostnamectl set-hostname ...` |
| Wireshark | GUI | Packet capture & analysis | `wireshark` |
| Kismet | Web UI | WiFi network mapping (Test 18, gap) | `sudo kismet` |
| airodump-ng | CLI | WiFi packet capture (Test 18, gap) | `sudo airodump-ng` |
| hping3 | CLI | Traffic flood/volume testing | `sudo hping3` |
| netdiscover | CLI | Network discovery | `sudo netdiscover` |
| p0f | CLI | Passive OS fingerprinting (observational) | `sudo p0f` |
| dnsrecon / dnsenum | CLI | DNS enumeration (Test 17, gap) | `dnsrecon` |
| vsftpd | Service | Anonymous-FTP credential-exposure target (Test 8) | `sudo systemctl restart vsftpd` |
| Metasploitable2/3 | VM | Reliable `--script vuln` target (Test 8) | — |
| dig | CLI | DNS lookups (Test 10) | `dig <domain>` |
| curl | CLI | HTTP requests / file downloads (Tests 3, 8-15) | `curl` |
| EICAR test file | Test file | Safe, industry-standard synthetic malware signature (Test 12) | `curl -o eicar.com http://secure.eicar.org/eicar.com` |
| psql | CLI | Direct `app_settings`/`threat_intel_cache` edits for test timing/seeding (Tests 14, 24) | `docker compose exec postgres psql -U sentinel -d sentinel` |
| docker exec | CLI | Confirm Suricata's ruleset actually loaded (Test 19) | `docker exec <suricata-container> ls /var/lib/suricata/rules/` |
| iperf3 | CLI | Sustained legitimate high-throughput generator (Test 20) | `iperf3 -c <server> -t 60 -P 4` |
| nmcli / iwconfig | CLI | WiFi SSID reassociation, requires a WiFi-capable adapter (Test 21) | `nmcli dev wifi connect "<ssid>" password "<psk>"` |
| jq | CLI | Extract `access_token` from login responses for authenticated API calls (Tests 23, 24, Check E) | `curl ... \| jq -r .access_token` |

---

## Legal Declaration

All tests performed on this network are authorized by the network owner. This document serves as verification evidence for Heimdall Security Guard capabilities. No unauthorized systems were targeted.

**Tester Signature:** _______________________________________________
**Date:** _______________________________________________
**Network:** _______________________________________________
