# Heimdall Security Guard — Penetration Testing Verification Report

**Device:** LG X140 Netbook  
**Testing Platform:** Kali Linux (Xfce)  
**Purpose:** Verify Heimdall Security Guard detection and protection capabilities  
**Tester:** Authorized network owner  

---

## Heimdall Protected Features Under Test

| Feature | Description |
|--------|-------------|
| OpenCanary | Honeypot trap detection |
| Network Traffic Anomaly Detection | Detects unusual traffic patterns |
| Passive Fingerprint Detection | Identifies devices without active scanning |
| Nmap Scanner | Active port and service detection |
| ARP Protection | Detects and blocks ARP spoofing attacks |
| Zeek DNS Visibility | Passive DNS query logging + malicious-domain alerting (URLhaus feed) |
| Zeek C2 Beaconing Detection | Flags suspiciously regular-interval connections to the same remote host |
| ClamAV Malware Scanning | Scans files Zeek extracts from observed downloads |

---

## Test 1 — ARP Spoofing Attack

**Objective:** Verify Heimdall ARP protection detects and blocks ARP poisoning attempts.

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
- ARP spoofing alert triggered
- Attack source IP flagged
- Network protection blocks poisoned ARP packets

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Test 2 — Active Network Scan (Nmap)

**Objective:** Verify Heimdall detects active port scanning and OS fingerprinting.

**Kali Tool:** nmap  
**GUI App:** Zenmap (`sudo zenmap`)

**Command Line:**
```bash
# Basic network discovery
sudo nmap -sn 192.168.1.0/24

# Full port scan with OS fingerprinting
sudo nmap -sS -O 192.168.1.0/24

# Aggressive scan
sudo nmap -A -T4 192.168.1.0/24

# Stealth scan
sudo nmap -sS -T2 192.168.1.1
```

**Zenmap GUI Steps:**
1. Launch `sudo zenmap`
2. Target: your network range e.g. 192.168.1.0/24
3. Profile: Intense scan or OS Detection
4. Click Scan

**Expected Heimdall Response:**
- Nmap scan detected and logged
- Scanning device IP flagged
- OS fingerprinting attempt recorded
- Alert generated for aggressive scan profiles

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Test 3 — OpenCanary Honeypot Trigger

**Objective:** Verify Heimdall OpenCanary honeypot detects and alerts on intrusion attempts to fake services.

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
- OpenCanary connection attempt logged immediately
- Alert triggered for each fake service probe
- Source IP of attacker recorded
- Timestamp and service type logged

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Test 4 — Passive Fingerprint Detection

**Objective:** Verify Heimdall passive fingerprinting identifies the Kali testing device without being actively scanned.

**Kali Tool:** p0f / netdiscover  
**GUI App:** Wireshark

**Command Line:**
```bash
# Passive OS fingerprinting
sudo p0f -i eth0 -p

# Network discovery (passive mode)
sudo netdiscover -p -i eth0

# Generate traffic for passive detection
curl http://192.168.1.1
ping -c 5 192.168.1.1
```

**Wireshark GUI Steps:**
1. Launch `wireshark`
2. Select eth0 interface
3. Start capture
4. Filter: `arp or icmp`
5. Observe traffic patterns Heimdall would passively see

**Expected Heimdall Response:**
- Kali device identified by OS fingerprint (Linux/Kali signature)
- Device added to network inventory
- Any unusual fingerprint flagged as new/unknown device

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Test 5 — Traffic Anomaly Detection

**Objective:** Verify Heimdall traffic anomaly detection flags unusual traffic volumes and patterns.

**Kali Tool:** hping3 / nmap  
**GUI App:** Ettercap, Wireshark

**Command Line:**
```bash
# ICMP flood (ping flood)
sudo hping3 -1 --flood 192.168.1.1

# SYN flood simulation
sudo hping3 -S --flood -p 80 192.168.1.1

# UDP flood
sudo hping3 -2 --flood -p 53 192.168.1.1

# Port sweep
sudo nmap -sS --top-ports 1000 192.168.1.1
```

**Expected Heimdall Response:**
- Traffic spike detected and logged
- Flood source IP flagged immediately
- Anomaly alert generated
- Rate limiting or blocking triggered

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Test 6 — DNS Reconnaissance

**Objective:** Verify Heimdall detects DNS enumeration and reconnaissance activity.

**Kali Tool:** dnsrecon / dnsenum  
**GUI App:** Zenmap

**Command Line:**
```bash
# DNS enumeration
dnsrecon -d local -t std

# DNS brute force
dnsenum 192.168.1.1

# Reverse DNS lookup sweep
nmap -sn -R 192.168.1.0/24
```

**Expected Heimdall Response:**
- DNS enumeration activity flagged
- Unusual DNS query volume detected
- Reconnaissance alert generated

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Test 7 — WiFi Network Mapping

**Objective:** Verify Heimdall detects devices performing WiFi reconnaissance on the network.

**Kali Tool:** airodump-ng / kismet  
**GUI App:** Kismet (web UI on port 2501)

**Command Line:**
```bash
# Put WiFi adapter in monitor mode
sudo airmon-ng start wlan0

# Scan for networks
sudo airodump-ng wlan0mon

# Target specific network
sudo airodump-ng -c <channel> --bssid <AP_MAC> wlan0mon

# Stop monitor mode after test
sudo airmon-ng stop wlan0mon
```

**Kismet GUI Steps:**
1. Launch `sudo kismet -c wlan0`
2. Open browser → http://localhost:2501
3. View real-time network map
4. Observe Heimdall alerts for probe requests

**Expected Heimdall Response:**
- Probe requests from Kali device detected
- Monitor mode device flagged as suspicious
- WiFi reconnaissance alert generated

**Result:** ☐ Pass &nbsp;&nbsp; ☐ Fail &nbsp;&nbsp; ☐ Partial

**Notes:** _______________________________________________

---

## Test 8 — Malicious Domain DNS Query (Zeek DNS + Threat Intel)

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

## Test 9 — C2 Beaconing Simulation (Zeek conn.log Analysis)

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

## Test 10 — Malware File Download (Zeek Extraction + ClamAV)

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

## Summary Results

| Test | Feature Tested | Result | Notes |
|------|---------------|--------|-------|
| 1 | ARP Protection | ☐ Pass ☐ Fail ☐ Partial | |
| 2 | Nmap Detection | ☐ Pass ☐ Fail ☐ Partial | |
| 3 | OpenCanary Honeypot | ☐ Pass ☐ Fail ☐ Partial | |
| 4 | Passive Fingerprinting | ☐ Pass ☐ Fail ☐ Partial | |
| 5 | Traffic Anomaly | ☐ Pass ☐ Fail ☐ Partial | |
| 6 | DNS Reconnaissance | ☐ Pass ☐ Fail ☐ Partial | |
| 7 | WiFi Mapping | ☐ Pass ☐ Fail ☐ Partial | |
| 8 | Zeek DNS / Malicious Domain | ☐ Pass ☐ Fail ☐ Partial | |
| 9 | Zeek C2 Beaconing | ☐ Pass ☐ Fail ☐ Partial | |
| 10 | ClamAV Malware Scan | ☐ Pass ☐ Fail ☐ Partial | |

---

## Kali Linux Tools Reference

| Tool | Type | Purpose | Launch Command |
|------|------|---------|---------------|
| nmap | CLI | Port scanning & OS detection | `sudo nmap` |
| Zenmap | GUI | nmap graphical frontend | `sudo zenmap` |
| Ettercap | GUI/CLI | ARP spoofing & MITM | `sudo ettercap -G` |
| bettercap | CLI | Network attacks framework | `sudo bettercap` |
| arpspoof | CLI | ARP poisoning | `sudo arpspoof` |
| Wireshark | GUI | Packet capture & analysis | `wireshark` |
| Kismet | Web UI | WiFi network mapping | `sudo kismet` |
| airodump-ng | CLI | WiFi packet capture | `sudo airodump-ng` |
| hping3 | CLI | Traffic flood testing | `sudo hping3` |
| netdiscover | CLI | Network discovery | `sudo netdiscover` |
| p0f | CLI | Passive OS fingerprinting | `sudo p0f` |
| dnsrecon | CLI | DNS enumeration | `dnsrecon` |
| Fern WiFi Cracker | GUI | WiFi security testing | `sudo fern-wifi-cracker` |
| dig | CLI | DNS lookups (Test 8) | `dig <domain>` |
| curl | CLI | HTTP requests / file downloads (Tests 8-10) | `curl` |
| EICAR test file | Test file | Safe, industry-standard synthetic malware signature (Test 10) | `curl -o eicar.com http://secure.eicar.org/eicar.com` |

---

## Legal Declaration

All tests performed on this network are authorized by the network owner. This document serves as verification evidence for Heimdall Security Guard capabilities. No unauthorized systems were targeted.

**Tester Signature:** _______________________________________________  
**Date:** _______________________________________________  
**Network:** _______________________________________________
