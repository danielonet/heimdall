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

---

## Legal Declaration

All tests performed on this network are authorized by the network owner. This document serves as verification evidence for Heimdall Security Guard capabilities. No unauthorized systems were targeted.

**Tester Signature:** _______________________________________________  
**Date:** _______________________________________________  
**Network:** _______________________________________________
