# Security Services

All security service modules live in `sentinel/security/`.

## ARP spoof watcher — `sentinel/security/arp_watch.py`

Scapy sniffs ARP reply packets on the LAN interface in a daemon thread.
Each reply is compared against the known MAC→IP table in PostgreSQL.
A MAC change for a known IP fires an immediate CRITICAL alert.

**Requires**: `NET_RAW` Docker capability (already granted to `sentinel-backend`).

```python
from scapy.all import ARP, sniff
import threading, logging

log = logging.getLogger(__name__)

class ArpWatcher:
    def __init__(self, alert_callback, iface: str = 'eth0'):
        self._callback = alert_callback
        self._iface    = iface
        self._table    = {}    # ip -> mac (populated from DB on start)

    def start(self):
        threading.Thread(target=self._sniff, daemon=True).start()

    def seed(self, ip_mac_pairs: list[tuple]):
        """Pre-populate table from device registry on startup."""
        for ip, mac in ip_mac_pairs:
            self._table[ip] = mac.lower()

    def _sniff(self):
        sniff(filter='arp', prn=self._process,
              iface=self._iface, store=False)

    def _process(self, pkt):
        if pkt[ARP].op != 2:   # op=2 = ARP reply
            return
        ip  = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc.lower()
        known = self._table.get(ip)
        if known and known != mac:
            log.critical('ARP SPOOF: %s was %s now %s', ip, known, mac)
            self._callback({
                'type': 'ARP_SPOOF', 'severity': 'CRITICAL',
                'ip': ip, 'old_mac': known, 'new_mac': mac,
                'description': f'ARP spoofing: {ip} changed from {known} to {mac}',
            })
        self._table[ip] = mac
```

## Passive OS fingerprinting — `sentinel/security/fingerprint.py`

Identifies device OS from TCP SYN packet characteristics (TTL, window size,
TCP options) without active scanning. Runs in a daemon thread alongside the
ARP watcher.

```python
from scapy.all import IP, TCP, sniff
import threading

OS_SIGNATURES = {
    (64,  65535): 'Linux / Android',
    (128, 65535): 'Windows',
    (64,  65536): 'macOS / iOS',
}

class PassiveFingerprinter:
    def __init__(self, on_fingerprint, iface: str = 'eth0'):
        self._callback = on_fingerprint
        self._iface    = iface
        self._seen     = set()

    def start(self):
        threading.Thread(target=self._sniff, daemon=True).start()

    def _sniff(self):
        sniff(filter='tcp[tcpflags] & tcp-syn != 0',
              prn=self._process, iface=self._iface, store=False)

    def _process(self, pkt):
        if IP not in pkt or TCP not in pkt:
            return
        src_ip = pkt[IP].src
        if src_ip in self._seen:
            return
        ttl = pkt[IP].ttl
        win = pkt[TCP].window
        os_guess = OS_SIGNATURES.get((ttl, win), 'Unknown')
        self._seen.add(src_ip)
        self._callback(src_ip, os_guess)
```

## Network scanner — `sentinel/security/scanner.py`

Wraps python-nmap for OS fingerprinting, service detection, and NSE
vulnerability scripts. Runs on a nightly APScheduler job (02:00 by default)
and on-demand from the device detail API endpoint.

```python
import nmap
from dataclasses import dataclass

@dataclass
class OpenPort:
    port: int
    protocol: str
    service: str
    version: str
    state: str

class NetworkScanner:
    def __init__(self):
        self._nm = nmap.PortScanner()

    async def scan_device(self, ip: str) -> dict:
        """OS detection + service version scan."""
        self._nm.scan(ip, arguments='-O -sV --version-intensity 5')
        host  = self._nm[ip]
        ports = [
            OpenPort(port=p, protocol=proto,
                     service=host[proto][p].get('name', ''),
                     version=host[proto][p].get('version', ''),
                     state=host[proto][p].get('state', ''))
            for proto in host.all_protocols()
            for p in host[proto]
        ]
        os_match = host.get('osmatch', [{}])[0].get('name', 'Unknown')
        return {'ip': ip, 'os': os_match, 'ports': ports}

    async def vuln_scan(self, ip: str) -> dict:
        """NSE vulnerability scripts."""
        self._nm.scan(ip, arguments='--script vuln')
        return self._nm[ip].get('script', {})
```

## Threat intelligence — `sentinel/security/threat_intel.py`

Downloads, caches, and queries multiple open-source threat feeds plus OTX.

```python
from OTXv2 import OTXv2
import httpx

class ThreatIntelService:
    def __init__(self, otx_api_key: str):
        self._otx      = OTXv2(otx_api_key)
        self._ip_block: set[str] = set()
        self._domains:  set[str] = set()

    async def refresh_feeds(self):
        feeds = {
            'feodo':     'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
            'tor_exits': 'https://check.torproject.org/torbulkexitlist',
            'spamhaus':  'https://www.spamhaus.org/drop/drop.txt',
            'urlhaus':   'https://urlhaus.abuse.ch/downloads/csv/',
        }
        async with httpx.AsyncClient(timeout=30) as client:
            for name, url in feeds.items():
                resp = await client.get(url)
                self._parse_feed(name, resp.text)

    def lookup_ip(self, ip: str) -> dict:
        in_feed = ip in self._ip_block
        try:
            result = self._otx.get_indicator_details_full('IPv4', ip)
            pulses = len(result.get('general', {})
                         .get('pulse_info', {}).get('pulses', []))
        except Exception:
            pulses = 0
        return {
            'ip': ip,
            'in_blocklist': in_feed,
            'otx_pulses': pulses,
            'is_malicious': in_feed or pulses > 0,
        }

    def is_domain_malicious(self, domain: str) -> bool:
        return domain.lower() in self._domains
```

## Threat feeds reference

| Feed | URL | Data |
|------|-----|------|
| AbuseIPDB | REST API (free tier) | IP reputation scores |
| Feodo Tracker | feodotracker.abuse.ch | Botnet C2 IP blocklist |
| Tor Exit Nodes | check.torproject.org | Full Tor exit node list |
| Spamhaus DROP | spamhaus.org/drop | Hijacked netblocks |
| URLhaus | urlhaus.abuse.ch | Malware distribution URLs |
| AlienVault OTX | OTXv2 Python SDK | Structured threat intel pulses |
| StevenBlack Hosts | raw GitHub | Ads + malware domains (Pi-hole) |
| Phishing Army | phishing.army | Phishing domain list (Pi-hole) |

## Zeek log parser — `sentinel/security/zeek_parser.py`

Parses Zeek `conn.log` and `dns.log` files using pandas for high-throughput
ingestion. Zeek writes JSON logs by default when configured with
`LogAscii::use_json = T`.

```python
import pandas as pd
from pathlib import Path

ZEEK_LOG_DIR = Path('/var/log/zeek/current')

class ZeekParser:

    def parse_conn_log(self) -> pd.DataFrame:
        path = ZEEK_LOG_DIR / 'conn.log'
        return pd.read_json(path, lines=True)

    def detect_beaconing(self, df: pd.DataFrame,
                          min_count: int = 10,
                          jitter_tolerance_s: float = 2.0) -> list[dict]:
        """Flag connections with suspiciously regular intervals (C2 beaconing)."""
        suspicious = []
        for (src, dst), group in df.groupby(['id.orig_h', 'id.resp_h']):
            if len(group) < min_count:
                continue
            intervals = group['ts'].sort_values().diff().dropna()
            if intervals.std() < jitter_tolerance_s:
                suspicious.append({
                    'src': src, 'dst': dst,
                    'count': len(group),
                    'interval_mean_s': round(intervals.mean(), 2),
                    'interval_std_s':  round(intervals.std(),  2),
                })
        return suspicious
```

## ClamAV integration

ClamAV runs as a separate container (port 3310). Files captured from HTTP
sessions by Zeek can be scanned via the `pyclamd` library.

```python
import pyclamd

class ClamAvScanner:
    def __init__(self, host='clamav', port=3310):
        self._cd = pyclamd.ClamdNetworkSocket(host, port)

    def scan_bytes(self, data: bytes) -> dict | None:
        """Returns None if clean, dict with virus name if infected."""
        result = self._cd.scan_stream(data)
        return result
```

## OpenCanary alert ingestion — `sentinel/security/canary.py`

OpenCanary writes alerts to syslog. The backend tails the syslog socket or
reads from a shared log volume.

```python
import json, logging

log = logging.getLogger(__name__)

class OpenCanaryIngester:
    """Reads OpenCanary JSON alerts and converts to Heimdall Alert objects."""

    def parse_event(self, raw: str) -> dict | None:
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if event.get('logtype') not in (1000, 2000, 3000, 4000):
            return None
        return {
            'type':        'HONEYPOT_ACCESS',
            'severity':    'CRITICAL',
            'source_ip':   event.get('src_host'),
            'service':     event.get('logdata', {}).get('SERVICE', 'unknown'),
            'description': (
                f'Honeypot connection from {event.get("src_host")} '
                f'to {event.get("dst_host")} '
                f'service {event.get("logdata",{}).get("SERVICE","?")}'
            ),
        }
```
