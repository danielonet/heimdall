# 10. Multi-Adapter Architecture & Auto-Detection

**Document**: Heimdall Design Document v1.0  
**Topic**: Pluggable router adapter system + startup discovery engine  
**Supported adapters**: Sagemcom XMO · OpenWrt ubus · MiWiFi stok · Ubiquiti UniFi · pfSense/OPNsense · MikroTik · ASUS

---

## 1. Purpose & Scope

This document specifies two related systems:

1. **Multi-Adapter Architecture** — how Heimdall supports multiple router vendors through a pluggable adapter system, how adapters are registered, selected, and tested, and what each adapter must implement.
2. **Startup Discovery Engine** — how Heimdall automatically detects which router is present on the network at startup without requiring manual configuration, and how it falls back gracefully when detection fails.

> **Design goal**: A user should be able to run Heimdall by specifying only their router password. Everything else — router IP, router type, adapter selection — is discovered automatically.

---

## 2. Multi-Adapter Architecture

### 2.1 Directory Structure

```
sentinel/adapter/
  base.py                  # RouterAdapter abstract base class
  models.py                # Canonical DTOs (unchanged from v5)
  registry.py              # AdapterRegistry — maps IDs to classes
  discovery/
    engine.py              # StartupDiscoveryEngine — main orchestrator
    gateway.py             # GatewayScanner — finds LAN gateway IP
    fingerprinter.py       # RouterFingerprinter — identifies router type
    probes/
      base.py              # BaseProbe abstract class
      sagemcom_probe.py
      openwrt_probe.py
      miwifi_probe.py
      unifi_probe.py
      pfsense_probe.py
      mikrotik_probe.py
      asus_probe.py
  sagemcom/                # Implemented — see docs/architecture/02-router-adapter.md
  openwrt/
    ubus_adapter.py
    ubus_client.py
  miwifi/
    miwifi_adapter.py
    miwifi_client.py
  unifi/
    unifi_adapter.py
    unifi_client.py
  pfsense/
    pfsense_adapter.py
    pfsense_client.py
  mikrotik/
    mikrotik_adapter.py
    mikrotik_client.py
  asus/
    asus_adapter.py
    asus_client.py
```

### 2.2 RouterAdapter Contract — `sentinel/adapter/base.py`

Every adapter must implement this interface exactly. No method may be added, removed, or renamed. This contract must never change once published.

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List
from .models import DeviceSnapshot, TrafficSample, PortStats, RouterInfo

@dataclass
class AdapterCapabilities:
    """Declares what this adapter can and cannot do."""
    per_device_traffic:  bool   # True if bytes measured per MAC
    per_port_stats:      bool   # True if physical port stats available
    device_blocking:     bool   # True if MAC-based blocking supported
    wifi_client_details: bool   # True if RSSI / signal rate available
    wan_stats:           bool   # True if WAN-level bytes available

class RouterAdapter(ABC):

    # Unique identifier — used by registry and config
    ADAPTER_ID: str = ''

    # Human-readable name shown in the UI
    ADAPTER_NAME: str = ''

    # Default port the router API listens on
    DEFAULT_PORT: int = 80

    @classmethod
    @abstractmethod
    def capabilities(cls) -> AdapterCapabilities:
        """Return this adapter's capabilities."""

    @abstractmethod
    async def connect(self, host: str, username: str, password: str) -> bool:
        """Authenticate and establish a session. Returns True on success."""

    @abstractmethod
    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        """Return all currently connected LAN devices."""

    @abstractmethod
    async def get_traffic_samples(self) -> List[TrafficSample]:
        """Return per-device traffic deltas since last call."""

    @abstractmethod
    async def get_port_stats(self) -> List[PortStats]:
        """Return physical port statistics. Empty list if not supported."""

    @abstractmethod
    async def block_device(self, mac: str) -> bool:
        """Issue a block rule for this MAC. Returns True on success."""

    @abstractmethod
    async def unblock_device(self, mac: str) -> bool:
        """Remove block rule for this MAC. Returns True on success."""

    @abstractmethod
    async def get_router_info(self) -> RouterInfo:
        """Return router metadata: model, firmware, WAN status, uptime."""

    async def health_check(self) -> bool:
        """Optional: ping the router API."""
        try:
            info = await self.get_router_info()
            return info.wan_status != 'ERROR'
        except Exception:
            return False
```

### 2.3 Adapter Registry — `sentinel/adapter/registry.py`

Adapters self-register using a class decorator. No central list to maintain.

```python
from typing import Type, Dict
from .base import RouterAdapter

_REGISTRY: Dict[str, Type[RouterAdapter]] = {}

def register(cls: Type[RouterAdapter]) -> Type[RouterAdapter]:
    """Class decorator — registers an adapter in the global registry."""
    if not cls.ADAPTER_ID:
        raise ValueError(f'{cls.__name__} must define ADAPTER_ID')
    _REGISTRY[cls.ADAPTER_ID] = cls
    return cls

def get(adapter_id: str) -> Type[RouterAdapter]:
    if adapter_id not in _REGISTRY:
        raise KeyError(f'No adapter registered for ID: {adapter_id}')
    return _REGISTRY[adapter_id]

def all_adapters() -> Dict[str, Type[RouterAdapter]]:
    return dict(_REGISTRY)

def list_ids() -> list[str]:
    return list(_REGISTRY.keys())
```

Each adapter applies the decorator at class definition:

```python
# sentinel/adapter/sagemcom/xmo_adapter.py
from sentinel.adapter.registry import register
from sentinel.adapter.base import RouterAdapter, AdapterCapabilities

@register
class SagemcomXmoAdapter(RouterAdapter):
    ADAPTER_ID   = 'sagemcom-xmo'
    ADAPTER_NAME = 'Sagemcom F@st (XMO API)'
    DEFAULT_PORT = 80

    @classmethod
    def capabilities(cls) -> AdapterCapabilities:
        return AdapterCapabilities(
            per_device_traffic  = True,
            per_port_stats      = True,
            device_blocking     = True,
            wifi_client_details = True,
            wan_stats           = True,
        )
```

---

## 3. Adapter Specifications

### 3.1 Sagemcom F@st — `sagemcom-xmo` ✅ IMPLEMENTED

| Property | Value |
|----------|-------|
| Protocol | HTTP POST `/cgi/json-req` — XMO JSON envelope |
| Auth | `auth-key = MD5(MD5(password) + ':' + cnonce)` |
| Session | `session-id` returned on login; refresh on error code `16777219` |
| Device list | `Device/Hosts/Host` |
| Port stats | `Device/Ethernet/Interfaces/Interface[Alias='PHY{N}']/Stats/*` |
| Block device | `addObject Device/Firewall/Chain[Name='LAN_IN']/Rule` with MAC + DROP |
| WAN status | `Device/IP/Interfaces/Interface[Alias='IP_DATA']/Status` |
| Python library | `httpx` (async) + `tenacity` retry |
| Status | **IMPLEMENTED** — see `sentinel/adapter/sagemcom/` |

See `docs/router/sagemcom-xmo-api.md` for complete xpath reference.

---

### 3.2 OpenWrt ubus — `openwrt-ubus` 🔜 Priority 1

Runs on hundreds of router models (Asus, TP-Link, Netgear, GL.iNet). Widest possible audience from a single adapter.

| Property | Value |
|----------|-------|
| Protocol | HTTP POST `/ubus` — JSON-RPC 2.0 |
| Auth | Call `session/login` with username + password. Returns `ubus_rpc_session` token (32 hex chars). |
| Token usage | Pass as first element of `params` array in every subsequent call |
| Device list | `ubus call hostapd.wlan0 get_clients` + `ubus call dhcp ipv4leases` |
| Interface stats | `ubus call network.interface.lan status` |
| WiFi client details | `ubus call iwinfo wlan0 assoclist` — RSSI + TX rate per client |
| Block device | Via `iptables` exec through ubus or network firewall rules |
| Python libraries | `openwrt-ubus-rpc` (PyPI) or `python-ubus` (GitHub: rytilahti) |
| Required OpenWrt packages | `rpcd`, `uhttpd-mod-ubus`, `rpcd-mod-rpcsys` |

```python
# Authentication
POST /ubus
{
  'jsonrpc': '2.0', 'id': 1, 'method': 'call',
  'params': ['00000000000000000000000000000000',
             'session', 'login',
             {'username': 'root', 'password': 'password'}]
}
# Response: {'result': [0, {'ubus_rpc_session': 'abc123...', ...}]}

# Get WiFi clients
POST /ubus
{
  'jsonrpc': '2.0', 'id': 2, 'method': 'call',
  'params': ['abc123...', 'hostapd.wlan0', 'get_clients', {}]
}

# Get DHCP leases
POST /ubus
{
  'jsonrpc': '2.0', 'id': 3, 'method': 'call',
  'params': ['abc123...', 'dhcp', 'ipv4leases', {}]
}
```

> **Setup requirement**: The OpenWrt router must have `rpcd` and `uhttpd-mod-ubus` installed. The adapter should detect missing packages and return a clear error message.

---

### 3.3 MiWiFi (Xiaomi/Redmi) — `miwifi-stok` 🔜 Priority 2

Covers Xiaomi, Redmi, and Mi router users. The RA67 (Redmi AX5) on the test network is this type. Reference implementation: `github.com/dmamontov/hass-miwifi`.

| Property | Value |
|----------|-------|
| Protocol | HTTP GET/POST — stok token embedded in URL path |
| Auth | `POST /cgi-bin/luci/api/misystem/login` with MD5 password. Returns stok token. |
| Token usage | All calls: `GET http://ip/cgi-bin/luci/;stok={token}/api/{endpoint}` |
| Device list | `/api/misystem/devicelist` — MAC, IP, hostname, signal, real-time up/down speed |
| Router status | `/api/misystem/status` — CPU, RAM, uptime, device count |
| WAN info | `/api/xqnetwork/waninfo` — WAN IP, connection type |
| Block device | `/api/xqsystem/wifi_macfilter_info` — add MAC to block list |
| Topology | `/api/misystem/topo_graph` — which devices on which band |
| Reference | `github.com/dmamontov/hass-miwifi` — complete implementation for RA67 |

```python
# Authentication
POST http://192.168.31.1/cgi-bin/luci/api/misystem/login
Body: {'password': md5(password)}
Response: {'code': 0, 'token': 'abc123stok'}

# Get device list
GET http://ip/cgi-bin/luci/;stok=abc123/api/misystem/devicelist
Response: {'code':0, 'list':[
  {'mac':'da:d4:...', 'ip':'10.100.102.10',
   'hostname':'Redmi-Note-13', 'upload':1024, 'download':8192,
   'signal':-59, 'type':1}  # type 1=5GHz, 2=2.4GHz, 3=wired
]}
```

> **Important**: MiWiFi `devicelist` returns **real-time speed in bytes/second** (not cumulative counters). The `TrafficDeltaCalculator` is NOT needed for MiWiFi traffic samples.

---

### 3.4 Ubiquiti UniFi — `unifi-network` 🔜 Priority 3

| Property | Value |
|----------|-------|
| Protocol | HTTPS REST API — UniFi Network Application |
| Auth | `POST /api/login` with username + password. Returns cookie-based session. |
| Base URL | `https://unifi-controller:8443` (self-hosted) or `https://192.168.1.1` (UDM Pro) |
| Device list | `GET /api/s/{site}/stat/sta` — all connected clients with full stats |
| Traffic | `tx_bytes`, `rx_bytes`, `signal`, `tx_rate` in `/stat/sta` response |
| Block device | `POST /api/s/{site}/cmd/stamgr` with `cmd=block-sta` and `mac` |
| Port stats | `GET /api/s/{site}/stat/device` — port stats embedded in device response |
| Python libraries | `py-unifi` (ubiquiti-community), `unifi-controller-api` (tnware) |
| Note | UDM Pro uses `/proxy/network/api/s/{site}/...` as base path |

---

### 3.5 pfSense / OPNsense — `pfsense-rest` 🔜 Priority 4

| Property | Value |
|----------|-------|
| Protocol | HTTPS REST API (pfSense requires REST API package install; OPNsense built-in) |
| pfSense auth | API key + API secret as HTTP Basic auth headers |
| OPNsense auth | API key + API secret as HTTP Basic auth headers |
| pfSense device list | `GET /api/v2/status/arp` — ARP table with MAC, IP, interface |
| pfSense DHCP leases | `GET /api/v2/services/dhcpd/leases` |
| OPNsense device list | `GET /api/diagnostics/interface/getArp` |
| OPNsense DHCP | `GET /api/dhcpv4/leases/searchLease` |
| Block device | `POST /api/v2/firewall/rule` — add block rule by MAC |
| Swagger docs | Available at `/api/v2/documentation` on pfSense after package install |

---

### 3.6 MikroTik RouterOS — `mikrotik-rest` 🔜 Priority 5

| Property | Value |
|----------|-------|
| Protocol | HTTPS REST API (RouterOS 7.1+) OR binary API (all versions via `librouteros`) |
| Auth | HTTP Basic auth with admin username + password |
| Device list | `GET /rest/ip/arp` — IP to MAC mappings |
| DHCP leases | `GET /rest/ip/dhcp-server/lease` |
| WiFi clients | `GET /rest/interface/wireless/registration-table` |
| Interface stats | `GET /rest/interface` — bytes sent/received per interface |
| Block device | `POST /rest/ip/firewall/filter` — add drop rule by MAC source |
| Python library | `librouteros` (pip) — covers both REST and binary API |
| Minimum version | RouterOS 7.1 for REST API; `librouteros` works on v6+ |

---

### 3.7 ASUS Asuswrt / Asuswrt-Merlin — `asus-http` 🔜 Priority 6

| Property | Value |
|----------|-------|
| Protocol | HTTP — proprietary ASUS httpd endpoints |
| Auth | `POST /login.cgi` with username + password. Returns `asus_token` cookie. |
| Device list | `POST /appGet.cgi` with `hook=get_clientlist()` |
| Traffic | `POST /appGet.cgi` with `hook=netdev()` |
| WiFi clients | `POST /appGet.cgi` with `hook=wl_get_client_info()` |
| Python library | `python-aioasuswrt` (Home Assistant) — reference implementation |
| Note | Asuswrt-Merlin firmware unlocks more API endpoints |

---

## 4. Adapter Capabilities Matrix

The `AdapterCapabilities` dataclass is returned by every adapter's `capabilities()` classmethod. The detection pipeline, UI, and ML engine query this at startup to adjust behaviour.

| Capability | Sagemcom | OpenWrt | MiWiFi | UniFi | pfSense | MikroTik | ASUS |
|------------|----------|---------|--------|-------|---------|----------|------|
| Per-device traffic | ✅ Yes | ⚠ Partial | ✅ Yes | ✅ Yes | ❌ No | ⚠ Partial | ⚠ Partial |
| Per-port stats | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| Device blocking | ✅ Yes | ⚠ Partial | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ⚠ Partial |
| WiFi client RSSI | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes |
| WAN stats | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Real-time speed | ❌ No* | ❌ No* | ✅ Yes | ✅ Yes | ❌ No* | ❌ No* | ❌ No* |
| Hostname | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |

\* No* = cumulative counters only — throughput derived by delta calculator, not native.

---

## 5. Startup Discovery Engine

### 5.1 Discovery Flow

```
StartupDiscoveryEngine.run(password)
  |
  +--> Phase 1: GatewayScanner.find_candidates()
  |      Discovers all candidate gateway IPs on the LAN
  |      Returns: List[GatewayCandidate]
  |
  +--> Phase 2: RouterFingerprinter.fingerprint(ip)
  |      For each candidate IP, runs all probes in parallel
  |      Each probe returns: FingerprintResult(confidence, adapter_id, metadata)
  |      Selects highest-confidence result above threshold (0.8)
  |
  +--> Phase 3: AdapterFactory.create(fingerprint, password)
  |      Instantiates the matching adapter class
  |      Calls adapter.connect(host, username, password)
  |      Verifies with adapter.health_check()
  |
  +--> Phase 4: DiscoveryResult persisted to system_config table
         Subsequent startups use cache if < 24 hours old
```

### 5.2 Phase 1 — Gateway Scanner — `sentinel/adapter/discovery/gateway.py`

```python
import subprocess, re, socket, asyncio, os
from dataclasses import dataclass

@dataclass
class GatewayCandidate:
    ip:         str
    source:     str    # 'default_route' | 'common_ip' | 'arp_table' | 'env_override'
    confidence: float

class GatewayScanner:

    COMMON_GATEWAY_IPS = [
        '192.168.1.1',    # TP-Link, Asus, Netgear default
        '192.168.0.1',    # Linksys, D-Link default
        '192.168.31.1',   # Xiaomi MiWiFi default
        '10.0.0.1',       # Apple AirPort, some ISP routers
    ]

    async def find_candidates(self) -> list[GatewayCandidate]:
        candidates = []

        # Strategy 1: Environment override (highest priority)
        env_ip = os.environ.get('ROUTER_IP', '').strip()
        if env_ip:
            return [GatewayCandidate(env_ip, 'env_override', 1.0)]

        # Strategy 2: Parse default route from kernel routing table
        route_ip = self._parse_default_route()
        if route_ip:
            candidates.append(GatewayCandidate(route_ip, 'default_route', 0.95))

        # Strategy 3: Scan ARP table for .1 addresses
        for ip in self._scan_arp_table():
            if ip not in [c.ip for c in candidates]:
                candidates.append(GatewayCandidate(ip, 'arp_table', 0.7))

        # Strategy 4: Try well-known gateway IPs (parallel ping)
        for ip in await self._ping_candidates(self.COMMON_GATEWAY_IPS):
            if ip not in [c.ip for c in candidates]:
                candidates.append(GatewayCandidate(ip, 'common_ip', 0.5))

        return sorted(candidates, key=lambda c: c.confidence, reverse=True)

    def _parse_default_route(self) -> str | None:
        try:
            out = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
            m = re.search(r'default via ([\d.]+)', out)
            return m.group(1) if m else None
        except Exception:
            return None

    def _scan_arp_table(self) -> list[str]:
        try:
            out = subprocess.check_output(['arp', '-n'], text=True)
            ips = re.findall(r'([\d.]+)', out)
            return [ip for ip in ips if ip.endswith('.1')]
        except Exception:
            return []

    async def _ping_candidates(self, ips: list) -> list[str]:
        results = await asyncio.gather(*[self._is_reachable(ip) for ip in ips])
        return [ip for ip, ok in zip(ips, results) if ok]

    async def _is_reachable(self, ip: str, port: int = 80) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=1.5
            )
            writer.close()
            return True
        except Exception:
            return False
```

### 5.3 Phase 2 — Router Fingerprinter — `sentinel/adapter/discovery/fingerprinter.py`

```python
from dataclasses import dataclass, field
from typing import Optional
import asyncio, logging

log = logging.getLogger(__name__)

@dataclass
class FingerprintResult:
    adapter_id:  str
    host:        str
    confidence:  float          # 0.0 - 1.0
    metadata:    dict = field(default_factory=dict)

class RouterFingerprinter:

    def __init__(self, probes: list):
        self._probes = probes

    async def fingerprint(self, host: str,
                           timeout: float = 5.0) -> Optional[FingerprintResult]:
        """Run all probes in parallel. Return best match above 0.8 confidence."""
        tasks = [probe.probe(host, timeout=timeout) for probe in self._probes]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid = [r for r in results
                 if isinstance(r, FingerprintResult) and r.confidence >= 0.8]

        if not valid:
            return None

        best = max(valid, key=lambda r: r.confidence)
        log.info('Fingerprinted %s as %s (%.0f%% confidence)',
                 host, best.adapter_id, best.confidence * 100)
        return best
```

### 5.4 Probe Base Class — `sentinel/adapter/discovery/probes/base.py`

```python
from abc import ABC, abstractmethod
from typing import Optional
import httpx
from ..fingerprinter import FingerprintResult

class BaseProbe(ABC):

    ADAPTER_ID: str = ''
    MATCH_CONFIDENCE: float = 0.95

    @abstractmethod
    async def probe(self, host: str, timeout: float = 5.0) -> Optional[FingerprintResult]:
        """
        Identify if host is this adapter's router type.
        Return FingerprintResult on match, None on no match.
        Must NEVER raise exceptions — catch all and return None.
        """

    async def _get(self, url: str, timeout: float = 5.0) -> httpx.Response | None:
        try:
            async with httpx.AsyncClient(verify=False) as client:
                return await client.get(url, timeout=timeout)
        except Exception:
            return None

    async def _post(self, url: str, json: dict,
                    timeout: float = 5.0) -> httpx.Response | None:
        try:
            async with httpx.AsyncClient(verify=False) as client:
                return await client.post(url, json=json, timeout=timeout)
        except Exception:
            return None
```

### 5.5 Probe Implementations

#### Sagemcom Probe — `sentinel/adapter/discovery/probes/sagemcom_probe.py`

```python
import json, urllib.parse
from .base import BaseProbe
from ..fingerprinter import FingerprintResult

class SagemcomProbe(BaseProbe):
    ADAPTER_ID = 'sagemcom-xmo'

    async def probe(self, host, timeout=5.0):
        # Send unauthenticated XMO request — Sagemcom always returns 'reply' with 'XMO' error
        payload = json.dumps({'request': {
            'id': 1, 'session-id': 0, 'priority': False,
            'actions': [{'id': 0, 'method': 'getValue', 'xpath': 'Device/DeviceInfo'}],
            'cnonce': 12345, 'auth-key': ''
        }})
        try:
            async with __import__('httpx').AsyncClient() as c:
                resp = await c.post(
                    f'http://{host}/cgi/json-req',
                    content=urllib.parse.urlencode({'req': payload}),
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=timeout
                )
            data = resp.json()
            if 'reply' in data:
                error_desc = data['reply'].get('error', {}).get('description', '')
                if 'XMO' in error_desc:
                    return FingerprintResult(
                        adapter_id='sagemcom-xmo',
                        host=host,
                        confidence=0.97,
                        metadata={'xmo_error': error_desc}
                    )
        except Exception:
            pass
        return None
```

#### OpenWrt Probe — `sentinel/adapter/discovery/probes/openwrt_probe.py`

```python
from .base import BaseProbe
from ..fingerprinter import FingerprintResult

class OpenWrtProbe(BaseProbe):
    ADAPTER_ID = 'openwrt-ubus'

    async def probe(self, host, timeout=5.0):
        resp = await self._post(f'http://{host}/ubus', json={
            'jsonrpc': '2.0', 'id': 1, 'method': 'call',
            'params': ['00000000000000000000000000000000',
                       'session', 'login', {'username': 'root', 'password': ''}]
        }, timeout=timeout)
        if resp is None:
            return None
        try:
            data = resp.json()
            if data.get('jsonrpc') == '2.0' and 'result' in data:
                result_code = data['result'][0] if data['result'] else None
                if result_code in (0, 6):  # 0=success, 6=access denied (still ubus)
                    luci = await self._get(f'http://{host}/cgi-bin/luci', timeout=2.0)
                    if luci and luci.status_code in (200, 302):
                        return FingerprintResult(
                            adapter_id='openwrt-ubus', host=host, confidence=0.95
                        )
        except Exception:
            pass
        return None
```

#### MiWiFi Probe — `sentinel/adapter/discovery/probes/miwifi_probe.py`

```python
from .base import BaseProbe
from ..fingerprinter import FingerprintResult

class MiWiFiProbe(BaseProbe):
    ADAPTER_ID = 'miwifi-stok'

    async def probe(self, host, timeout=5.0):
        resp = await self._post(
            f'http://{host}/cgi-bin/luci/api/misystem/login',
            json={'password': ''},
            timeout=timeout
        )
        if resp is None:
            return None
        try:
            data = resp.json()
            # MiWiFi returns {'code': N} — unique structure
            if 'code' in data and 'jsonrpc' not in data and 'reply' not in data:
                return FingerprintResult(
                    adapter_id='miwifi-stok', host=host, confidence=0.93
                )
        except Exception:
            pass
        return None
```

#### MikroTik Probe — `sentinel/adapter/discovery/probes/mikrotik_probe.py`

```python
from .base import BaseProbe
from ..fingerprinter import FingerprintResult

class MikroTikProbe(BaseProbe):
    ADAPTER_ID = 'mikrotik-rest'

    async def probe(self, host, timeout=5.0):
        resp = await self._get(f'http://{host}/rest', timeout=timeout)
        if resp is None:
            return None
        if resp.status_code == 401:
            body = resp.text.lower()
            if 'unauthorized' in body or 'mikrotik' in body:
                return FingerprintResult(
                    adapter_id='mikrotik-rest', host=host, confidence=0.90
                )
        return None
```

### 5.6 Full Discovery Engine — `sentinel/adapter/discovery/engine.py`

```python
from dataclasses import dataclass
from typing import Optional
import asyncio, logging
from .gateway      import GatewayScanner
from .fingerprinter import RouterFingerprinter, FingerprintResult
from .probes.sagemcom_probe import SagemcomProbe
from .probes.openwrt_probe  import OpenWrtProbe
from .probes.miwifi_probe   import MiWiFiProbe
from .probes.unifi_probe    import UniFiProbe
from .probes.pfsense_probe  import PfSenseProbe
from .probes.mikrotik_probe import MikroTikProbe
from .probes.asus_probe     import AsusProbe
from sentinel.adapter.registry import get as get_adapter

log = logging.getLogger(__name__)

@dataclass
class DiscoveryResult:
    adapter:          'RouterAdapter'
    adapter_id:       str
    host:             str
    router_info:      'RouterInfo'
    confidence:       float
    discovery_method: str   # 'auto' | 'env_override' | 'config_cache'

ALL_PROBES = [
    SagemcomProbe(), OpenWrtProbe(), MiWiFiProbe(),
    UniFiProbe(), PfSenseProbe(), MikroTikProbe(), AsusProbe(),
]

class StartupDiscoveryEngine:

    def __init__(self, settings):
        self._settings      = settings
        self._scanner       = GatewayScanner()
        self._fingerprinter = RouterFingerprinter(ALL_PROBES)

    async def run(self) -> DiscoveryResult:
        log.info('Starting router discovery...')

        # Fast path: check config cache (< 24 hours old)
        cached = await self._load_cache()
        if cached:
            log.info('Using cached discovery: %s at %s', cached.adapter_id, cached.host)
            return cached

        # Phase 1: Find gateway candidates
        candidates = await self._scanner.find_candidates()
        if not candidates:
            raise RuntimeError('Cannot find any gateway IP on LAN')

        # Phase 2 + 3: Fingerprint and connect
        for candidate in candidates:
            fingerprint = await self._fingerprinter.fingerprint(candidate.ip)
            if fingerprint is None:
                continue

            adapter = await self._create_adapter(fingerprint)
            if adapter is None:
                continue

            router_info = await adapter.get_router_info()
            result = DiscoveryResult(
                adapter=adapter,
                adapter_id=fingerprint.adapter_id,
                host=fingerprint.host,
                router_info=router_info,
                confidence=fingerprint.confidence,
                discovery_method='auto',
            )
            await self._save_cache(result)
            log.info('Discovery complete: %s at %s', fingerprint.adapter_id, fingerprint.host)
            return result

        raise RuntimeError(
            'Router discovery failed: no supported router found. '
            'Set ROUTER_IP and ROUTER_ADAPTER in .env to configure manually.'
        )

    async def _create_adapter(self, fingerprint: FingerprintResult):
        AdapterClass = get_adapter(fingerprint.adapter_id)
        adapter = AdapterClass()
        connected = await adapter.connect(
            host=fingerprint.host,
            username=self._settings.ROUTER_USERNAME,
            password=self._settings.ROUTER_PASSWORD,
        )
        if not connected:
            return None
        if not await adapter.health_check():
            return None
        return adapter
```

---

## 6. Complete Application Startup Sequence

```
Docker container starts
  |
  +--> sentinel/main.py: run()
       |
       +--> Step 1: Load configuration
       |     Settings.load()  -- reads .env + Docker secrets
       |     Validates: ROUTER_PASSWORD must be set
       |
       +--> Step 2: Database initialisation
       |     Wait for PostgreSQL (retry 30s max)
       |     alembic upgrade head
       |
       +--> Step 3: Redis health check
       |     Wait for Redis (retry 10s max)
       |
       +--> Step 4: Router Discovery
       |     StartupDiscoveryEngine.run()
       |       --> GatewayScanner.find_candidates()        ~1–2s
       |       --> RouterFingerprinter.fingerprint()        ~2–5s
       |       --> AdapterFactory.create()                  ~1–3s
       |       --> adapter.health_check()                   ~1s
       |     On success: adapter registered in app context
       |     On failure: start in DEGRADED mode
       |
       +--> Step 5: Security services
       |     ArpWatcher.start()           -- daemon thread
       |     PassiveFingerprinter.start() -- daemon thread
       |     ThreatIntelService.refresh_feeds()
       |
       +--> Step 6: ML Engine warm-up
       |     ModelStore.load_all()
       |
       +--> Step 7: Scheduler start
       |     APScheduler.start()
       |     Register: poll_cycle()     every 15s
       |     Register: ml_retrain()     daily 03:00
       |     Register: nmap_scan()      daily 02:00
       |     Register: feed_refresh()   every 6h
       |     Fire: poll_cycle() immediately
       |
       +--> Step 8: Flask + SocketIO start
             gunicorn binds to 0.0.0.0:5000
             emit 'system:ready' via SocketIO
             Log: 'Heimdall ready. Adapter: {adapter_id} at {host}'
```

### Degraded Mode

If discovery fails, Heimdall starts without polling rather than crashing:

- Flask API starts normally — dashboard accessible at `http://localhost:3000`
- `GET /api/health` returns `{'status': 'degraded', 'reason': '...'}`
- `POST /api/discover` triggers manual re-discovery
- `POST /api/router/configure` allows manual adapter selection
- No polling until a working adapter is configured
- ArpWatcher and PassiveFingerprinter still run

### Discovery Cache

```sql
CREATE TABLE system_config (
    key        VARCHAR(100) PRIMARY KEY,
    value      JSONB        NOT NULL,
    updated_at TIMESTAMPTZ  DEFAULT now()
);

-- Cache expires after 24 hours (configurable via DISCOVERY_CACHE_TTL_H)
-- Force re-discovery: POST /api/discover
-- Or: DELETE FROM system_config WHERE key = 'last_discovery';
```

---

## 7. Configuration Reference

| Environment Variable | Description & Default |
|----------------------|-----------------------|
| `ROUTER_PASSWORD` | **REQUIRED**. Router admin password. Load from Docker secret. |
| `ROUTER_USERNAME` | Router admin username. Default: `admin`. OpenWrt uses `root`. |
| `ROUTER_IP` | Optional override. Skips gateway discovery entirely. |
| `ROUTER_ADAPTER` | Optional override. Skips fingerprinting. Must match registered `ADAPTER_ID`. |
| `ROUTER_PORT` | Optional port override. Default: `80`. Use `8443` for UniFi, `443` for pfSense. |
| `DISCOVERY_TIMEOUT_S` | Seconds per probe during fingerprinting. Default: `5`. |
| `DISCOVERY_CACHE_TTL_H` | Hours before discovery cache expires. Default: `24`. |
| `POLL_INTERVAL_SECONDS` | Adapter poll cycle interval. Default: `15`. |

### Configuration Examples

**Auto-discover (recommended — minimal config)**:
```env
ROUTER_PASSWORD=mypassword
```

**Force a specific adapter**:
```env
ROUTER_IP=10.100.102.1
ROUTER_ADAPTER=sagemcom-xmo
ROUTER_USERNAME=admin
ROUTER_PASSWORD=mypassword
```

**OpenWrt with non-default IP**:
```env
ROUTER_IP=192.168.1.1
ROUTER_ADAPTER=openwrt-ubus
ROUTER_USERNAME=root
ROUTER_PASSWORD=mypassword
```

---

## 8. Contributor Guide — Adding a New Adapter

### Required Files

```
sentinel/adapter/{vendor}/
  __init__.py
  {vendor}_adapter.py      # implements RouterAdapter
  {vendor}_client.py       # low-level HTTP client

sentinel/adapter/discovery/probes/
  {vendor}_probe.py        # implements BaseProbe

tests/adapter/
  test_{vendor}_adapter.py
  test_{vendor}_probe.py

docs/adapters/
  {vendor}.md              # documentation
```

### Step-by-Step

1. **Adapter class** — Create `{vendor}_adapter.py`. Apply `@register` decorator. Set `ADAPTER_ID`, `ADAPTER_NAME`, `DEFAULT_PORT`. Implement all 7 abstract methods. Implement `capabilities()`.

2. **HTTP client** — Create `{vendor}_client.py`. Handle auth lifecycle. All HTTP calls async via `httpx.AsyncClient`. Wrap in `tenacity` retry.

3. **Discovery probe** — Create `{vendor}_probe.py`. Implement `probe(host, timeout)`. Make a single lightweight unauthenticated HTTP request. Return `FingerprintResult` with confidence >= 0.8 only when certain. Never raise exceptions.

4. **Register probe** — Add to `ALL_PROBES` in `sentinel/adapter/discovery/engine.py`.

5. **Register adapter** — Add import to `sentinel/adapter/__init__.py` so `@register` fires at import time.

6. **Tests** — Mock HTTP responses using `pytest-httpx`. Test happy path, auth failure, connection timeout, counter-reset.

7. **Documentation** — Create `docs/adapters/{vendor}.md` with: tested router models, confirmed firmware versions, any setup steps required on the router.

### PR Acceptance Checklist

- [ ] `@register` decorator applied
- [ ] All 7 abstract methods implemented
- [ ] `capabilities()` accurately reflects what the router provides
- [ ] Probe correctly identifies router without credentials
- [ ] Unit tests pass
- [ ] `docs/adapters/{vendor}.md` exists with tested models listed

---

## 9. API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/router` | Active adapter info: adapter_id, host, model, firmware, WAN status, capabilities |
| `GET /api/router/adapters` | All registered adapters with ADAPTER_ID, ADAPTER_NAME, capabilities |
| `POST /api/discover` | Trigger manual re-discovery. Runs full gateway scan + fingerprint + connect. |
| `POST /api/router/configure` | Manually set adapter: `{adapter_id, host, username, password}`. Validates via health_check(). |
| `GET /api/router/health` | Adapter health check: `{healthy, latency_ms, last_poll, adapter_id}` |
| `GET /api/router/capabilities` | `AdapterCapabilities` for active adapter. Used by frontend to show/hide features. |
| `POST /api/router/rediscover` | Clear discovery cache and force full re-discovery on next startup. |

---

## 10. Testing Strategy

### Unit Testing with Mocked HTTP

```python
# tests/adapter/test_sagemcom_adapter.py
import pytest
from unittest.mock import AsyncMock, patch
from sentinel.adapter.sagemcom.xmo_adapter import SagemcomXmoAdapter

MOCK_HOSTS_RESPONSE = {
    'reply': {
        'uid': 0, 'id': 1,
        'error': {'code': 16777239, 'description': 'XMO_NO_ERR'},
        'actions': [{'uid': 1, 'callbacks': [{'result': {'code': 16777239},
            'parameters': {'value': {'Host': [
                {'PhysAddress': 'da:d4:19:31:c0:e9',
                 'IPAddress': '10.100.102.10',
                 'HostName': 'Redmi-Note-13-Pro-5G',
                 'InterfaceType': 'WiFi',
                 'Active': True,
                 'X_SAGEMCOM_SignalStrength': -59,
                 'X_SAGEMCOM_RxRate': 130,
                 'BytesSent': 1000000,
                 'BytesReceived': 5000000}
            ]}}}]}]
    }
}

@pytest.mark.asyncio
async def test_get_connected_devices():
    adapter = SagemcomXmoAdapter()
    with patch.object(adapter._client, 'get_value',
                      new=AsyncMock(return_value=MOCK_HOSTS_RESPONSE)):
        devices = await adapter.get_connected_devices()
    assert len(devices) == 1
    assert devices[0].mac_address == 'da:d4:19:31:c0:e9'
    assert devices[0].signal_strength_dbm == -59
```

### Probe Testing

```python
# tests/adapter/test_sagemcom_probe.py
import pytest
from pytest_httpx import HTTPXMock
from sentinel.adapter.discovery.probes.sagemcom_probe import SagemcomProbe

@pytest.mark.asyncio
async def test_sagemcom_probe_matches(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url='http://10.100.102.1/cgi/json-req',
        json={'reply': {'uid':0,'error':{'code':16777219,
                        'description':'XMO_REQUEST_AUTHENTICATION_ERR'}}}
    )
    result = await SagemcomProbe().probe('10.100.102.1')
    assert result is not None
    assert result.adapter_id == 'sagemcom-xmo'
    assert result.confidence >= 0.8

@pytest.mark.asyncio
async def test_sagemcom_probe_no_match(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url='http://192.168.1.1/cgi/json-req', status_code=404)
    result = await SagemcomProbe().probe('192.168.1.1')
    assert result is None
```

---

## 11. Discovery Timing & Performance

| Phase | Typical Duration | Worst Case |
|-------|-----------------|------------|
| Gateway scan (default route) | < 100ms | 500ms |
| Gateway scan (common IPs ping) | 1–2s | 5s |
| Single probe (match) | 200–500ms | 5s |
| All 7 probes in parallel | 500ms–1s | 5s |
| Adapter connect + health check | 500ms–2s | 10s |
| **Total (cache hit)** | **< 200ms** | **1s** |
| **Total (cache miss, found)** | **3–8s** | **20s** |
| **Total (cache miss, not found)** | **15–30s** | **60s** |

> Discovery runs asynchronously and does not block Flask from starting. A `system:discovering` WebSocket event is emitted when discovery starts, and `system:ready` or `system:degraded` when it completes.

---

## 12. Future Extension — Multi-Router Support

Multi-router support (monitoring both Sagemcom + Redmi AX5 simultaneously) is out of scope for v1.0. When implementing in v2.0, the only change needed to canonical data models:

```python
# Add to DeviceSnapshot:
adapter_id:   str   # which router reported this device
adapter_host: str   # which router IP

# Add to TrafficSample:
adapter_id:   str

# Discovery engine becomes:
class MultiAdapterDiscoveryEngine:
    async def run(self) -> list[DiscoveryResult]:
        # Returns ALL discovered routers, not just the first
```

Deduplication when two adapters report the same MAC:
- WiFi adapter with `per_device_traffic=True` wins for traffic data
- Blocking issued to the adapter where the device is currently connected
- Both adapters' device lists merged into unified registry with a `sources` field
