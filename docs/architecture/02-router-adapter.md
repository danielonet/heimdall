# Router Adapter

The adapter layer is the only part of Heimdall that knows anything about a
specific router. Everything else in the system — the detection pipeline, ML
engine, API, and frontend — depends only on the canonical data models defined
here.

## Abstract base class — `sentinel/adapter/base.py`

```python
from abc import ABC, abstractmethod
from typing import List
from .models import DeviceSnapshot, TrafficSample, PortStats, RouterInfo

class RouterAdapter(ABC):

    @abstractmethod
    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        """Return all currently connected LAN devices."""

    @abstractmethod
    async def get_traffic_samples(self) -> List[TrafficSample]:
        """Return per-device traffic deltas since last call."""

    @abstractmethod
    async def get_port_stats(self) -> List[PortStats]:
        """Return per-physical-port Ethernet stats (PHY1–PHY5)."""

    @abstractmethod
    async def block_device(self, mac: str) -> bool:
        """Remove this MAC's network access. Returns True on success.
        Adapter-specific mechanism — see docs/router/sagemcom-xmo-api.md's
        "Device blocking" section for why a WAN firewall rule alone isn't
        enough (it doesn't stop purely local traffic like ARP spoofing)."""

    @abstractmethod
    async def unblock_device(self, mac: str) -> bool:
        """Restore this MAC's network access."""

    @abstractmethod
    async def get_router_info(self) -> RouterInfo:
        """Return router metadata: model, firmware, uptime, WAN status."""
```

## Canonical data models — `sentinel/adapter/models.py`

```python
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Set

class TrafficGranularity(Enum):
    PER_DEVICE = 'per_device'   # WiFi: bytes measured per MAC by router
    PER_PORT   = 'per_port'     # Wired: port aggregate — NOT per device

@dataclass
class DeviceSnapshot:
    mac_address:          str
    ip_address:           str
    hostname:             str
    vendor_name:          str = ''
    interface_name:       str = ''        # 'WiFi' | 'Ethernet'
    signal_strength_dbm:  int = 0         # e.g. -59; 0 if wired
    signal_rate_mbps:     int = 0         # e.g. 130 Mbps
    is_online:            bool = True
    first_seen:           Optional[datetime] = None
    last_seen:            Optional[datetime] = None
    tags:                 Set[str] = field(default_factory=set)

@dataclass
class TrafficSample:
    mac_address:          str
    timestamp:            datetime
    bytes_sent_delta:     int = 0
    bytes_recv_delta:     int = 0
    throughput_up_kbps:   int = 0
    throughput_dn_kbps:   int = 0
    granularity:          TrafficGranularity = TrafficGranularity.PER_DEVICE
    port_alias:           Optional[str] = None   # None=WiFi, 'PHY5'=wired
    poll_interval_s:      int = 15

@dataclass
class PortStats:
    port_alias:           str             # 'PHY1' .. 'PHY5'
    timestamp:            datetime
    status:               str             # 'UP' | 'DOWN'
    link_speed_mbps:      int = 0
    bytes_sent_total:     int = 0
    bytes_recv_total:     int = 0
    sent_delta:           int = 0
    recv_delta:           int = 0
    errors_sent:          int = 0
    errors_recv:          int = 0
    discards_recv:        int = 0
    broadcast_recv:       int = 0
    last_change_secs:     int = 0

@dataclass
class RouterInfo:
    model:                str = ''
    firmware:             str = ''
    serial:               str = ''
    wan_ip:               str = ''
    wan_mac:              str = ''
    wan_status:           str = 'UNKNOWN'
    wan_mode:             str = ''        # 'PPPoE' | 'IPoE'
    uptime_seconds:       int = 0
    ssids:                list = field(default_factory=list)
```

## Sagemcom XMO authentication — `sentinel/adapter/sagemcom/xmo_auth.py`

The XMO API uses a challenge-response scheme:

1. Send a request with `session-id: 0` and empty `auth-key`
2. Router returns a `session-id`
3. Compute `auth-key = MD5( MD5(password) + ":" + cnonce )`
4. All subsequent requests include the `session-id` and computed `auth-key`
5. On error code `16777219` (auth failure) — recompute and retry

```python
import hashlib, secrets

class XmoAuth:
    def __init__(self, password: str):
        self._password = password
        self.session_id = 0
        self.request_id = 1

    def compute_auth_key(self, cnonce: int) -> str:
        pwd_hash = hashlib.md5(self._password.encode()).hexdigest()
        return hashlib.md5(f'{pwd_hash}:{cnonce}'.encode()).hexdigest()

    def build_envelope(self, actions: list) -> dict:
        cnonce = secrets.randbelow(2**31)
        env = {
            'request': {
                'id':         self.request_id,
                'session-id': self.session_id,
                'priority':   False,
                'actions':    actions,
                'cnonce':     cnonce,
                'auth-key':   self.compute_auth_key(cnonce),
            }
        }
        self.request_id += 1
        return env
```

## HTTP client — `sentinel/adapter/sagemcom/xmo_client.py`

All requests are `POST http://{router_ip}/cgi/json-req` with body:
`req=<URL-encoded JSON envelope>`

```python
import httpx, urllib.parse, json
from tenacity import retry, stop_after_attempt, wait_exponential

class XmoClient:
    def __init__(self, base_url: str, auth: XmoAuth):
        self._url  = f'{base_url}/cgi/json-req'
        self._auth = auth
        self._http = httpx.AsyncClient(timeout=10.0)

    @retry(stop=stop_after_attempt(4),
           wait=wait_exponential(multiplier=1, min=1, max=30))
    async def post(self, actions: list) -> dict:
        envelope = self._auth.build_envelope(actions)
        payload  = urllib.parse.urlencode({'req': json.dumps(envelope)})
        resp = await self._http.post(
            self._url,
            content=payload,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get('reply',{}).get('error',{}).get('code') == 16777219:
            await self.login()
            return await self.post(actions)
        return data

    async def get_value(self, xpath: str) -> dict:
        return await self.post([{'id': 0, 'method': 'getValue', 'xpath': xpath}])

    async def get_values(self, xpaths: list) -> dict:
        actions = [{'id': i, 'method': 'getValue', 'xpath': xp}
                   for i, xp in enumerate(xpaths)]
        return await self.post(actions)

    async def add_object(self, xpath: str, params: dict) -> dict:
        return await self.post([{
            'id': 0, 'method': 'addObject',
            'xpath': xpath, 'parameters': params
        }])

    async def delete_object(self, xpath: str) -> dict:
        return await self.post([{'id': 0, 'method': 'deleteObject', 'xpath': xpath}])
```

## Delta counter pattern — `sentinel/adapter/sagemcom/delta.py`

The XMO API returns **cumulative** byte counters since last router reboot.
The adapter must maintain previous-poll snapshots and compute deltas:

```python
class TrafficDeltaCalculator:
    def __init__(self):
        self._prev = {}   # mac -> (bytes_sent, bytes_recv, timestamp)

    def compute(self, mac, sent_now, recv_now, granularity) -> TrafficSample:
        prev = self._prev.get(mac)
        sent_delta = recv_delta = 0
        if prev:
            # Guard: counter reset on router reboot (value decreased)
            sent_delta = sent_now - prev[0] if sent_now >= prev[0] else sent_now
            recv_delta = recv_now - prev[1] if recv_now >= prev[1] else recv_now
        self._prev[mac] = (sent_now, recv_now, datetime.now(timezone.utc))
        interval = 15  # seconds
        return TrafficSample(
            mac_address=mac,
            timestamp=datetime.now(timezone.utc),
            bytes_sent_delta=sent_delta,
            bytes_recv_delta=recv_delta,
            throughput_up_kbps=sent_delta * 8 // 1024 // interval,
            throughput_dn_kbps=recv_delta * 8 // 1024 // interval,
            granularity=granularity,
        )
```

## Gateway auto-discovery — `sentinel/adapter/discovery.py`

The router IP is discovered at startup from the host's default route.
Never hardcode `10.100.102.1`.

```python
import subprocess, re, os

def discover_gateway_ip() -> str:
    # Strategy 1: parse default route on Linux
    try:
        out = subprocess.check_output(['ip', 'route', 'show', 'default'],
                                       text=True)
        m = re.search(r'default via ([\d.]+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    # Strategy 2: environment variable override
    env_ip = os.environ.get('ROUTER_IP', '').strip()
    if env_ip:
        return env_ip
    raise RuntimeError('Cannot determine gateway IP')
```
