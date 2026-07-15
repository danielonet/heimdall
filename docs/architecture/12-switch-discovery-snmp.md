# 11. Managed Switch Discovery & SNMP Integration

**Document**: Heimdall Design Document v1.0  
**Topic**: LLDP auto-detection · SNMP BRIDGE-MIB · Per-device wired traffic · Port map UI · Settings tab  

> **Resolves**: The `PER_PORT` wired monitoring caveat documented in `docs/router/wired-monitoring-caveat.md`

---

## 1. Purpose & Scope

Heimdall v3.0 documented a fundamental limitation: wired devices connected through a downstream switch share a single port-level traffic counter on the router. Both the Akuvox-R20K intercom and the Ringslink device on Port 5 (PHY5) of the Sagemcom F@st 5670 are invisible as individuals.

**Managed switches solve this completely.** Every managed switch supports SNMP and broadcasts LLDP frames. The SNMP `BRIDGE-MIB` contains a MAC address forwarding table that maps every connected device to its exact physical port. Combined with per-port `IF-MIB` traffic counters, Heimdall achieves full per-device wired monitoring equal to WiFi monitoring.

This document specifies:
1. The protocols and MIBs used to discover and query managed switches
2. The `SwitchMonitor` architecture — how switch data integrates without changing any existing adapter or detection code
3. The Settings tab UI additions

> When a managed switch is present, `TrafficGranularity.PER_PORT` upgrades to `TrafficGranularity.PER_DEVICE`. The PORT TOTAL badge disappears from the UI.

---

## 2. Protocols

### 2.1 SNMP — Simple Network Management Protocol

SNMP exposes management data in Management Information Bases (MIBs) over UDP port 161. Every managed switch from every vendor supports it.

- **Version**: Use v2c by default (most common). v3 available for security-conscious users.
- **Community string**: Default on almost every switch is `public` (read-only). No write access needed.
- **Read-only**: Heimdall never needs write access to switches via SNMP.

### 2.2 The Three Critical MIBs

#### BRIDGE-MIB (RFC 4188) — MAC-to-Port Mapping

This is the jackpot MIB. It contains the MAC address forwarding table — which device is on which physical port.

| OID | Name | Data |
|-----|------|------|
| `1.3.6.1.2.1.17.4.3.1.1` | `dot1dTpFdbAddress` | MAC addresses in forwarding table (one per row) |
| `1.3.6.1.2.1.17.4.3.1.2` | `dot1dTpFdbPort` | Port number where each MAC was learned |
| `1.3.6.1.2.1.17.4.3.1.3` | `dot1dTpFdbStatus` | Entry type: 3=learned (dynamic), 4=self, 5=mgmt |
| `1.3.6.1.2.1.17.1.4.1.2` | `dot1dBasePortIfIndex` | Maps bridge port number → IF-MIB ifIndex |

```
# Result of walking dot1dTpFdbPort on an 8-port switch:
#
# OID suffix encodes the MAC address as decimal octets:
# 1.3.6.1.2.1.17.4.3.1.2.218.212.25.52.233.26 = port 3
#   -> MAC: DA:D4:19:31:C0:E9 (Redmi-Note-13-Pro-5G) is on port 3
# 1.3.6.1.2.1.17.4.3.1.2.12.17.5.28.67.93   = port 1
#   -> MAC: 0C:11:05:A6:B6:18 (Ringslink device) is on port 1
# 1.3.6.1.2.1.17.4.3.1.2.12.17.5.26.149.29  = port 2
#   -> MAC: 0C:11:05:61:AD:5B (Akuvox-R20K) is on port 2
#
# Heimdall now knows EXACTLY which device is on which port.
# PER_PORT caveat is resolved.
```

#### IF-MIB (RFC 2863) — Per-Port Interface Statistics

| OID | Name | Data |
|-----|------|------|
| `1.3.6.1.2.1.2.2.1.1` | `ifIndex` | Interface index (links to BRIDGE-MIB via `dot1dBasePortIfIndex`) |
| `1.3.6.1.2.1.2.2.1.2` | `ifDescr` | Port name: `GigabitEthernet1`, `Port 1` |
| `1.3.6.1.2.1.2.2.1.5` | `ifSpeed` | Link speed in bps (1000000000 = 1 Gbps) |
| `1.3.6.1.2.1.2.2.1.8` | `ifOperStatus` | 1=up, 2=down |
| `1.3.6.1.2.1.2.2.1.10` | `ifInOctets` | Bytes received (32-bit, wraps at 4 GB) |
| `1.3.6.1.2.1.2.2.1.16` | `ifOutOctets` | Bytes sent (32-bit) |
| `1.3.6.1.2.1.2.2.1.14` | `ifInErrors` | Receive errors |
| `1.3.6.1.2.1.2.2.1.13` | `ifInDiscards` | Dropped incoming packets |
| `1.3.6.1.2.1.31.1.1.1.6` | `ifHCInOctets` | **64-bit** bytes received — use this for Gigabit+ ports |
| `1.3.6.1.2.1.31.1.1.1.10` | `ifHCOutOctets` | **64-bit** bytes sent — use this for Gigabit+ ports |

> ⚠️ **Counter wrap**: Standard 32-bit counters wrap at 4 GB — on a Gigabit port at full speed, every ~34 seconds. Always use `ifHCInOctets` / `ifHCOutOctets` (64-bit). All modern managed switches support these.

#### System MIB — Device Identification

| OID | Name | Data |
|-----|------|------|
| `1.3.6.1.2.1.1.1.0` | `sysDescr` | `TP-Link Smart Switch TL-SG108E 2.0` |
| `1.3.6.1.2.1.1.2.0` | `sysObjectID` | Vendor OID tree: `1.3.6.1.4.1.11863` = TP-Link |
| `1.3.6.1.2.1.1.3.0` | `sysUpTime` | Timeticks since last reboot |
| `1.3.6.1.2.1.1.5.0` | `sysName` | Configured hostname |
| `1.3.6.1.2.1.17.1.2.0` | `dot1dBaseBridgeAddress` | Switch's own MAC address |
| `1.3.6.1.2.1.17.1.3.0` | `dot1dBaseNumPorts` | Number of physical ports |

**Vendor OID prefixes** (`sysObjectID` lookup):

```python
VENDOR_OID_MAP = {
    '1.3.6.1.4.1.11863': 'TP-Link',
    '1.3.6.1.4.1.9':     'Cisco',
    '1.3.6.1.4.1.4526':  'Netgear',
    '1.3.6.1.4.1.14988': 'MikroTik',
    '1.3.6.1.4.1.11':    'HP/HPE',
    '1.3.6.1.4.1.171':   'D-Link',
    '1.3.6.1.4.1.41112': 'Ubiquiti',
    '1.3.6.1.4.1.25506': 'HPE Aruba',
}
```

### 2.3 LLDP — Link Layer Discovery Protocol

LLDP (IEEE 802.1AB) is a protocol where every managed switch broadcasts its identity to neighbour devices every 30 seconds. Heimdall's existing Scapy daemon captures these frames passively — **no credentials, no configuration, no prior knowledge of the switch's IP address**.

- **EtherType**: `0x88CC`
- **Destination MAC**: `01:80:C2:00:00:0E` (LLDP multicast — never forwarded by switches)
- **Broadcast interval**: Every 30 seconds (default, configurable on switch)

An LLDP frame reveals: switch hostname, model description, management IP address (where SNMP can be reached), and which port Heimdall's machine is connected to.

---

## 3. Architecture — SwitchMonitor Integration

Switch monitoring is a **parallel subsystem** alongside the router adapter. The existing `RouterAdapter` interface and `DetectionPipeline` are unchanged. A new `SwitchMonitor` module runs on its own APScheduler job and enriches the device registry with per-port assignments.

### 3.1 New Files

```
sentinel/switches/
  __init__.py
  models.py              # SwitchInfo, SwitchPort, PortMacEntry, SwitchPortStat
  registry.py            # SwitchRegistry — in-memory + DB store
  monitor.py             # SwitchMonitor — main polling orchestrator
  delta.py               # SwitchDeltaCalculator — IF-MIB counter deltas
  enricher.py            # DeviceEnricher — upgrades device monitoring granularity
  snmp/
    client.py            # SnmpClient — puresnmp wrapper
    bridge_mib.py        # BridgeMibReader — MAC-to-port table queries
    if_mib.py            # IfMibReader — per-port traffic counters
    sys_mib.py           # SysMibReader — device identification
    oid.py               # OID constants
  lldp/
    sniffer.py           # LldpSniffer — Scapy LLDP frame capture
    parser.py            # LldpParser — TLV decoding
  discovery/
    engine.py            # SwitchDiscoveryEngine
    subnet_sweep.py      # SnmpSubnetSweeper
    oui_classifier.py    # OuiClassifier

sentinel/api/routes/
  switches.py            # GET /api/switches, /api/switches/<id>/ports
```

### 3.2 Data Flow

```
Startup
  +--> LldpSniffer.start()          [daemon thread, always running]
  |      Listens for LLDP frames on eth0
  |      On frame -> SwitchDiscoveryEngine.on_lldp_discovered(ip, info)
  |
  +--> SwitchDiscoveryEngine.run()  [once at startup, then on LLDP events]
         Scans subnet for SNMP responders (community 'public')
         Identifies switches via sysObjectID + dot1dBaseNumPorts > 0
         Registers confirmed switches in SwitchRegistry

APScheduler: switch_poll() every 30 seconds
  +--> For each registered switch:
       +--> SnmpClient.walk(BridgeOid.FDB_PORT)    -> MAC-to-port table
       +--> SnmpClient.walk(IfOid.IF_HC_IN/OUT)    -> 64-bit traffic counters
       +--> SwitchDeltaCalculator.compute()          -> throughput per port
       +--> DeviceEnricher.enrich()                  -> update device DB
            |  For each MAC in BRIDGE-MIB table:
            |    device.traffic_granularity -> 'per_device'  [UPGRADED]
            |    device.switch_port         -> 'Port 2'
            |    TrafficSample written with per-device throughput
            +--> emit 'switch:update' via SocketIO -> React port map
```

### 3.3 Canonical Switch Models — `sentinel/switches/models.py`

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from enum import Enum

class SwitchDiscoveryMethod(Enum):
    LLDP        = 'lldp'
    SNMP_SWEEP  = 'snmp_sweep'
    OUI         = 'oui'
    MANUAL      = 'manual'

@dataclass
class SwitchInfo:
    id:               str              # UUID
    ip_address:       str
    mac_address:      str              # from dot1dBaseBridgeAddress
    hostname:         str              # sysName
    model:            str              # sysDescr parsed
    vendor:           str              # from sysObjectID
    num_ports:        int              # dot1dBaseNumPorts
    snmp_community:   str = 'public'
    snmp_version:     int = 2
    discovery_method: SwitchDiscoveryMethod = SwitchDiscoveryMethod.LLDP
    first_seen:       Optional[datetime] = None
    last_seen:        Optional[datetime] = None
    is_reachable:     bool = True

@dataclass
class SwitchPort:
    switch_id:      str
    port_index:     int        # IF-MIB ifIndex
    bridge_port:    int        # BRIDGE-MIB bridge port number
    port_name:      str        # 'Port 1', 'GigabitEthernet0/1'
    status:         str        # 'up' | 'down'
    speed_mbps:     int
    connected_macs: list = field(default_factory=list)

@dataclass
class PortMacEntry:
    switch_id:    str
    bridge_port:  int
    port_name:    str
    mac_address:  str     # normalised lowercase colon-separated
    status:       int     # 3=learned, 4=self, 5=mgmt

@dataclass
class SwitchPortStat:
    switch_id:           str
    port_index:          int
    timestamp:           datetime
    bytes_in_total:      int    # ifHCInOctets (64-bit cumulative)
    bytes_out_total:     int    # ifHCOutOctets (64-bit cumulative)
    bytes_in_delta:      int
    bytes_out_delta:     int
    throughput_up_kbps:  int
    throughput_dn_kbps:  int
    errors_in:           int
    discards_in:         int
```

---

## 4. SNMP Client Implementation

### 4.1 Why puresnmp

`puresnmp` is pure-Python with native async support and no system library dependencies. It requires no `net-snmp` installation in the Docker container.

```
# requirements.txt addition
puresnmp>=2.0
```

### 4.2 OID Constants — `sentinel/switches/snmp/oid.py`

```python
class SysOid:
    DESCR      = '1.3.6.1.2.1.1.1.0'
    OBJECT_ID  = '1.3.6.1.2.1.1.2.0'
    UPTIME     = '1.3.6.1.2.1.1.3.0'
    NAME       = '1.3.6.1.2.1.1.5.0'

class BridgeOid:
    BASE_BRIDGE_ADDR   = '1.3.6.1.2.1.17.1.2.0'
    BASE_NUM_PORTS     = '1.3.6.1.2.1.17.1.3.0'
    FDB_ADDRESS        = '1.3.6.1.2.1.17.4.3.1.1'
    FDB_PORT           = '1.3.6.1.2.1.17.4.3.1.2'
    FDB_STATUS         = '1.3.6.1.2.1.17.4.3.1.3'
    BASE_PORT_IF_INDEX = '1.3.6.1.2.1.17.1.4.1.2'

class IfOid:
    IF_INDEX   = '1.3.6.1.2.1.2.2.1.1'
    IF_DESCR   = '1.3.6.1.2.1.2.2.1.2'
    IF_SPEED   = '1.3.6.1.2.1.2.2.1.5'
    IF_STATUS  = '1.3.6.1.2.1.2.2.1.8'
    IF_IN_ERR  = '1.3.6.1.2.1.2.2.1.14'
    IF_IN_DIS  = '1.3.6.1.2.1.2.2.1.13'
    # 64-bit high-capacity counters — always use these on Gigabit+ ports
    IF_HC_IN   = '1.3.6.1.2.1.31.1.1.1.6'
    IF_HC_OUT  = '1.3.6.1.2.1.31.1.1.1.10'
```

### 4.3 SNMP Client — `sentinel/switches/snmp/client.py`

```python
import logging
from typing import Any
from puresnmp import Client, V2C

log = logging.getLogger(__name__)

class SnmpClient:

    def __init__(self, host: str, community: str = 'public',
                 port: int = 161, timeout: float = 5.0):
        self._host      = host
        self._community = community
        self._port      = port
        self._timeout   = timeout

    def _client(self) -> Client:
        return Client(self._host, V2C(self._community),
                      port=self._port, timeout=int(self._timeout))

    async def get(self, oid: str) -> Any:
        try:
            async with self._client() as client:
                return await client.get(oid)
        except Exception as e:
            log.debug('SNMP GET %s@%s failed: %s', oid, self._host, e)
            return None

    async def walk(self, oid: str) -> dict:
        """Walk an OID subtree. Returns {full_oid_string: value} dict."""
        try:
            async with self._client() as client:
                results = {}
                async for item in client.walk(oid):
                    results[str(item.oid)] = item.value
                return results
        except Exception as e:
            log.debug('SNMP WALK %s@%s failed: %s', oid, self._host, e)
            return {}

    async def is_reachable(self) -> bool:
        val = await self.get('1.3.6.1.2.1.1.1.0')  # sysDescr
        return val is not None
```

### 4.4 BRIDGE-MIB Reader — `sentinel/switches/snmp/bridge_mib.py`

```python
import logging
from .client import SnmpClient
from .oid    import BridgeOid
from ..models import PortMacEntry

log = logging.getLogger(__name__)

class BridgeMibReader:

    def __init__(self, client: SnmpClient, switch_id: str):
        self._client    = client
        self._switch_id = switch_id

    async def get_mac_port_table(self) -> list[PortMacEntry]:
        """Read MAC address forwarding table. Returns (mac, bridge_port) pairs."""
        fdb_port   = await self._client.walk(BridgeOid.FDB_PORT)
        fdb_status = await self._client.walk(BridgeOid.FDB_STATUS)

        entries = []
        for oid_str, port_num in fdb_port.items():
            if not isinstance(port_num, int) or port_num == 0:
                continue
            mac = self._oid_suffix_to_mac(oid_str)
            if mac is None:
                continue
            status_oid = oid_str.replace(BridgeOid.FDB_PORT, BridgeOid.FDB_STATUS)
            status = fdb_status.get(status_oid, 0)
            entries.append(PortMacEntry(
                switch_id=self._switch_id,
                bridge_port=port_num,
                port_name='',
                mac_address=mac,
                status=status,
            ))
        return entries

    async def get_bridge_to_if_mapping(self) -> dict[int, int]:
        """Map bridge port number -> IF-MIB ifIndex."""
        result = await self._client.walk(BridgeOid.BASE_PORT_IF_INDEX)
        mapping = {}
        for oid_str, if_index in result.items():
            bridge_port = int(oid_str.split('.')[-1])
            mapping[bridge_port] = int(if_index)
        return mapping

    def _oid_suffix_to_mac(self, oid_str: str) -> str | None:
        """Convert OID suffix '218.212.25.52.233.26' -> 'da:d4:19:31:c0:e9'."""
        try:
            base   = BridgeOid.FDB_PORT + '.'
            suffix = oid_str[len(base):]
            octets = [int(x) for x in suffix.split('.')]
            if len(octets) != 6:
                return None
            return ':'.join(f'{o:02x}' for o in octets)
        except (ValueError, IndexError):
            return None
```

### 4.5 IF-MIB Reader — `sentinel/switches/snmp/if_mib.py`

```python
from .client import SnmpClient
from .oid    import IfOid
from ..models import SwitchPort

class IfMibReader:

    def __init__(self, client: SnmpClient, switch_id: str):
        self._client    = client
        self._switch_id = switch_id

    async def get_ports(self) -> list[SwitchPort]:
        descr  = await self._client.walk(IfOid.IF_DESCR)
        speed  = await self._client.walk(IfOid.IF_SPEED)
        status = await self._client.walk(IfOid.IF_STATUS)

        ports = []
        for oid_str, name in descr.items():
            idx = int(oid_str.split('.')[-1])
            spd = speed.get(oid_str.replace(IfOid.IF_DESCR, IfOid.IF_SPEED), 0)
            sta = status.get(oid_str.replace(IfOid.IF_DESCR, IfOid.IF_STATUS), 2)
            ports.append(SwitchPort(
                switch_id=self._switch_id,
                port_index=idx,
                bridge_port=0,
                port_name=str(name),
                status='up' if sta == 1 else 'down',
                speed_mbps=int(spd) // 1_000_000,
            ))
        return ports

    async def get_traffic_counters(self) -> dict[int, tuple]:
        """Returns {ifIndex: (bytes_in_hc, bytes_out_hc, errors_in, discards_in)}"""
        hc_in  = await self._client.walk(IfOid.IF_HC_IN)
        hc_out = await self._client.walk(IfOid.IF_HC_OUT)
        err_in = await self._client.walk(IfOid.IF_IN_ERR)
        dis_in = await self._client.walk(IfOid.IF_IN_DIS)

        counters = {}
        for oid_str, bytes_in in hc_in.items():
            idx      = int(oid_str.split('.')[-1])
            bytes_out = hc_out.get(oid_str.replace(IfOid.IF_HC_IN, IfOid.IF_HC_OUT), 0)
            errors    = err_in.get(oid_str.replace(IfOid.IF_HC_IN, IfOid.IF_IN_ERR), 0)
            discards  = dis_in.get(oid_str.replace(IfOid.IF_HC_IN, IfOid.IF_IN_DIS), 0)
            counters[idx] = (int(bytes_in), int(bytes_out), int(errors), int(discards))
        return counters
```

---

## 5. LLDP Auto-Detection

### 5.1 LLDP Sniffer — `sentinel/switches/lldp/sniffer.py`

```python
from scapy.all import sniff
from .parser import LldpParser
import threading, logging

log = logging.getLogger(__name__)

class LldpSniffer:
    """
    Passively captures LLDP frames from directly-connected switches.
    Runs in a daemon thread. Requires NET_RAW capability (already granted).
    Switches broadcast LLDP every 30 seconds by default.
    """

    def __init__(self, on_switch_discovered, iface: str = 'eth0'):
        self._callback = on_switch_discovered
        self._iface    = iface
        self._parser   = LldpParser()
        self._seen     = set()   # management IPs already reported

    def start(self):
        threading.Thread(target=self._sniff, daemon=True, name='lldp-sniffer').start()
        log.info('LLDP sniffer started on %s', self._iface)

    def _sniff(self):
        sniff(filter='ether proto 0x88cc', prn=self._process,
              iface=self._iface, store=False)

    def _process(self, pkt):
        try:
            info = self._parser.parse(pkt)
            if info is None:
                return
            mgmt_ip = info.get('management_ip')
            if mgmt_ip and mgmt_ip not in self._seen:
                self._seen.add(mgmt_ip)
                log.info('LLDP: discovered switch at %s (%s)',
                         mgmt_ip, info.get('system_name', 'unknown'))
                self._callback(mgmt_ip, info)
        except Exception as e:
            log.debug('LLDP parse error: %s', e)
```

### 5.2 LLDP Parser — `sentinel/switches/lldp/parser.py`

```python
class LldpParser:

    TLV_CHASSIS_ID   = 1
    TLV_PORT_ID      = 2
    TLV_TTL          = 3
    TLV_PORT_DESCR   = 4
    TLV_SYSTEM_NAME  = 5
    TLV_SYSTEM_DESCR = 6
    TLV_CAPABILITIES = 7
    TLV_MGMT_ADDR    = 8
    TLV_END          = 0

    CAPABILITY_BRIDGE = 0x04

    def parse(self, pkt) -> dict | None:
        if pkt.type != 0x88cc:
            return None

        payload = bytes(pkt.payload)
        info    = {}
        pos     = 0

        while pos < len(payload) - 1:
            header   = int.from_bytes(payload[pos:pos+2], 'big')
            tlv_type = (header >> 9) & 0x7F
            tlv_len  = header & 0x1FF
            pos += 2
            if tlv_type == self.TLV_END:
                break
            value = payload[pos:pos + tlv_len]
            pos  += tlv_len

            if tlv_type == self.TLV_SYSTEM_NAME:
                info['system_name'] = value.decode('utf-8', errors='replace').strip()
            elif tlv_type == self.TLV_SYSTEM_DESCR:
                info['system_description'] = value.decode('utf-8', errors='replace').strip()
            elif tlv_type == self.TLV_PORT_DESCR:
                info['port_description'] = value.decode('utf-8', errors='replace').strip()
            elif tlv_type == self.TLV_CAPABILITIES:
                caps = int.from_bytes(value[0:2], 'big')
                info['is_bridge'] = bool(caps & self.CAPABILITY_BRIDGE)
            elif tlv_type == self.TLV_MGMT_ADDR and len(value) >= 6:
                addr_len  = value[0]
                addr_type = value[1]   # 1=IPv4
                if addr_type == 1 and addr_len == 5:
                    info['management_ip'] = '.'.join(str(b) for b in value[2:6])

        if not info.get('is_bridge', False):
            return None
        return info
```

### 5.3 SNMP Subnet Sweeper — `sentinel/switches/discovery/subnet_sweep.py`

```python
import asyncio, ipaddress, logging
from ..snmp.client import SnmpClient
from ..snmp.oid    import BridgeOid, SysOid, VENDOR_OID_MAP

log = logging.getLogger(__name__)

class SnmpSubnetSweeper:

    COMMUNITY_STRINGS = ['public', 'private', 'community']

    async def sweep(self, subnet: str, max_concurrent: int = 20) -> list[dict]:
        """Scan all hosts in subnet for SNMP-responsive managed switches."""
        network = ipaddress.IPv4Network(subnet, strict=False)
        sem     = asyncio.Semaphore(max_concurrent)
        results = await asyncio.gather(
            *[self._probe(str(ip), sem) for ip in network.hosts()]
        )
        switches = [r for r in results if r is not None]
        log.info('SNMP sweep of %s: found %d switch(es)', subnet, len(switches))
        return switches

    async def _probe(self, ip: str, sem: asyncio.Semaphore) -> dict | None:
        async with sem:
            for community in self.COMMUNITY_STRINGS:
                client = SnmpClient(ip, community, timeout=1.5)
                if not await client.is_reachable():
                    return None
                # Confirm it's a switch by checking dot1dBaseNumPorts
                num_ports = await client.get(BridgeOid.BASE_NUM_PORTS)
                if num_ports and int(num_ports) > 0:
                    sys_descr = await client.get(SysOid.DESCR)
                    sys_oid   = await client.get(SysOid.OBJECT_ID)
                    sys_name  = await client.get(SysOid.NAME)
                    return {
                        'ip':        ip,
                        'community': community,
                        'num_ports': int(num_ports),
                        'sys_descr': str(sys_descr or ''),
                        'sys_name':  str(sys_name or ''),
                        'vendor':    self._identify_vendor(str(sys_oid or '')),
                    }
        return None

    def _identify_vendor(self, sys_oid: str) -> str:
        for prefix, vendor in VENDOR_OID_MAP.items():
            if sys_oid.startswith(prefix):
                return vendor
        return 'Unknown'
```

---

## 6. SwitchMonitor — `sentinel/switches/monitor.py`

```python
from datetime import datetime, timezone
import asyncio, logging
from .snmp.client     import SnmpClient
from .snmp.bridge_mib import BridgeMibReader
from .snmp.if_mib     import IfMibReader
from .delta           import SwitchDeltaCalculator
from .enricher        import DeviceEnricher
from .registry        import SwitchRegistry

log = logging.getLogger(__name__)

class SwitchMonitor:
    """
    Polls all registered managed switches every 30 seconds.
    Updates device registry with per-port MAC assignments.
    Writes per-port traffic samples to switch_port_stats hypertable.
    """

    def __init__(self, registry: SwitchRegistry,
                 enricher: DeviceEnricher, socketio):
        self._registry = registry
        self._enricher = enricher
        self._socketio = socketio
        self._deltas   = SwitchDeltaCalculator()

    async def poll_all(self):
        """Called by APScheduler every 30 seconds."""
        switches = self._registry.get_all()
        await asyncio.gather(*[self._poll_switch(sw) for sw in switches],
                             return_exceptions=True)

    async def _poll_switch(self, switch_info):
        client = SnmpClient(switch_info.ip_address, switch_info.snmp_community)
        bridge = BridgeMibReader(client, switch_info.id)
        ifmib  = IfMibReader(client, switch_info.id)
        now    = datetime.now(timezone.utc)

        try:
            mac_entries = await bridge.get_mac_port_table()
            port_if_map = await bridge.get_bridge_to_if_mapping()
            ports       = await ifmib.get_ports()
            counters    = await ifmib.get_traffic_counters()

            # Link bridge ports to IF indices and port names
            for entry in mac_entries:
                if_index = port_if_map.get(entry.bridge_port)
                if if_index:
                    port = next((p for p in ports if p.port_index == if_index), None)
                    if port:
                        entry.port_name = port.port_name

            # Compute traffic deltas per port
            port_stats = []
            for port in ports:
                if port.port_index not in counters:
                    continue
                b_in, b_out, err, dis = counters[port.port_index]
                stat = self._deltas.compute(
                    switch_info.id, port.port_index, b_in, b_out, err, dis, now
                )
                port_stats.append(stat)

            # Enrich device registry with port assignments
            await self._enricher.enrich(
                switch_id=switch_info.id,
                mac_entries=mac_entries,
                port_stats=port_stats,
            )

            # Emit real-time update to React
            self._socketio.emit('switch:update', {
                'switch_id': switch_info.id,
                'hostname':  switch_info.hostname,
                'mac_table': [{'mac': e.mac_address, 'port': e.port_name}
                              for e in mac_entries if e.status == 3],
                'port_stats': [self._stat_to_dict(s) for s in port_stats],
            }, namespace='/sentinel')

        except Exception as e:
            log.warning('Switch poll failed for %s: %s', switch_info.ip_address, e)
```

---

## 7. Device Enricher — `sentinel/switches/enricher.py`

This is the critical component that resolves the `PER_PORT` caveat.

```python
from sentinel.adapter.models import TrafficGranularity
from sentinel.db.session     import get_db
from sentinel.db.models      import Device, TrafficSampleRecord
import logging

log = logging.getLogger(__name__)

class DeviceEnricher:
    """
    Receives BRIDGE-MIB MAC-to-port data and IF-MIB port statistics.
    Updates the devices table with exact port assignments.
    Writes per-device TrafficSamples to traffic_samples hypertable.

    Before enrichment (router-only):
      Akuvox-R20K  -> granularity='per_port',   port_alias='PHY5'
      Ringslink    -> granularity='per_port',   port_alias='PHY5'

    After enrichment (managed switch SNMP data):
      Akuvox-R20K  -> granularity='per_device', switch_port='Port 2'
      Ringslink    -> granularity='per_device', switch_port='Port 1'
    """

    async def enrich(self, switch_id, mac_entries, port_stats):
        stat_by_port = {s.port_name: s for s in port_stats}

        async with get_db() as db:
            for entry in mac_entries:
                if entry.status != 3:   # 3=learned dynamic entry only
                    continue

                device = await db.get(Device, entry.mac_address)
                if device is None:
                    continue

                # Upgrade from PER_PORT to PER_DEVICE
                device.traffic_granularity = TrafficGranularity.PER_DEVICE.value
                device.switch_port         = entry.port_name
                device.switch_id           = switch_id
                device.port_alias          = entry.port_name
                await db.flush()

                # Write accurate per-device traffic sample
                port_stat = stat_by_port.get(entry.port_name)
                if port_stat:
                    sample = TrafficSampleRecord(
                        mac_address=entry.mac_address,
                        timestamp=port_stat.timestamp,
                        bytes_sent_delta=port_stat.bytes_out_delta,
                        bytes_recv_delta=port_stat.bytes_in_delta,
                        throughput_up_kbps=port_stat.throughput_up_kbps,
                        throughput_dn_kbps=port_stat.throughput_dn_kbps,
                        granularity=TrafficGranularity.PER_DEVICE.value,
                        anomaly_score=None,
                    )
                    db.add(sample)
                    log.debug('Enriched %s: up=%d dn=%d kbps via %s',
                              entry.mac_address,
                              port_stat.throughput_up_kbps,
                              port_stat.throughput_dn_kbps,
                              entry.port_name)

            await db.commit()
```

---

## 8. Supported Switches & Compatibility

Any switch responding to SNMP v2c with `BRIDGE-MIB` and `ifHCInOctets` is fully supported.

| Switch | Price | SNMP | LLDP | Auto-detect | Notes |
|--------|-------|------|------|-------------|-------|
| TP-Link TL-SG108E | ~$25 | ❌ No | ✅ | LLDP only | Budget Easy Smart — no SNMP. Web scrape only. |
| TP-Link Omada TL-SG2008 | ~$50 | ✅ v2c | ✅ | LLDP+SNMP | **Recommended entry-level**. Full BRIDGE-MIB. |
| Netgear GS308E | ~$35 | ⚠ Lim. | ✅ | LLDP only | Limited SNMP — BRIDGE-MIB may be unavailable. |
| MikroTik CSS326 | ~$60 | ✅ v2c/v3 | ✅ | LLDP+SNMP | **Best value**. Full BRIDGE-MIB + REST API. |
| MikroTik CSS610 | ~$100 | ✅ v2c/v3 | ✅ | LLDP+SNMP | 10G SFP+ ports. Full support. |
| Cisco SG350-10 | ~$120 | ✅ Full | ✅ | LLDP+SNMP | Enterprise-grade. Full BRIDGE-MIB + REST. |
| D-Link DGS-1100-08 | ~$40 | ✅ v2c | ✅ | LLDP+SNMP | Full BRIDGE-MIB. Popular in Europe/ME. |
| HPE Aruba 1830 | ~$80 | ✅ v2c/v3 | ✅ | LLDP+SNMP | Full support. Cloud + local management. |
| Ubiquiti UniFi US-8 | ~$100 | Via controller | ✅ | UniFi adapter | Use existing UniFi adapter — not SNMP. |

> **For this specific setup**: If adding a managed switch to resolve the Akuvox + Ringslink wired monitoring gap, the **MikroTik CSS326** (~$60, 24-port, fanless) or **TP-Link Omada TL-SG2008** (~$50, 8-port) are recommended.

---

## 9. Database Schema Additions

```sql
-- Managed switch registry
CREATE TABLE switches (
    id               VARCHAR(36)  PRIMARY KEY,
    ip_address       VARCHAR(15)  NOT NULL,
    mac_address      VARCHAR(17),
    hostname         VARCHAR(255),
    model            VARCHAR(255),
    vendor           VARCHAR(100),
    num_ports        INT,
    snmp_community   VARCHAR(100) DEFAULT 'public',
    snmp_version     INT          DEFAULT 2,
    discovery_method VARCHAR(20)  DEFAULT 'lldp',
    is_reachable     BOOLEAN      DEFAULT TRUE,
    first_seen       TIMESTAMPTZ  DEFAULT now(),
    last_seen        TIMESTAMPTZ  DEFAULT now()
);

-- Switch port definitions
CREATE TABLE switch_ports (
    id           BIGSERIAL    PRIMARY KEY,
    switch_id    VARCHAR(36)  NOT NULL REFERENCES switches(id),
    port_index   INT          NOT NULL,
    bridge_port  INT,
    port_name    VARCHAR(100),
    status       VARCHAR(10)  DEFAULT 'unknown',
    speed_mbps   INT,
    UNIQUE(switch_id, port_index)
);

-- Per-port traffic time-series (TimescaleDB hypertable)
CREATE TABLE switch_port_stats (
    time               TIMESTAMPTZ  NOT NULL,
    switch_id          VARCHAR(36)  NOT NULL,
    port_index         INT          NOT NULL,
    port_name          VARCHAR(100),
    bytes_in_total     BIGINT,    -- ifHCInOctets  (64-bit cumulative)
    bytes_out_total    BIGINT,    -- ifHCOutOctets (64-bit cumulative)
    bytes_in_delta     BIGINT,
    bytes_out_delta    BIGINT,
    throughput_up_kbps BIGINT,
    throughput_dn_kbps BIGINT,
    errors_in          INT,
    discards_in        INT,
    status             VARCHAR(10)
);
SELECT create_hypertable('switch_port_stats', 'time');
CREATE INDEX ON switch_port_stats (switch_id, port_index, time DESC);

-- MAC address forwarding table snapshots
CREATE TABLE switch_mac_table (
    id           BIGSERIAL    PRIMARY KEY,
    switch_id    VARCHAR(36)  NOT NULL,
    bridge_port  INT          NOT NULL,
    port_name    VARCHAR(100),
    mac_address  VARCHAR(17)  NOT NULL,
    entry_status INT          DEFAULT 3,
    first_seen   TIMESTAMPTZ  DEFAULT now(),
    last_seen    TIMESTAMPTZ  DEFAULT now(),
    UNIQUE(switch_id, mac_address)
);
CREATE INDEX ON switch_mac_table (mac_address);

-- Add switch columns to existing devices table
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS switch_id   VARCHAR(36),
    ADD COLUMN IF NOT EXISTS switch_port VARCHAR(100);
```

---

## 10. API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/switches` | List all discovered and manually added switches with status |
| `GET /api/switches/<id>` | Switch detail: model, ports, reachability, last poll time |
| `GET /api/switches/<id>/ports` | All ports: name, status, speed, connected devices, throughput |
| `GET /api/switches/<id>/mac-table` | Current MAC address forwarding table from BRIDGE-MIB |
| `POST /api/switches/discover` | Trigger manual discovery (LLDP flush + SNMP sweep) |
| `POST /api/switches` | Manually add switch: `{ip, community, snmp_version}` |
| `PUT /api/switches/<id>` | Update switch config: community string, SNMP version, hostname alias |
| `DELETE /api/switches/<id>` | Remove switch from monitoring |
| `POST /api/switches/<id>/test` | Test SNMP connectivity: returns `{reachable, num_ports, vendor}` |
| `GET /api/network/topology` | Full topology graph: router + switches + device-port assignments |

---

## 11. Settings Tab — UI Specification

The Settings page gains a **Network Devices** section with four panels.

### Layout

```
SettingsPage
  +--> Section: Router Configuration   (existing)
  |
  +--> Section: Network Devices        (NEW)
  |      DiscoveredSwitchesPanel
  |      SwitchPortMapPanel
  |      SnmpConfigPanel
  |      VlanMapPanel (Phase 2)
  |
  +--> Section: Notifications          (existing)
  +--> Section: Detection Rules        (existing)
```

### DiscoveredSwitchesPanel

Displays every auto-detected switch. Shows model, vendor, IP, detection method, port count, and reachability status. "Scan now" button triggers `POST /api/switches/discover`.

Empty state when no switches detected:
> "Heimdall listens for LLDP frames and scans for SNMP responses. If you have a managed switch, ensure LLDP and SNMP are enabled. The default SNMP community string is 'public'."

### SwitchPortMapPanel

Visual faceplate showing each physical port as a tile. Updates in real time via `switch:update` WebSocket event.

Each port tile shows:
- Port name (`Port 1`, `GigabitEthernet0/1`)
- Status indicator (green = UP, muted = DOWN)
- Link speed (`1 Gbps`)
- Connected device hostname(s) — resolved from device registry
- Throughput `↑ / ↓` in Kbps
- Error badge if `errors_in > 0`

> The `PORT TOTAL` badge on wired devices in the device list is removed once SNMP enrichment is active.

### SnmpConfigPanel

Per-switch SNMP configuration form. Validates community string before saving via `POST /api/switches/<id>/test`.

| Field | Default |
|-------|---------|
| Community string | `public` |
| SNMP version | v2c |
| v3 Username | (empty) |
| v3 Auth protocol | SHA |
| v3 Auth password | (empty) |
| v3 Privacy protocol | AES |
| v3 Privacy password | (empty) |
| Poll interval | 30 seconds |
| Hostname alias | (empty) |

### VlanMapPanel (Phase 2)

Lists all VLANs from Q-BRIDGE-MIB (`1.3.6.1.2.1.17.7`), which ports belong to each VLAN, and highlights unexpected VLAN assignments. Useful for verifying IoT device segmentation.

---

## 12. Network Topology Visualisation

The topology view (React Flow) upgrades from flat device list to hierarchical graph:

```
Internet
    |
  [WAN]
    |
Sagemcom F@st 5670  [router node — hexagon]
    |
    +-- [WiFi 5GHz / 907 Mbps]
    |       +-- Redmi-Note-13-Pro-5G    (-59dBm, 8.4 MB/s)
    |       +-- DESKTOP-OFNIM7N         (-72dBm)
    |       +-- chuangmi_camera_ipc019  [SUSPECT]
    |       +-- ...
    |
    +-- [WiFi 2.4GHz / 72 Mbps]
    |       +-- MiWiFi-RA67             [WARN]
    |
    +-- [Port 5 / PHY5 / 100 Mbps]
            |
        MikroTik CSS326  [switch node — rectangle, teal]
            +-- [Port 1]   Ringslink device  (0.0 MB/s)
            +-- [Port 2]   Akuvox-R20K       (0.1 MB/s)
            +-- [Port 24]  (Heimdall uplink)
```

**Node types**:
- Router: hexagon, blue — shows model + WAN status
- Switch: rectangle, teal — shows model + port count
- Device: circle — coloured by threat level
- WiFi band: group container — labelled with band + aggregate speed

---

## 13. New Python Dependencies

```
# requirements.txt addition
puresnmp>=2.0    # Pure-Python async SNMP v1/v2c/v3 — no system library needed

# Already present (no new dependencies):
# scapy>=2.5     -- LLDP frame sniffing (already used for ARP monitoring)
# ipaddress      -- stdlib, no install needed
```

> Switch support adds exactly **one new Python dependency**. Total Docker image size increase is negligible (~200 KB for puresnmp).

---

## 14. APScheduler Job Additions

```python
# sentinel/scheduler/tasks.py additions

def register_switch_jobs(scheduler, switch_monitor, switch_discovery):

    # Poll all registered switches every 30 seconds
    scheduler.add_job(
        switch_monitor.poll_all,
        trigger='interval',
        seconds=30,
        id='switch_poll',
        replace_existing=True,
    )

    # Re-run SNMP subnet sweep every 6 hours
    scheduler.add_job(
        switch_discovery.run_snmp_sweep,
        trigger='interval',
        hours=6,
        id='switch_snmp_sweep',
        replace_existing=True,
    )

    # Prune stale MAC table entries (not seen for 24h)
    scheduler.add_job(
        switch_discovery.prune_stale_entries,
        trigger='interval',
        hours=24,
        id='switch_mac_prune',
        replace_existing=True,
    )

    # LldpSniffer runs as a daemon thread — no scheduler job needed
```

---

## 15. Phased Delivery

| Phase | Scope | Outcome |
|-------|-------|---------|
| Switch 1 — LLDP | `LldpSniffer` + `LldpParser` + `SwitchDiscoveryEngine.on_lldp_discovered()` + `switches` DB table + `GET /api/switches` | Switches auto-detected and listed in Settings. No traffic data yet. |
| Switch 2 — SNMP Identify | `SysMibReader` + `SnmpSubnetSweeper` + `SnmpConfigPanel` in UI + `POST /api/switches/discover` + test endpoint | User configures SNMP community string. Switch model/vendor identified. |
| Switch 3 — Port Map | `BridgeMibReader` + `IfMibReader` + `SwitchMonitor.poll_all()` + `SwitchPortMapPanel` in UI | Port map visible in Settings. MAC-to-port table polled every 30s. |
| Switch 4 — Enrichment | `DeviceEnricher` + upgrade `PER_PORT` → `PER_DEVICE` + write per-device `TrafficSamples` | **PER_PORT caveat resolved.** Wired devices show accurate per-device throughput. |
| Switch 5 — Topology | Network topology view in React Flow + switch nodes + port edges | Full visual topology: router + switches + all devices. |
| Switch 6 — VLAN | Q-BRIDGE-MIB VLAN support + `VlanMapPanel` + VLAN badges on device cards | VLAN assignments visible. IoT segmentation verification. |
