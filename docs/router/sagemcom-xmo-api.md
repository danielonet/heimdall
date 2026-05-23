# Sagemcom XMO API Reference

Router: **Sagemcom F@st 5670**
Firmware: **SGFg12000116**
GUI Version: **5.146.1**
Admin URL: **http://10.100.102.1** (discovered from default route at runtime)

All xpaths marked ✅ have been directly observed in browser DevTools XHR.
Xpaths marked ✅* have confirmed parent nodes but sub-paths need one more capture.
Xpaths marked ⬜ are expected to exist based on firmware conventions.

---

## Transport

```
POST  http://{router_ip}/cgi/json-req
Content-Type: application/x-www-form-urlencoded

Body:  req=<URL-encoded JSON envelope>
```

## Authentication

1. Send request with `session-id: 0` and `auth-key: ""`
2. Router returns `session-id` in response `reply.uid`
3. For all subsequent requests:
   - `cnonce` = random integer
   - `auth-key` = `MD5( MD5(password) + ":" + cnonce )`
4. On error code `16777219` (XMO_REQUEST_AUTHENTICATION_ERR) → re-login

Error code `16777239` = `XMO_NO_ERR` (success).

## Request envelope

```json
{
  "request": {
    "id": 863,
    "session-id": 1084566263,
    "priority": false,
    "actions": [
      {
        "id": 0,
        "method": "getValue",
        "xpath": "Device/Hosts/Host",
        "options": { "capability-flags": { "interface": true } }
      }
    ],
    "cnonce": 583156031,
    "auth-key": "d1fa311771f1f1cbd61ea913cc6236af"
  }
}
```

## Available methods

| Method | Description |
|--------|-------------|
| `getValue` | Read current value of a node or subtree |
| `setValue` | Write a scalar value to a config node |
| `addObject` | Create a new list entry (e.g. add a firewall rule) |
| `deleteObject` | Remove a list entry (e.g. remove a block rule) |

---

## Device & Host Layer

| XPath | Status | Data |
|-------|--------|------|
| `Device/Hosts/Host` | ✅ | All LAN clients: MAC (`PhysAddress`), IP (`IPAddress`), hostname (`HostName`), `InterfaceType` (WiFi/Ethernet), `Active`, `X_SAGEMCOM_SignalStrength`, `X_SAGEMCOM_RxRate`, `BytesSent`, `BytesReceived` |
| `Device/DHCPv4/Server/Pool/Client` | ✅ | DHCP leases: MAC, IP, hostname, lease expiry |
| `Device/DeviceInfo` | ✅ | Model "F@st 5670", firmware "SGFg12000116", serial "N7223428X0026...", hardware version "2.00", uptime (seconds), WAN MAC "C4:EB:42:F1:26:85" |

---

## WiFi Layer

| XPath | Status | Data |
|-------|--------|------|
| `Device/WiFi/SSIDs/SSID[Alias="WL_PRIV"]/Stats/*` | ✅ | 2.4GHz SSID aggregate: `BytesSent` 2.1 GB, `BytesReceived` 1.07 GB, `ErrorsSent` 18681, `RetransCount` 194592 |
| `Device/WiFi/SSIDs/SSID[Alias="WL_PRIV_5G"]/Stats/*` | ⬜ | 5GHz SSID — alias unconfirmed |
| `Device/WiFi/Radios/Radio[Alias="wl0"]/Stats/*` | ✅* | 5GHz radio: 907 Mbps link speed, 50.48 GB sent, 6.50 GB recv, ErrorsSent 202257 |
| `Device/WiFi/Radios/Radio[Alias="wl1"]/Stats/*` | ✅* | 2.4GHz radio: 72 Mbps link speed, 2.32 GB sent, 1.08 GB recv |
| `Device/WiFi/Radios/Radio` | ✅ | Radio config: channel, TX power, standard (n/ac/ax) |
| `Device/WiFi/AccessPoints/AccessPoint/.../AssociatedDevice` | ⬜ | Per-client: RSSI, TX/RX rate, connection time |

---

## LAN Ethernet Layer — PHY1 through PHY5

Port status as of last observation:
- **PHY1–PHY4**: Status DOWN (nothing connected)
- **PHY5 (2.5G)**: Status UP, CurrentBitRate 100 Mbps

Sub-path pattern: `Device/Ethernet/Interfaces/Interface[Alias="PHY{N}"]/{sub-path}`

| Sub-path | Status | Data |
|----------|--------|------|
| `Enable` | ✅ | Boolean |
| `Status` | ✅ | `UP` \| `DOWN` \| `DORMANT` |
| `MaxBitRate` | ✅ | AUTO \| 100 \| 1000 \| 2500 |
| `CurrentBitRate` | ✅ | PHY5 = 100 Mbps negotiated |
| `DuplexMode` | ✅ | AUTO \| HALF \| FULL |
| `Diagnostics/CurrentDuplexMode` | ✅ | PHY1/2 = HALF; PHY3/4/5 = FULL |
| `Stats/BytesSent` | ✅ | PHY5 = 46.43 GB (cumulative) |
| `Stats/BytesReceived` | ✅ | PHY5 = 3.32 GB (cumulative) |
| `Stats/PacketsSent` | ✅ | PHY5 = 42,682,891 |
| `Stats/PacketsReceived` | ✅ | PHY5 = 10,707,246 |
| `Stats/ErrorsSent` | ✅ | PHY5 = 0 |
| `Stats/ErrorsReceived` | ✅ | PHY5 = 0 |
| `Stats/DiscardPacketsSent` | ✅ | PHY5 = 0 |
| `Stats/DiscardPacketsReceived` | ✅ | PHY5 = 126 |
| `Stats/UnicastPacketsSent` | ✅ | PHY5 = 41,631,850 |
| `Stats/UnicastPacketsReceived` | ✅ | PHY5 = 9,703,619 |
| `Stats/MulticastPacketsSent` | ✅ | PHY5 = 606,394 |
| `Stats/MulticastPacketsReceived` | ✅ | PHY5 = 183,488 |
| `Stats/BroadcastPacketsSent` | ✅ | PHY5 = 444,647 |
| `Stats/BroadcastPacketsReceived` | ✅ | PHY5 = 820,139 |
| `LastChange` | ✅ | Seconds since last link state change |
| `ResetStats` | ✅ | Write `true` to reset port counters |

---

## WAN Layer

| XPath | Status | Data |
|-------|--------|------|
| `Device/IP/Interfaces/Interface[Alias='IP_DATA']/Status` | ✅ | WAN state: `UP` \| `DOWN` |
| `Device/IP/Interfaces/Interface[Alias='IP_DATA']/Stats/*` | ✅* | Total household bytes — sub-paths to verify |
| `Device/IP/Interfaces/Interface[Alias='PPP_DATA']/Stats/*` | ⬜ | PPPoE stats |
| `Device/IP/Interfaces/Interface[Alias='IP_IPTV']/Status` | ✅ | IPTV interface: UP, 278.1 KB received |
| `Device/Services/NetworkCfg/CurrentWanMode` | ✅ | `PPPoE` \| `IPoE` \| `Bridge` |

---

## Firewall Layer

| XPath | Status | Notes |
|-------|--------|-------|
| `Device/Firewall/Chain` | ✅* | Chains confirmed — exact chain name for MAC blocking TBD |
| `Device/Firewall/Chain[Name="LAN_IN"]/Rule` | ⬜ | **Confirm by**: DevTools open → Parental Control → add test block → capture XHR |
| `Device/Firewall/Chain/Rule[Description="SENTINEL_BLOCK_*"]` | ⬜ | How adapter's own rules appear — verify after first block |

### Block device (addObject)

```json
{
  "method": "addObject",
  "xpath": "Device/Firewall/Chain[Name=\"LAN_IN\"]/Rule",
  "parameters": {
    "SourceMACAddress": "da:d4:19:31:c0:e9",
    "Target": "DROP",
    "Enable": true,
    "Description": "SENTINEL_BLOCK_da:d4:19:31:c0:e9"
  }
}
```

### Unblock device (deleteObject)

```json
{
  "method": "deleteObject",
  "xpath": "Device/Firewall/Chain[Name=\"LAN_IN\"]/Rule[@uid=\"42\"]"
}
```

---

## Remaining captures needed

| Priority | Navigate to | Reveals |
|----------|-------------|---------|
| **CRITICAL** | Access Control → Parental Control → add temp block → capture XHR | Exact Firewall chain name and Rule xpath for `block_device()` |
| Important | WAN → Statistics | `IP_DATA/Stats/*` sub-paths for total household bandwidth |
| Useful | WiFi → Stats (DevTools open) | Confirms Radio alias (`wl0`/`wl1`) vs SSID alias |
