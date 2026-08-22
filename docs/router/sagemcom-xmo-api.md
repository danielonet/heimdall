# Sagemcom XMO API Reference

Router: **Sagemcom F@st 5670 (model ST5670V2IL)**
Firmware: **SGFg12000116**
GUI Version: **5.146.1**
ISP: **Cellcom** (Israel) — this is an ISP-customized data model, not stock
Sagemcom; several xpaths from generic XMO references don't apply here (see
"Remaining captures needed" below).
Admin URL: **http://10.100.102.1** (discovered from default route at runtime)

All xpaths marked ✅ have been directly observed in browser DevTools XHR
**and confirmed against a live authenticated call** (see Authentication
section — this doc previously marked xpaths ✅ off unverified assumptions,
which turned out wrong for the Hosts table; don't trust a ✅ here that
predates that fix without re-checking the git history of this file).
Xpaths marked ✅* have confirmed parent nodes but sub-paths need one more capture.
Xpaths marked ⬜ are expected to exist based on firmware conventions but are unverified.
Xpaths marked ❌ were checked live and do not exist on this firmware.
Xpaths marked ⚠️ were captured live but a later finding cast doubt on a detail (see the row's note) — re-verify before trusting.

---

## Transport

```
POST  http://{router_ip}/cgi/json-req
Content-Type: application/x-www-form-urlencoded

Body:  req=<URL-encoded JSON envelope>
```

## Authentication

**The section below as previously written was wrong** — a bare
`session-id: 0, auth-key: ""` handshake with no actions does not work
against this router; it always replies with `XMO_INVALID_SESSION_ERR`
regardless of credentials. This was reverse-engineered from the router's own
`js/gui-api.js` (fetched from `http://{router_ip}/2.0/gui/js/gui-api.js`,
served unauthenticated) and confirmed against a live login + authenticated
`getValue` call. See `sentinel/adapter/sagemcom/xmo_auth.py` for the
implementation.

1. `HA1 = MD5( f"{username}:{nonce}:{MD5(password)}" )` — `nonce` is `""`
   until a session has been established.
2. `auth-key = MD5( f"{HA1}:{request_id}:{cnonce}:JSON:/cgi/json-req" )`
3. **Login**: `session-id: 0`, `priority: true`, HA1 computed with
   `nonce=""`, and a single action:
   ```json
   {
     "id": 0,
     "method": "logIn",
     "parameters": {
       "user": "home",
       "persistent": "true",
       "session-options": {
         "nss": [{ "name": "gtw", "uri": "http://sagemcom.com/gateway-data" }],
         "context-flags": { "get-content-name": true, "local-time": true },
         "capability-depth": 2,
         "capability-flags": { "name": true, "default-value": false, "restriction": true, "description": false },
         "time-format": "ISO_8601",
         "jwt-auth": "true"
       }
     }
   }
   ```
   Note: the plaintext password is **never sent** — it's only ever expressed
   through the `auth-key` hash. Sending a literal `"password"` parameter
   here (as this doc previously showed) gets the action accepted structurally
   but the login rejected with `XMO_AUTHENTICATION_ERR` (16777224).
4. On success, the response carries the new session-id **and** a fresh
   server nonce in `reply.actions[0].callbacks[0].parameters` — **not**
   `reply.uid`, which stays `0` even on a successful login:
   ```json
   {"reply":{"uid":0,"error":{"code":16777216,"description":"XMO_REQUEST_NO_ERR"},
     "actions":[{"error":{"code":16777239,"description":"XMO_NO_ERR"},
       "callbacks":[{"parameters":{"id":1037387852,"nonce":"2021791795"}}]}]}}
   ```
5. Recompute HA1 with that nonce for **every** request for the rest of the
   session (not just once) — `session-id` becomes the returned `id`.
6. On error code `16777219` (`XMO_INVALID_SESSION_ERR`) → re-login (resets
   nonce to `""` and starts over).

Other error codes hit while reverse-engineering this: `16777224`
`XMO_AUTHENTICATION_ERR` (wrong credentials), `16777225`
`XMO_LOGIN_RETRY_ERR` (temporary brute-force lockout after repeated failed
logins — clears on a router power-cycle, or after some cooldown that resets
on every further attempt while it's active, so stop retrying immediately if
you see this).

Error code `16777239` = `XMO_NO_ERR` (per-action success). Error code
`16777216` = `XMO_REQUEST_NO_ERR` (per-request success, top level).

## Request envelope

Response values live at `reply.actions[].callbacks[0].parameters.value`, not
`callbacks[0].result` (`result` only carries a status code/description).
Object-returning xpaths additionally wrap the value one level deeper, keyed
by the xpath's own last segment — e.g. `Device/DeviceInfo` returns
`{"DeviceInfo": {...}}`. `sentinel/adapter/sagemcom/xmo_client.py:_extract_result`
peels that wrapper off automatically.

```json
{
  "request": {
    "id": 1,
    "session-id": 1037387852,
    "priority": false,
    "actions": [
      { "id": 0, "method": "getValue", "xpath": "Device/DeviceInfo" }
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
| `Device/Hosts/Host` | ❌ | **Does not exist on this firmware** — `XMO_UNKNOWN_PATH_ERR` (16777243), confirmed live despite this doc previously marking it ✅. Use `Device/Hosts` instead. |
| `Device/Hosts` | ✅ | Returns a container: `{"GlobalBlackAndWhitelistSwitch", "MasterBlacklistEnable", "SweepARP", "Hosts": [...]}` — the actual host list is the nested `Hosts` array, one level below what `_extract_result`'s xpath-leaf unwrap gives you. Each entry has MAC (`PhysAddress`), IP (`IPAddress`), hostname (`HostName`), `InterfaceType` (WiFi/Ethernet), `Active`. Confirmed **absent** on this firmware: `X_SAGEMCOM_SignalStrength`, `X_SAGEMCOM_RxRate`, `BytesSent`, `BytesReceived` (present instead: `SignalSgtrength` [sic — real firmware typo] as an enum string like `WL_SIGNAL_NONE`, not dBm). Per-device WiFi signal/traffic now comes from `Device/WiFi/AccessPoints/AccessPoint[Alias="X"]/AssociatedDevices` instead — see WiFi Layer below. |
| `Device/DHCPv4/Server/Pool/Client` | ✅ | DHCP leases: MAC, IP, hostname, lease expiry |
| `Device/DeviceInfo` | ✅ | Confirmed live. Model "Fast5670_GPON", firmware "SGFg12000116", serial "N7223428X002678", hardware version "2.00" |
| `Device/Hosts` entry → `Layer1Interface` | ✅ | Confirmed live for wired hosts: `"Device/Ethernet/Interfaces/Interface[PHY5]"` — the bracketed segment is the PHY port that host's physical connection terminates on (`_parse_port_alias` in `xmo_adapter.py`). Blank for WiFi hosts. **This is how per-device wired bandwidth becomes possible**: group active wired hosts by this field — if a port has exactly one occupant, that port's `Device/Ethernet/Interfaces/Interface[Alias]/Stats` total unambiguously belongs to that one device (see `_single_occupant_port_samples`). A port with more than one host on it (a switch/hub downstream) still can't be split apart — the router has no visibility past the switch. |

---

## WiFi Layer

| XPath | Status | Data |
|-------|--------|------|
| `Device/WiFi/SSIDs/SSID[Alias="WL_PRIV"]/Stats/*` | ✅ | 2.4GHz SSID aggregate: `BytesSent` 2.1 GB, `BytesReceived` 1.07 GB, `ErrorsSent` 18681, `RetransCount` 194592 |
| `Device/WiFi/SSIDs/SSID[Alias="WL_PRIV_5G"]/Stats/*` | ⬜ | 5GHz SSID — alias unconfirmed |
| `Device/WiFi/Radios/Radio[Alias="wl0"]/Stats/*` | ⚠️ | 5GHz radio: 907 Mbps link speed, 50.48 GB sent, 6.50 GB recv, ErrorsSent 202257. **Alias now suspect**: the `Radio[@uid='N']` capture below confirms this router's real radio aliases are `RADIO2G4`/`RADIO5G`, not `wl0`/`wl1` — this row predates that finding and isn't used by any current adapter code (nothing reads per-radio traffic stats), so it hasn't been re-verified under the correct alias. |
| `Device/WiFi/Radios/Radio[Alias="wl1"]/Stats/*` | ⚠️ | 2.4GHz radio: 72 Mbps link speed, 2.32 GB sent, 1.08 GB recv. Same alias caveat as the row above. |
| `Device/WiFi/Radios/Radio` (bare, unfiltered) | ❌ | **Confirmed live bug, not usable**: only ever returns the first radio (`uid=1`), silently dropping every other one (`uid=2`, 5GHz) — no error of any kind, unlike `Device/WiFi/SSIDs`, which genuinely does return every SSID via the same bare-path pattern. |
| `Device/WiFi/Radios/Radio[@uid='N']` | ✅ | The fix: query each `uid` explicitly (1, 2, 3, ...) and stop at the first one that 404s (`XMO_UNKNOWN_PATH_ERR`, empty `callbacks`, no exception — see `SagemcomXmoAdapter._get_wifi_radios`). Confirmed live on this router: `uid=1` is `Alias: 'RADIO2G4'` (2.4GHz), `uid=2` is `Alias: 'RADIO5G'` (5GHz) — **not** `wl0`/`wl1` as this doc and the adapter's primary alias branch previously assumed (that branch is dead code on this firmware, harmless because it falls through to the `OperatingFrequencyBand` fallback, which does resolve: raw values `'2_4GHZ'`/`'5GHZ'`). Fields present as named: `Channel`, `TransmitPower`, `OperatingStandards`. **`TransmitPower` is a percentage of `TransmitPowerMax`, not dBm** — confirmed live (`TransmitPower: -1`, `TransmitPowerSupported: '-1,0,10,20,30,40,50,60,70,80,90,100'`, `TransmitPowerMax: 31.5`, `TransmitPowerControlMode: 'Disable'`); `-1` specifically means automatic power control, not a literal power level (mapped to `None` in `WifiRadioInfo.tx_power_percent`, not passed through as `-1%`). |
| `Device/WiFi/AccessPoints/AccessPoint[Alias="X"]/AssociatedDevice` | ❌ | **Does not exist on this firmware** — `XMO_UNKNOWN_PATH_ERR`. Despite this being the form most XMO docs/examples (and the `iMicknl/python-sagemcom-api` library) suggest. |
| `Device/WiFi/AccessPoints/AccessPoint[Alias="X"]/AssociatedDevices` | ✅ | **This is the real per-client WiFi data source** (note the plural — confirmed live, solves what `Device/Hosts` can't: real `SignalStrength` in dBm, `LastDataDownlinkRate`/`LastDataUplinkRate` in **kbps** (confirmed: 72222 ≈ `MaxBitRate` 72200 for an 802.11n client), `Active`, `MACAddress`, and cumulative `Stats.BytesSent`/`Stats.BytesReceived`. **Direction gotcha, confirmed empirically against live traffic**: from the AP's own perspective, `Sent` is AP→device (the device's *download*) and `Received` is device→AP (the device's *upload*) — the **opposite** of the WAN interface's Sent/Received convention (there, `Sent` = upload to the internet). Get this backwards and up/down are swapped in the UI. Valid `AccessPoint` aliases on this unit (fixed set, not user-configurable): `PRIV0`, `VID1`, `GUEST2G`, `GUEST5G`, `AP_BACKHAUL` — query all of them and merge by MAC to cover every band/SSID. A device mid-roam can have a stale entry on one AP and a live one on another; prefer whichever has `Active: true`. |

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
| `Device/IP/Interfaces/Interface[Alias='IP_DATA']` | ✅ | Confirmed live — fetch the whole object, not just `/Status`: `Status` (`UP`\|`DOWN`), `LowerLayers` (references a `Device/PPP/Interfaces/...` path when the WAN mode is PPPoE — used to infer `wan_mode` since `CurrentWanMode` below doesn't exist), and `IPv4Addresses[0].IPAddress` for the actual WAN IP (**not** a top-level field — it's nested one level deeper than `/Status` was fetching). Response wraps as `{"Interface": {...}}` — note the `[Alias='IP_DATA']` qualifier is stripped from the wrapper key by the router, see `_extract_result`. |
| `Device/IP/Interfaces/Interface[Alias='IP_DATA']/Stats/*` | ✅ | Total household bytes. Confirmed live — not just resolving but genuinely correct: cross-checked `SagemcomXmoAdapter.get_wan_stats()`'s output against the live `wan_stats` DB table (98 rows, plausible varying throughput). `BytesSent`/`BytesReceived` present as named. |
| `Device/IP/Interfaces/Interface[Alias='PPP_DATA']/Stats/*` | ⬜ | PPPoE stats |
| `Device/IP/Interfaces/Interface[Alias='IP_IPTV']/Status` | ⬜ | IPTV interface — unverified since the Hosts xpath mismatch was found |
| `Device/Services/NetworkCfg/CurrentWanMode` | ❌ | **Does not exist on this firmware** — `XMO_UNKNOWN_PATH_ERR`, confirmed live despite this doc previously marking it ✅. `wan_mode` is inferred instead from whether `IP_DATA`'s `LowerLayers` references a PPP interface. The real xpath for this, if one exists, hasn't been found yet. |
| `Device/DeviceInfo` → `MACAddress` | ✅ | This is the WAN MAC — **not** a `WANMACAddress` field, which doesn't exist on this firmware (the adapter previously looked for it and always got `''`). |
| `Device/WiFi/SSIDs` | ✅ | Confirmed live. Returns a **bare list** (no wrapper dict, unlike `Device/Hosts`) of SSID objects, each with an `SSID` field holding the actual broadcast name (e.g. `"MyHomeWiFi"`). The same name typically appears twice — once per radio band (2.4GHz/5GHz) — dedupe before display. |

---

## Firewall Layer

| XPath | Status | Notes |
|-------|--------|-------|
| `Device/Firewall/Chain` | ✅* | Chains confirmed live, including a distinct `"Custom"` chain — **but this is a routed-IP firewall chain**, not device-level LAN exclusion. A `Custom`-chain rule only affects traffic that's actually routed through the firewall (WAN-bound, or cross-VLAN); it has **no effect on purely local LAN/WiFi traffic** — e.g. it does not stop ARP spoofing between two devices on the same segment. Confirmed by attempting exactly this: a device blocked via a Custom-chain DROP rule stayed fully connected and kept spoofing. Do not use this chain for `block_device()`. |
| `Device/Firewall/Chains/Chain[Name="Custom"]/Rules` (`addChild`) | ✅ | Real xpath/method for adding a custom firewall rule (method is `addChild`, **not** `addObject` as the generic XMO docs suggest — confirmed live). Payload is nested: `{"value": {"Rule": {...}}}`. Created rules report `Status: "DISABLED"` unless the router's active firewall security level is actually set to `"Custom"` (see `Device/Firewall/Levels/Level[Name="Custom"]/DefaultPolicy`, confirmed `"DROP"` on this unit) — check that before relying on rules here for anything. |

## Device blocking — the real mechanism (confirmed live)

The router's own Devices-page "block" action does **not** touch the Firewall
layer at all. It blacklists the device's own `Device/Hosts/Hosts/Host` entry
24/7 via its `BlacklistedSchedule` — confirmed via a live DevTools capture of
clicking Block for a real device (`4C:ED:DE:75:02:76`, host uid 93) on
2026-07-19. This is enforced at the same DHCP/host-management layer that
already tracks device presence, so — unlike the Firewall-chain approach — it
does actually remove the device from the LAN, not just its WAN access.

Every `Host` entry defaults to `BlacklistEnable: true` and
`BlacklistedAccordingToSchedule: true`, so setting the schedule alone is
sufficient — no separate "enable blacklisting" step needed. `Blacklisted` and
`BlacklistStatus` are read-only/computed; don't try to `setValue` them
directly.

### Resolve MAC → host uid

```json
{"method": "getValue", "xpath": "Device/Hosts/Hosts"}
```
Find the entry whose `PhysAddress` matches (case-insensitive), read its
`uid`.

### Block device (setValue x168)

One `setValue` per hour of every day — `ManagementDay[@uid]` runs 1=SUNDAY
through 7=SATURDAY, `HoursN` runs 0-23. The router's own UI batches these into
~90-action requests rather than sending all 168 in one shot:

```json
{
  "method": "setValue",
  "xpath": "Device/Hosts/Hosts/Host[@uid=\"93\"]/BlacklistedSchedule/ManagementDay[@uid=\"1\"]/Hours0",
  "parameters": {"value": true}
}
```
...repeated for every `(day_uid, hour)` pair, `day_uid` in 1-7, `hour` in
0-23 (168 actions total).

### Unblock device

Identical, with `"value": false` for every action.

### A separate, likely-cosmetic action also fires on block

```json
{
  "method": "addChild",
  "xpath": "Device/Services/ParentalControl/Categories/UserProfiles/Hosts",
  "parameters": {"value": {"Host": {"uid": null, "MAC": "4C:ED:DE:75:02:76"}}}
}
```
Associates the MAC with a Parental Control user profile — this appears to be
for UI categorization, not enforcement (the `BlacklistedSchedule` write above
is what actually removes the device from the network). `block_device()` does
not replicate this step.

---

## Remaining captures needed

Given `Device/Hosts/Host` turned out not to exist despite being marked ✅,
**every xpath below that hasn't been re-confirmed against a live login on
this specific firmware should be treated as unverified**, not just the
"CRITICAL" row — the generic XMO docs this file was originally built from
don't reliably match this ISP's customized data model.

| Priority | Navigate to | Reveals |
|----------|-------------|---------|
| ~~CRITICAL~~ ✅ done | ~~Access Control → Parental Control → add temp block → capture XHR~~ | Solved: `BlacklistedSchedule` on the device's own `Device/Hosts/Hosts/Host` entry, not the Firewall layer — see "Device blocking — the real mechanism" above |
| ~~CRITICAL~~ ✅ done | ~~WiFi client list / Connected devices page~~ | Solved: `Device/WiFi/AccessPoints/AccessPoint[Alias="X"]/AssociatedDevices` — see WiFi Layer above |
| Important | Ethernet ports page (DevTools open) | `Device/Ethernet/Interfaces/Interface[Alias="PHY{N}"]/Stats` — the resolving question is now settled (still resolves), but the Sent/Received direction is still **unverified**: `SagemcomXmoAdapter.get_port_stats()`/`_get_port_traffic_samples()` now apply the same swap as the confirmed WiFi `AssociatedDevices/Stats` fix, purely on that precedent — nobody has captured live wired traffic to confirm the wired interface actually follows the same convention. Capture a real upload/download on a known wired device and compare against the Ports page to confirm or revert. |
| ~~Important~~ ✅ done | ~~WAN → Statistics~~ | Solved: `IP_DATA/Stats/*` confirmed correct and already working in production — see WAN Layer above |
| ~~Useful~~ ✅ done | ~~WiFi → Stats (DevTools open)~~ | Solved: Radio alias is `RADIO2G4`/`RADIO5G` on this firmware (not `wl0`/`wl1`), `Channel`/`TransmitPower`/`OperatingStandards` field names confirmed correct, and `TransmitPower` is a percentage (not dBm) — see WiFi Layer above. Also found and fixed a real bug in the same pass: the bare `Device/WiFi/Radios/Radio` path only ever returned one radio. |
