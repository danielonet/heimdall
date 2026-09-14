# MiWiFi API (Redmi/Xiaomi second router)

> ✅ **Confirmed live 2026-09-13** against this project's actual Redmi unit
> (platform `RA67`, firmware `1.4.31`), running in **AP/bridge mode**
> (`xqnetwork/mode` → `mode: 2`, `hostip` pointing at the Sagemcom). Login,
> router info, and the AP-mode device-list fallback below are all confirmed
> against live responses, not just reproduced from community documentation
> — entries below say so explicitly. Anything still marked ⚠️ **unverified**
> (block/unblock, quarantine) has not been exercised live and may need
> correcting the same way — see each section for how.

## Why this exists

Heimdall's adapter layer (see `docs/architecture/02-router-adapter.md`) only
had one implementation, for a Sagemcom router, until a second physical
router — a Redmi unit on stock MiWiFi firmware — was added to the household
network. `sentinel/adapter/miwifi/` is that second adapter. It is
**optional**: leaving `MIWIFI_IP` blank (the default) means Heimdall behaves
exactly as it did with only the Sagemcom.

## Authentication — stok-token login

✅ Confirmed live. MiWiFi's admin API session is a `stok` token appended to
every authenticated request's URL path (not a header/cookie):

```
POST http://{router_ip}/cgi-bin/luci/api/xqsystem/login
  Content-Type: application/x-www-form-urlencoded

  username=admin
  logtype=2
  nonce=0_heimdall_{unix_seconds}_{random}
  password={sha1(nonce + sha1(password + KEY))}
```

`KEY` is a fixed, publicly-known constant baked into the router's own
web JS (`js/xqjson.js`/`js/login.js`), not a per-device secret:
`a2ffa5c9be07488bbb04a3a47d3c5f6a`.

A successful response looks like `{"code": 0, "token": "<stok>", "url": "..."}`.
Every subsequent request is:

```
GET http://{router_ip}/cgi-bin/luci/;stok={stok}/api/{endpoint}
```

See `sentinel/adapter/miwifi/miwifi_auth.py` / `miwifi_client.py:MiwifiClient.login`.

## Device list — two shapes depending on router mode

**This unit's actual mode matters a lot** — confirmed live it changes which
endpoint has any data at all:

```
GET .../api/xqnetwork/mode
  -> {"mode": 2, "hostip": "10.100.102.1", "hostname": "MiWiFi--srv", "code": 0}
```

`mode: 0` = router/gateway (this unit runs its own DHCP/NAT). `mode: 2` =
AP/bridge (this unit just extends WiFi onto an upstream network's subnet —
`hostip` is that upstream router's IP). `mode: 1` (repeater) is presumably a
third variant, not tested.

### Router mode (`mode: 0`) — richer shape, NOT live-tested

```
GET .../api/misystem/devicelist
  -> {
    "mac": "<router's own MAC>",
    "list": [{
      "mac": "AA:BB:CC:DD:EE:FF", "oname": "some-hostname", "online": 1,
      "ip": [{"ip": "192.168.31.100"}],
      "statistics": {"upload": "10485760", "download": "104857600"}
    }]
  }
```

⚠️ Still just reproduced from community documentation for this mode — this
project's unit runs in AP mode, so this shape has never actually been
observed live. `MiwifiAdapter._get_device_list()` tries this endpoint
first; if it comes back with a non-empty `list`, its `ip`/`oname`/
`statistics` fields are used for IP/hostname/cumulative traffic (fed through
the same `TrafficDeltaCalculator` XmoClient uses).

### AP/bridge mode (`mode: 2`) — ✅ confirmed live, much sparser

```
GET .../api/misystem/devicelist
  -> {"mac": "50:B7:C3:B3:AA:A4", "list": [], "code": 0}   # ALWAYS empty in this mode

GET .../api/xqnetwork/wifi_connect_devices
  -> {"list": [{"mac": "42:95:72:12:49:26", "wifiIndex": 1, "signal": 46}], "code": 0}
```

Confirmed live: an AP-mode node's `misystem/devicelist` is always empty —
it doesn't run DHCP or route traffic, so it has nothing to put there. The
real (only) client list in this mode is `xqnetwork/wifi_connect_devices`,
and it is **much sparser**: just `mac`, `wifiIndex` (which radio), and
`signal` — no IP, no hostname, no traffic counters at all. `signal`'s scale
is **not** dBm (observed values were 46, 94, 102 — dBm would be negative) —
unconfirmed what scale it actually is, so it's deliberately left unmapped
to `signal_strength_dbm` rather than guessed. `online` is also absent
entirely on this shape; `_to_device_snapshot` treats a missing `online` key
as "present in this list == currently connected" (default `1`, not `0`) —
this endpoint has no way to list a disconnected client at all, so an
absent key doesn't mean "offline" the way it might in the richer shape.

**Practical consequence for this topology**: a Redmi in AP/bridge mode
genuinely cannot report per-device traffic through *any* endpoint found so
far (`misystem/bandwidth_test`, `netctrl/getipbandwidth` and a few other
guesses all 404'd/errored outright, not gracefully). `get_traffic_samples()`
still runs correctly — it just returns real, honest zero-deltas for every
device in this mode, not fabricated numbers. Presence (who's connected,
live, tagged `source_router: miwifi`) works fully; bandwidth attribution
for those devices does not, and there's no known API fix for that while
this unit stays in AP mode — see `docs/router/network-topology.md`.

## Router info / WAN status — ✅ confirmed live

```
GET .../api/misystem/status
  -> {
    "hardware": {"mac": "8C:DE:F9:1A:5D:7E", "platform": "RA67", "version": "1.4.31", "sn": "..."},
    "upTime": "10793.21", "count": {"online": 0, "all": 0}, ...
  }
GET .../api/xqnetwork/wan_info
  -> {"info": false, "code": 0}   # AP mode: no WAN interface at all
GET .../api/xqnetwork/wifi_diag_detail_all
  -> {"info": [{"ssid": "Redmi_A1B2_C3D4", "password": "...", ...}, {...}], "code": 0}
```

Confirmed live, corrected from an earlier draft of this doc: `hardware.
platform` (e.g. `RA67`) is the model identifier, not `hardware.version`
(that's a firmware/software version number, `1.4.31`) — the two were
initially swapped. There is no top-level `rom` field on this firmware.
`wan_info`'s `info` key is the literal boolean `false` in AP mode (not an
object) — `get_router_info()` maps that to `wan_status: 'UNKNOWN'`
explicitly rather than falling through to the reply's numeric `code`.
`upTime` is a numeric *string with a decimal point* (`"10793.21"`), which a
bare `int()` rejects — parsed via `float()` first.

SSIDs come from `xqnetwork/wifi_diag_detail_all`'s per-radio `ssid` field —
confirmed live. That same response also carries each radio's WiFi password
in plaintext under `password`; `MiwifiAdapter` deliberately reads only
`ssid` from it and that value is never stored or logged anywhere.

## Blocking a device — ⚠️ still unverified

```
POST .../api/xqnetwork/set_mac_filter
  mac={mac}
  enable=1   (or 0 to unblock)
```

Not yet exercised live (didn't want to actually block a real device on the
household network to check). MiWiFi's device block/deny-list feature is
sometimes only exposed through the Mi Home mobile app rather than this web
API, and the exact endpoint varies across firmware forks. **If
`block_device`/`unblock_device` don't actually work**: block a test device
by hand from the router's own web UI (Device management → block), capture
that exact request from devtools, and fix
`MiwifiAdapter.block_device`/`unblock_device` to match.

## Known gaps (by design, not oversights)

| Capability | Status |
|---|---|
| Per-device traffic in AP/bridge mode | ✅ Confirmed unavailable via any endpoint found — see "AP/bridge mode" above. Not a bug; there is currently no known API fix short of switching this unit to router mode (a bigger topology change with its own tradeoffs). |
| Per-port Ethernet stats | Not available — consumer MiWiFi firmware exposes no per-port counter API. `get_port_stats()` always returns `[]`. |
| WAN-only "quarantine" tier | No known equivalent to Sagemcom's Firewall Custom-chain rule. `quarantine_device()`/`unquarantine_device()` always return `False` — see their docstrings. |
| Household WAN byte counters | No confirmed cumulative-counter endpoint (and none makes sense for an AP-mode unit, which has no WAN interface at all — confirmed live). `get_wan_stats()` always returns `None`. |
| DHCP lease table | No distinct DHCP-server endpoint, and none would return anything in AP mode anyway (this unit doesn't run DHCP) — `get_dhcp_leases()` derives MAC/IP pairs from the device list itself, which means it's also empty in AP mode (no IP data there either). |

## Topology note

✅ Confirmed live for this deployment: this unit runs in **AP/bridge mode**
on the same subnet as the Sagemcom (`xqnetwork/mode` → `hostip:
10.100.102.1`), wired into the Sagemcom's LAN (its own MAC,
`50:B7:C3:B3:AA:A4`, appears as a wired `Ethernet`/`PHY2` host in the
Sagemcom's own device list). See `docs/router/network-topology.md`'s
"Second router" section for what that means for device de-duplication and
for which security detectors can see this router's clients at all.
