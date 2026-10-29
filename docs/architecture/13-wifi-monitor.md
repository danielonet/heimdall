# 13. WiFi Monitor — Rogue AP Detection & Nearby Device Sightings

**Document**: Heimdall Design Document v1.0
**Topic**: 802.11 monitor-mode sniffing · Rogue/evil-twin AP detection · Nearby unassociated device inventory

> **Resolves**: `docs/capability-review.md` item #4 ("Rogue AP / evil-twin detection") — previously marked
> *"Skipped — confirmed blocked, not just unbuilt... no spare monitor-mode-capable hardware was confirmed
> available"*. A MediaTek MT7921U USB adapter is now available and live-verified.

---

## 1. Purpose & Scope

Neither router adapter (Sagemcom XMO, MiWiFi stok) exposes anything about WiFi devices that never associate
with the network — both only ever list *currently-connected* clients. Seeing a neighbor's phone, a drive-by
device, or (the actual security case) an attacker's AP impersonating your own SSID requires reading raw
802.11 management frames off the air, which needs a WiFi radio in **monitor mode** — a fundamentally
different capability from anything a router's own management API can provide.

Two things this module answers:

1. **Rogue AP / evil-twin detection**: is anything nearby broadcasting *our* SSID from a BSSID that isn't one
   of our own access points? This is a genuine attack signal — CRITICAL, routed through the same
   `_raise_threat_alert` choke point as ARP spoofing / rogue DHCP.
2. **Nearby WiFi device inventory**: what MACs have been overheard nearby via probe requests, whether or not
   they've ever joined this network? Passive presence data, not a threat finding — surfaced on its own WIFI
   tab, never through the Alerts pipeline.

### Live verification (2026-09-18)

A MediaTek MT7921U USB WiFi adapter (`mt7921u` driver, dual-band WiFi 6) was confirmed monitor-mode-capable
via `iw phy1 info`'s "Supported interface modes" list, and a manual capture —

```
ip link set wlx90de8047f3c5 down
iw dev wlx90de8047f3c5 set type monitor
ip link set wlx90de8047f3c5 up
tcpdump -i wlx90de8047f3c5 -e type mgt
```

— captured real neighboring APs' beacon frames (BSSID, SSID, `dBm_AntSignal`) within seconds. Every module
below wraps exactly this mechanism.

### v1 scope cuts (deliberate, stated up front)

- **2.4GHz channels 1/6/11 only.** A monitor-mode radio only ever hears one channel at a time, so seeing
  more than one requires hopping — this v1 hops only the three non-overlapping 2.4GHz channels (where the
  live test capture found every neighbor, and where the vast majority of home/neighboring APs sit). No
  5GHz/6GHz hopping yet.
- **No automatic blocking of a rogue AP.** There's no `Device`/client to block — a rogue AP's own radio MAC
  isn't something `adapter.block_device()` can act on. Falls out naturally: `_raise_threat_alert` is called
  with `mac=None`, and its block-attempt branch (`elif mac:`) is a no-op for a falsy MAC.
- **No mute/ignore UI for nearby sightings.** Read-only list. A neighbor's device showing up forever isn't a
  problem worth solving before the core feature ships.
- **No new Docker service.** Runs in-process inside `sentinel-backend`, exactly like `ArpWatcher`/
  `DhcpWatcher`/`PassiveFingerprinter` — that container already runs `network_mode: host` with
  `NET_ADMIN`/`NET_RAW` (docker-compose.yml), the exact capabilities monitor-mode entry needs. Confirmed live
  that a bare (non-Docker) dev process lacks these — `ip link set ... down` fails with `Operation not
  permitted` outside the container's granted capabilities, and the watcher degrades cleanly (logs, stays
  inactive) rather than crashing anything, same posture as ArpWatcher's NET_RAW-denied path.

## 2. Architecture

### 2.1 New files

| File | Role |
|---|---|
| `sentinel/security/wifi_iface.py` | Enumerates monitor-capable WiFi interfaces (`iw dev` + `iw phy <n> info`); switches an interface into/out of monitor mode; sets its channel. |
| `sentinel/security/wifi_monitor.py` | `WifiMonitorWatcher` — the sniffer itself. |
| `sentinel/db/models.py:WifiSighting` | One row per distinct nearby MAC. |
| `sentinel/db/repositories.py:WifiSightingRepository` | Upsert-by-MAC + recent-list query. |
| `sentinel/api/routes/wifi.py` | `GET /api/wifi/sightings`, `GET /api/wifi/monitor-interfaces`. |
| `frontend/src/pages/WifiScanPage.jsx` | The WIFI nav tab — read-only sightings table. |
| `frontend/src/components/settings/WifiMonitorSection.jsx` | Equipment-page panel (moved from Settings): adapter picker + protected-SSID/trusted-BSSID chip editors, and "Detect from my router" (`GET /api/wifi/suggestions`, `build_suggestions()` in `sentinel/api/routes/wifi.py`): the SSIDs come from `RouterInfo.ssids`, the BSSID candidates from heard `wifi_networks` rows; a candidate whose OUI equals the router's MAC is pre-ticked, nothing is saved until the admin presses SAVE. |

### 2.2 `WifiMonitorWatcher` — the house sniffer pattern, extended

Same shape as `ArpWatcher`/`DhcpWatcher`/`PassiveFingerprinter`: a Scapy `AsyncSniffer` on its own OS thread
(the blocking read lives entirely outside the asyncio loop — the only `async` boundary is the
`asyncio.run_coroutine_threadsafe` hand-off into the scheduler, same as the other three), plus a watchdog
thread that detects the sniffer dying. Two things are new:

- **`start()` first calls `wifi_iface.enter_monitor_mode(iface)`** — unlike the other three watchers, which
  sniff an already-up promiscuous interface, this one must actively reconfigure the radio first. A failure
  here (no such interface, not monitor-capable, no `NET_ADMIN`) is logged and the watcher simply never starts
  sniffing — never raises.
- **A second daemon thread hops channels** (`_hop_channels`, `[1, 6, 11]` every 0.5s via
  `wifi_iface.set_channel`) — nothing else in this codebase needs this, since ARP/DHCP/TCP sniffing on a
  wired-or-associated interface doesn't have a "channel" concept at all.

`_process(pkt)` runs on every frame the sniffer delivers and discards everything except beacons and probe
requests. There is deliberately no BPF filter: Scapy compiles one by shelling out to `tcpdump`, which doesn't
inherit this process's capabilities in the non-root dev setup (confirmed live 2026-09-19).

- Both frame types are management frames:

- **`Dot11Beacon`**: extract SSID (`Dot11Elt` ID 0) + BSSID (`addr2`) + `dBm_AntSignal`. If the SSID is in
  the configured protected list and the BSSID is *not* in the trusted list → fires a `ROGUE_AP` alert event.
- **`Dot11ProbeReq`**: extract source MAC + probed SSID (if any, `''`/hidden is common and expected) + signal
  → fires a sighting event, unconditionally (every MAC, not just unrecognized ones — the point is presence,
  not filtering).

### 2.3 Scheduler wiring (`sentinel/scheduler/scheduler.py`)

- `self._wifi_monitor: WifiMonitorWatcher | None` — unlike `_arp_watcher`/`_dhcp_watcher`/`_fingerprinter`,
  this stays `None` unless an admin has actually configured `wifi_monitor_iface`. There's no env-config
  fallback (`Settings.WIFI_MONITOR_IFACE`) the way `SNIFF_IFACE` has one — no deployment can assume a second,
  monitor-capable adapter is physically present.
- `_resolve_wifi_monitor_config()` reads `(iface, protected_ssids, trusted_bssids)` from `SettingsRepository`
  at boot, same "best-effort, never crash the scheduler thread over a transient DB hiccup" posture as
  `_resolve_sniff_iface`.
- `_startup_job` starts it (if constructed) alongside the other three, same try/except-log wrapper.
- `_on_wifi_alert`/`_persist_wifi_alert`: routes a `ROGUE_AP` event straight to `_raise_threat_alert(None,
  ...)` — the single choke point every other attack-signal source in this codebase already uses, so it gets
  auto-block-skip-for-null-mac, mitigation copy, WebSocket emission, and notification, all for free.
- `_on_wifi_sighting`/`_persist_wifi_sighting`: routes to `WifiSightingRepository.upsert` — **never**
  `_raise_threat_alert`. This is the hard line between the two output types described in §1.
- `reload_wifi_monitor(iface, protected_ssids, trusted_bssids)`: the Settings-tab hot-apply path (mirrors
  `restart_sniffers`), called from the Flask request thread directly (safe — `WifiMonitorWatcher` never
  touches the asyncio loop). Handles first-time enable (watcher didn't exist yet), disable (`iface` blank →
  stop and drop the reference), interface change (restart), and SSID/BSSID-list-only edits (no restart
  needed, just `update_targets`).
- `_data_retention_job` prunes `wifi_sightings` the same way it prunes `alerts` — a plain `DELETE ... WHERE
  last_seen < cutoff`, reusing `data_retention_days` rather than a dedicated retention knob.

## 3. Data model

```sql
-- app_settings additions
wifi_monitor_iface    VARCHAR(20)              -- NULL = disabled
wifi_protected_ssids  TEXT[] NOT NULL DEFAULT '{}'
wifi_trusted_bssids   TEXT[] NOT NULL DEFAULT '{}'   -- lowercased on write

-- new table
CREATE TABLE wifi_sightings (
    mac_address           TEXT PRIMARY KEY,
    vendor_name           TEXT NOT NULL DEFAULT '',   -- '' for randomized MACs, same as everywhere else
    first_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen             TIMESTAMPTZ NOT NULL DEFAULT now(),
    strongest_signal_dbm  INTEGER,                     -- max ever seen, not most recent
    times_seen            INTEGER NOT NULL DEFAULT 1,
    last_probed_ssid      VARCHAR(32)
);
```

No FK to `devices` — deliberately: a sighting is very often a MAC that never becomes a `Device` at all (see
`sentinel/security/wifi_monitor.py`'s module docstring for why this couldn't reuse the `Device` model —
no IP, no router-reported `ap_alias`/traffic granularity, none of what `Device` is actually shaped around).

## 4. Alert type & mitigation

`ROGUE_AP` (CRITICAL, `device_mac=NULL`) — added to `sentinel/security/remediation.py`'s `_BUILDERS` dict and
to `ServiceStatusPanel.jsx`'s `ALERT_TYPES_BY_SERVICE`/`system.py`'s `_SERVICE_ALERT_TYPES` (kept in sync
across languages, same convention every other service row already follows) so an open rogue-AP alert lights
up the WIFI MONITOR row on the dashboard exactly like every other service's ALERT state.

## 5. Equipment tab

The "WIFI MONITOR" panel (it began on the Settings tab and now sits in its own card on the Equipment tab) (`WifiMonitorSection.jsx`): an adapter dropdown sourced from `GET
/api/wifi/monitor-interfaces` (only genuinely monitor-capable adapters — confirmed live that a laptop's
built-in WiFi card can legitimately report monitor-mode support too, so this isn't just "USB dongles"), plus
two chip-list editors for protected SSIDs and trusted BSSIDs. `PATCH /api/settings` validates all three
fields (interface must be one of the detected list or blank; SSIDs non-empty ≤32 chars, ≤20 entries; BSSIDs
must match a MAC pattern, ≤20 entries) before persisting and calling `SentinelScheduler.reload_wifi_monitor`.

## 6. API endpoints

| Endpoint | Description |
|---|---|
| `GET /api/wifi/sightings` | Nearby-device inventory, most recently seen first. |
| `GET /api/wifi/monitor-interfaces` | Monitor-capable WiFi adapters on this host. |

## 7. Deployment note

**Non-root dev setup** (confirmed working 2026-09-19): `sudo setcap cap_net_raw,cap_net_admin+eip
.venv/bin/python3.14` once, then restart. `wifi_iface._raise_ambient_net_admin()` raises `CAP_NET_ADMIN` into
the *calling thread's* ambient set before each `ip`/`iw` subprocess, since file capabilities are otherwise
dropped on exec and are per-thread on Linux.

Live-tested against the bare dev process (`flask run`, no elevated privileges): `enter_monitor_mode` fails
cleanly with a logged `Operation not permitted` and the watcher stays inactive — exactly the intended
degrade-gracefully behavior, not a bug. In the real Docker deployment, `sentinel-backend` already runs
`network_mode: host` with `cap_add: [NET_RAW, NET_ADMIN]`, so this works with zero additional compose
changes once a monitor-capable adapter is plugged into the host.

## 8. Testing

`tests/test_security/test_wifi_iface.py`, `tests/test_security/test_wifi_monitor.py` (mocked `Dot11Beacon`/
`Dot11ProbeReq` packets exercising `_process`'s SSID/BSSID matching logic directly, no real radio needed),
`tests/test_db/test_wifi_sighting_repository.py`, `tests/test_api/test_wifi.py`.
