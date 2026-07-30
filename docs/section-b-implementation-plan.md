# Section B: rogue DHCP detection, WAN bandwidth tracking, AP-alias visibility, WiFi channel visibility, wired-PHY direction fix

*Saved from the plan-mode scratch file before starting Section D, whose
plan now occupies that same path. See `docs/zeek-clamav-implementation-plan.md`
for the note on why this file exists — same reason.*

## Context

`docs/capability-review.md`'s Section B ("Extract more from the router/WiFi
hardware") proposed 6 items (#4-#9). Two rounds of research (parallel
subagent survey + direct file reads) and 3 scope-clarifying questions
narrowed this to 5 buildable items:

- **#4 Rogue AP detection — SKIPPED.** Confirmed: needs a WiFi radio in
  monitor mode to see beacon frames from unassociated APs. The current
  `SNIFF_IFACE` (`eth0` by default, `docker-compose.yml`'s
  `network_mode: host` + `NET_RAW`/`NET_ADMIN`) is a normal wired/LAN
  promiscuous interface — monitor mode is a fundamentally different radio
  mode nothing in this codebase sets up, and no spare monitor-mode-capable
  hardware was confirmed available. Not attempted.
- **#5 Rogue DHCP server detection — full build.** Confirmed buildable
  exactly as originally scoped: broadcast DHCP OFFER packets are ordinary
  visible traffic on a promiscuous wired interface (unlike 802.11 beacons),
  so this reuses `ArpWatcher`'s exact sniffing pattern.
- **#6 WAN/household bandwidth tracking — build defensively.** The
  `IP_DATA/Stats/*` xpath is a genuine guess-by-analogy in
  `docs/router/sagemcom-xmo-api.md` (marked ⬜ "expected based on firmware
  conventions but unverified", no observed field list) — same posture as
  Zeek's file-analysis framework earlier this session: build it, degrade
  gracefully if the xpath 404s, verify against the live router afterward.
- **#7 Guest network isolation check — descoped to AP-alias visibility.**
  Confirmed not buildable as originally conceived: the XMO API exposes no
  traffic-flow/netflow data (only cumulative per-host/per-port/per-AP
  counters), and there's no confirmed guest-vs-private subnet split to key
  off of even as a proxy. What *is* a real, fixable gap: the adapter already
  fetches each device's AP alias (`GUEST2G`/`GUEST5G`/`PRIV0`/etc.) while
  merging `_get_associated_devices()`, then **discards it** before it
  reaches `DeviceSnapshot` — item #19 in the capability review ("you already
  know which AP each device is on") is actually false today. Fixing that
  plumbing gap and surfacing it is the descoped version of #7.
- **#8 WiFi channel/interference visibility — full build.** `Device/WiFi/
  Radios/Radio`'s channel/TX power/standard fields are confirmed solid
  (✅, not the unverified `/Stats` sub-path) — never read by the adapter at
  all today.
- **#9 Wired-PHY Sent/Received direction — fix now.** The WiFi
  `AssociatedDevices` path had this exact swap bug (AP-side "Sent" =
  device's download, not upload), confirmed live and fixed
  (`xmo_adapter.py`'s `get_traffic_samples()`). The wired `PHY{N}/Stats`
  path reads the same two raw fields with no relabeling at all, and no
  comment anywhere flags it as verified. Per user's direction: apply the
  same fix now on that precedent, without live re-verification.

---

## #5 — Rogue DHCP server detection

**New file `sentinel/security/dhcp_watch.py`** — mirrors
`sentinel/security/arp_watch.py`'s `ArpWatcher` class structure exactly
(same `AsyncSniffer(..., store=False, started_callback=...)` pattern,
same `_watch_for_failure`/`is_active`/`restart()` shape), sniffing
`filter='udp and (port 67 or port 68)'` and using scapy's `BOOTP`/`DHCP`
layers (already available via the pinned `scapy>=2.5` dependency — no new
import needed elsewhere in the codebase). `DhcpWatcher.__init__(self,
alert_callback, iface, expected_server_ip)` — takes the router's own LAN
IP as the "expected" DHCP server, since there's no dedicated "router MAC"
field anywhere in the schema (`RouterInfo.wan_mac` is the *WAN*-side MAC,
not LAN-side — confirmed wrong value to use).

`_process(self, pkt)`: filters to DHCP OFFER (`message-type` option == 2),
reads `pkt[IP].src` (the offering server's own IP) and `pkt[Ether].src`
(its MAC); if `pkt[IP].src != self._expected_server_ip`, fires
`self._callback({'type': 'ROGUE_DHCP_SERVER', 'severity': 'CRITICAL',
'ip': ..., 'mac': ..., 'description': ...})`.

**Resolving `expected_server_ip`**: reuse `sentinel/adapter/discovery.py`'s
`discover_gateway_ip()` (already the exact function `create_router_adapter()`
uses to resolve `ROUTER_IP` when blank) — add a
`SentinelScheduler._resolve_router_ip()` helper mirroring the existing
`_resolve_sniff_iface()` pattern (reads `settings.ROUTER_IP`, falls back to
`discover_gateway_ip()`), called once in `_run_loop` before constructing
the watcher.

**Scheduler wiring** (`sentinel/scheduler/scheduler.py`) — mirrors
`ArpWatcher`'s wiring at every point: `self._dhcp_watcher:
DhcpWatcher | None = None` in `__init__`; constructed in `_run_loop`
alongside `self._arp_watcher`; `.start()` in `_startup_job` (no seeding
needed — it only needs the one `expected_server_ip` value, not a table);
`_on_dhcp_alert`/`_persist_dhcp_alert` sync-callback-bridge pair mirroring
`_on_arp_alert`/`_persist_arp_alert` exactly, routing through the existing
`_raise_threat_alert` (attributes the alert to the rogue device's MAC if
it resolves to a known `Device` row, same lookup pattern `_persist_canary_alert`
already uses); added to `restart_sniffers()` and
`security_services_snapshot()` (`dhcp_watch_active`) alongside the other
watchers.

**Frontend**: add a "DHCP Watch" row to `ServiceStatusPanel.jsx`, same
`Row` shape as `ARP Watch`.

**Tests**: `tests/test_security/test_dhcp_watch.py` mirroring
`tests/test_security/test_arp_watch.py`'s structure (hand-built scapy
packets, direct `_process()` calls, no live sniffing). Scheduler-level
test extending the `object.__new__(SentinelScheduler)` pattern for
`_persist_dhcp_alert`.

---

## #7 — AP-alias visibility (descoped from guest isolation)

**`sentinel/adapter/sagemcom/xmo_adapter.py`'s `_get_associated_devices()`**
(lines 418-456): currently loops `for i, alias in enumerate(_ACCESS_POINT_ALIASES)`
and merges every AP's clients into one `by_mac` dict, discarding which
`alias` each entry came from. Fix: stamp `client['_ap_alias'] = alias`
before the merge, so it survives into `_to_device_snapshot()`.

**`sentinel/adapter/models.py`**: add `ap_alias: str = ''` to
`DeviceSnapshot`. **`_to_device_snapshot()`**: read
`client.get('_ap_alias', '')` into the new field (blank for wired devices,
which don't have one).

**DB**: new migration (`down_revision` = current head `c3d8e5a1f907`)
adding `devices.ap_alias VARCHAR(20)`, mirroring `c3d8e5a1f907_device_type.py`
exactly. Wire through `sentinel/scheduler/jobs.py`'s insert/update
(`ap_alias=snapshot.ap_alias or None`, same two spots `device_type` was
added), `sentinel/api/serializers.py`'s `device_to_dict()`, and
`sentinel/adapter/mock/mock_adapter.py` (set `ap_alias='PRIV0'` on the
mock WiFi devices, `ap_alias='GUEST2G'` on the existing `guest-phone` mock
device — it's already named for this and currently has no AP data behind
that name).

**Frontend**: small badge next to the existing device-type badge on
`DevicesPage`/device-detail views (`GUEST2G`/`GUEST5G` in the amber/warning
color family since it's worth an admin's attention which devices are on
guest bands; `PRIV0`/`VID1`/`AP_BACKHAUL` neutral). No isolation-violation
claim anywhere in the UI copy — purely "here's which network this device
is on."

**Tests**: extend `tests/test_adapter/test_xmo_adapter.py` for the
`_ap_alias` stamping + `DeviceSnapshot.ap_alias` propagation. Extend
`tests/test_db/test_models.py`/serializer tests for the new column.

---

## #6 — WAN/household bandwidth tracking (defensive)

**`sentinel/adapter/base.py`**: new abstract method
`get_wan_stats(self) -> Optional[WanStats]`. **`sentinel/adapter/models.py`**:
new dataclass `WanStats(timestamp, bytes_sent_delta, bytes_recv_delta,
throughput_up_kbps, throughput_dn_kbps)` — deliberately *not* reusing
`TrafficSample` (which is keyed by `mac_address`/`port_alias`; a household
total has no such key, and forcing one in — e.g. `mac_address='WAN'` —
would be a hack against the schema's intent, per the research).

**`sentinel/adapter/sagemcom/xmo_adapter.py`**: new `get_wan_stats()`
querying `Device/IP/Interfaces/Interface[Alias='IP_DATA']/Stats` (the
unverified xpath), self-contained delta tracking via a `self._wan_prev:
Optional[Tuple[int, int]]` instance attribute — same pattern
`self._port_prev` already uses in `get_port_stats()`. **Defensive
handling**: if the xpath resolves to `XMO_UNKNOWN_PATH_ERR` or the response
shape doesn't match expectations, catch/log a warning *once* (not every
15s poll — mirror the throttled-warning style already used for the
NET_RAW sniffing-permission case) and return `None`; the poll cycle simply
skips persisting that cycle. `MockSagemcomAdapter.get_wan_stats()` returns
synthetic totals (reuse the same random-walk pattern already used for
mock per-device traffic).

**`sentinel/db/models.py`**: new `WanStats` hypertable model — `time`-only
key (no device dimension), mirrors `TrafficSample`'s no-DB-constraint
convention. New migration (chained after the `ap_alias` one) creating the
table + `SELECT create_hypertable(...)`, mirroring the initial schema
migration's hypertable setup for `traffic_samples`.

**`sentinel/scheduler/jobs.py`**: `poll_cycle()` — add `wan_stats =
await adapter.get_wan_stats()` alongside the existing `port_stats =
await adapter.get_port_stats()` line; new `_insert_wan_stats(session,
wan_stats)` helper (no-op if `None`) called alongside `_insert_port_stats`.

**Spike detection**: new `sentinel/detection/wan_bandwidth.py`,
`WanBandwidthDetector` — not a `BaseDetector` subclass (that interface is
per-device-shaped; this has no MAC to key on or block), a small standalone
class with the same sustained-streak + cooldown shape as
`HighUploadDetector`, but threshold-free: flags throughput more than N
standard deviations above a rolling window of the last ~20 polls' mean,
rather than a fixed Mbps constant (a fixed number would need to be
hand-tuned per household's actual ISP plan; a rolling baseline adapts
automatically and needs no new admin-configurable setting). Alert type
`WAN_BANDWIDTH_SPIKE`, `device_mac=None`, inserted directly into
`poll_cycle()`'s existing `alerts` list (not routed through
`_raise_threat_alert` — there's no device to auto-block here, so that
method's block-then-alert shape doesn't fit; this mirrors how
`DetectionPipeline`-produced alerts already flow straight into
`poll_cycle`'s session).

**Frontend**: a small stat tile on the dashboard (near the existing
DEVICES ONLINE / ACTIVE ALERTS / THREAT SCORE row) showing current
household throughput. Degrades to "—"/hidden when `wan_stats` rows don't
exist yet (xpath unverified/failing) rather than showing a misleading zero.

**Tests**: `tests/test_detection/test_wan_bandwidth.py` (pure, synthetic
rolling-window data, mirrors other detector test structure).
`tests/test_adapter/test_xmo_adapter.py` additions for `get_wan_stats()`
covering both the happy path and the "xpath doesn't resolve" degrade path.

**Explicit caveat carried into the code/docs, same as Zeek's**: the very
first thing to check after this ships is a live `getValue` call against
`Device/IP/Interfaces/Interface[Alias='IP_DATA']/Stats` on the real router
(the Settings-tab admin session or a manual DevTools capture) — if the
field names differ from `BytesSent`/`BytesReceived`, `get_wan_stats()`'s
parsing needs a follow-up correction, same story as Zeek's `files.log`
schema turning out different from the initial guess.

---

## #8 — WiFi channel/interference visibility

**`sentinel/adapter/models.py`**: new dataclass `WifiRadioInfo(band,
channel, tx_power_dbm, standard)`. Add `radios: list[WifiRadioInfo]` to
`RouterInfo` (fits naturally alongside the existing `ssids: list[str]`
field — same "router-wide metadata" shape, fetched together).

**`sentinel/adapter/sagemcom/xmo_adapter.py`'s `get_router_info()`**: add
`'Device/WiFi/Radios/Radio'` to the existing batched `get_values([...])`
call (already fetches `DeviceInfo`/`IP_DATA`/`WiFi/SSIDs` in one request —
this is a same-shape addition, not a new round-trip), parse into
`WifiRadioInfo` entries. `MockSagemcomAdapter.get_router_info()`: add two
static `WifiRadioInfo` entries (2.4GHz/5GHz), matching the network-topology
doc's documented values.

**Frontend**: extend `SettingsPage.jsx`'s existing router-info `Field`
list (where `WAN IP`/`SSIDs` already render) with a small per-radio
channel/TX-power/standard block — same page, same pattern, no new page.

**Tests**: extend `tests/test_adapter/test_xmo_adapter.py` for the new
parsing.

---

## #9 — Wired-PHY Sent/Received direction fix

**`sentinel/adapter/sagemcom/xmo_adapter.py`**, two call sites, same fix
pattern as the already-confirmed WiFi swap
(`get_traffic_samples()`'s `device_download = BytesSent; device_upload =
BytesReceived` comment block, lines 102-114):

- **`get_port_stats()`** (lines 198-199): swap which raw field feeds
  `sent_total`/`recv_total` — `sent_total` (the value the frontend's
  `PortCard.jsx` renders under a ↑ upload arrow) should come from the
  interface's `BytesReceived` (device→interface = upload), `recv_total`
  from `BytesSent` (interface→device = download).
- **`_get_port_traffic_samples()`** (lines 475-476): same swap for the
  `sent`/`recv` values passed into `self._device_delta.compute(...)`.

`_single_occupant_port_samples()` derives from `_get_port_traffic_samples()`'s
output, so fixing that one call site also fixes the derived per-device
wired samples — no separate touch needed there.

Comment on both sites explicitly notes this is the same pattern as the
confirmed WiFi fix, applied without live re-verification per user
direction — and points at `docs/router/sagemcom-xmo-api.md`'s "Remaining
captures needed" section as where to note the outcome once someone does
capture live wired traffic to confirm.

**Tests**: update `tests/test_adapter/test_xmo_adapter.py`'s existing
port-stats/traffic-sample tests to assert the corrected mapping (any test
currently asserting the old orientation needs its expected values swapped
to match).

---

## Verification

- `python3 -m py_compile` on every new/changed file.
- New Alembic migrations: `alembic upgrade head` against `sentinel_test`,
  confirm both new columns/tables land, `alembic downgrade -1`/`-2` and
  back up cleanly.
- Targeted test run: `pytest tests/test_security/test_dhcp_watch.py
  tests/test_adapter/test_xmo_adapter.py tests/test_detection/test_wan_bandwidth.py
  tests/test_scheduler/ -q` against `sentinel_test` (`DATABASE_URL` +
  `JWT_SECRET_FILE` exported explicitly, per this session's established
  gotchas).
- Full `pytest tests/ -q` — expect only the same 5 pre-existing
  `test_data_retention.py` failures (unrelated `drop_chunks()` typing
  issue, present on `main`).
- Frontend `npm run lint && npm run build`.
- Manual, once live: confirm `Device/IP/Interfaces/Interface[Alias='IP_DATA']/Stats`
  actually resolves (item #6's real open question) and that a live wired
  download shows the corrected up/down direction on the Ports page
  (item #9 — no live verification was done before applying this fix, so
  this is the first real chance to catch it if the guess was wrong).

---

**Status: fully implemented and verified this session** — see
`sentinel/security/dhcp_watch.py`, `sentinel/adapter/sagemcom/xmo_adapter.py`'s
`get_wan_stats`/`_to_wifi_radio_info`/the direction-swap fixes,
`sentinel/detection/wan_bandwidth.py`, and the `ap_alias`/`wan_stats`
migrations. All items marked done/skipped/descoped in
`docs/capability-review.md`.
