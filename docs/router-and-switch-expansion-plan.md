# Router selection & managed-switch monitoring

## Context

Heimdall today talks to exactly two routers, both hard-coded:

- **Sagemcom F@st 5670** (XMO JSON API) — the permanent household router.
- **Redmi/MiWiFi** (stok API) — an optional second router, enabled from the
  Settings tab.

`sentinel/adapter/factory.py` hard-codes `SUPPORTED_ROUTERS = ('sagemcom',
'miwifi')`, and the Settings tab's `PrimaryRouterSelect` only switches between
those two. Wired devices behind a dumb switch are only visible as one
`PER_PORT` aggregate (`docs/router/wired-monitoring-caveat.md`).

This plan has two independent parts:

1. **Part 1 — Router catalog.** Let the user pick their router *type* in
   Settings from a list of mainstream models/protocols, with a simulator
   (existing, or a WireMock one we build) for every adapter so none ships
   untested.
2. **Part 2 — Managed-switch monitoring.** One shared pipeline (counters,
   per-device attribution, storage, scheduling, UI) and pluggable *drivers* per
   switch. The first target is a web-managed switch (HC-SWTGW218AS); the design
   goal is that the next switch costs a JSON *definition* plus captured pages,
   not a new scraper. SNMP is a second driver of the same pipeline.

### Relationship to existing design docs

- `docs/architecture/11-multi-adapter-auto-detection.md` already specifies an
  `AdapterRegistry`, `AdapterCapabilities`, and per-vendor adapter specs
  (OpenWrt, UniFi, pfSense/OPNsense, MikroTik, ASUS) plus startup discovery.
  **None of that registry is implemented** — only the two adapters above exist.
  Part 1 reuses that design rather than replacing it; this plan adds the
  *Settings-tab selection UX*, a *wider model catalog*, and the *simulator
  strategy*.
- `docs/architecture/12-switch-discovery-snmp.md` specifies the SNMP switch
  path (`sentinel/switches/`, `SwitchMonitor`, BRIDGE-MIB/IF-MIB). Part 2 makes
  the monitor, enricher and tables **driver-neutral**, so SNMP becomes one
  driver and web-managed switches another. Doc 12 needs corrections before
  anyone builds it, two of them breaking CLAUDE.md rule 5 and the upload/
  download direction: see section 2.10.

### Honesty about sources

The protocol/model tables below come from the existing docs plus general
knowledge of these ecosystems. Only OpenWrt's ubus documentation and the
existence of MikroTik CHR container images were re-checked while writing this
plan. Every row marked **verify** must be confirmed in Phase 0 before anyone
writes adapter code against it. The one switch described in Part 2 was checked
only as far as its public login page (section 2.2); everything past the login
is unknown until a capture is made.

---

# Part 1 — Router catalog and selection

## 1.1 Catalog: routers, protocols, simulators

Priority reflects (audience size) × (API quality) × (testability).

| Pri | Adapter id | Family / example models | Protocol & auth | Python lib to evaluate | Simulator for tests |
|---|---|---|---|---|---|
| ✅ | `sagemcom-xmo` | Sagemcom F@st 5670 (done) | JSON-over-HTTP XMO, SHA512/MD5 login | in-tree | `MockSagemcomAdapter` + WireMock (partial) |
| ✅ | `miwifi-stok` | Xiaomi / Redmi / Mi routers (done) | HTTP, `stok` token in URL, hashed login | in-tree | `MockMiwifiAdapter` |
| 1 | `sagemcom-xmo` (extend) | Orange Livebox, Sky Hub, other Sagemcom-built ISP boxes | Same XMO API; differs in password hashing (`encryption_method`) and login quirks (**verify**) | `sagemcom-api` (reference) | WireMock — reuse existing XMO stubs |
| 1 | `openwrt-ubus` | Any OpenWrt device (TP-Link, Netgear, Linksys, GL.iNet, x86…) | HTTP POST `/ubus`, JSON-RPC 2.0, `session.login` → `ubus_rpc_session` ([ubus techref](https://openwrt.org/docs/techref/ubus)). Needs `rpcd` + `uhttpd-mod-ubus` | none needed (plain `httpx`) | **Real thing, containerised** — see §1.2 |
| 2 | `mikrotik-rest` | MikroTik hAP/hEX/CCR, RouterOS 7.1+ | HTTPS REST, Basic auth; binary API for v6 | `librouteros` | **Real thing** — RouterOS CHR (free for lab use) in a QEMU-wrapped container; third-party images exist ([forum thread](https://forum.mikrotik.com/t/real-docker-images-for-chr-to-run-in-containerlalb/181934)) |
| 2 | `unifi-network` | Ubiquiti UniFi (UDM/UDR/Cloud Key/self-hosted controller) | HTTPS REST; cookie session via `/api/login`, `/proxy/network/...` on UDM; newer firmware also offers API keys (**verify**) | `aiounifi` | WireMock (controller container has no device simulator) |
| 2 | `opnsense-rest` | OPNsense | HTTPS REST, API key + secret as Basic auth; ARP + DHCP lease endpoints | none needed | WireMock; OPNsense VM image for manual validation |
| 2 | `pfsense-rest` | pfSense CE/Plus | **Third-party** REST API package must be installed (not built in); key auth | none needed | WireMock |
| 3 | `fritzbox-tr064` | AVM FRITZ!Box (very common in DACH) | TR-064 SOAP over HTTP(S) + SCPD XML descriptors; digest-style auth | `fritzconnection` | WireMock — record SOAP/SCPD from a real box (**verify** whether any maintained emulator exists) |
| 3 | `asus-http` | ASUS stock & Asuswrt-Merlin | `login.cgi` → token cookie; `appGet.cgi` hooks | `asusrouter` / `aioasuswrt` | WireMock |
| 3 | `tplink-router` | TP-Link Archer/Deco stock firmware | Model-dependent encrypted login (RSA/AES) — the least uniform on this list (**verify** per generation) | `tplinkrouterc6u` | WireMock per generation |
| 4 | `netgear-soap` | Netgear Nighthawk/Orbi stock | SOAP on `/soap/server_sa`, Basic auth | `pynetgear` | WireMock |
| 4 | `keenetic-rci` | Keenetic | REST-ish "RCI" API, challenge-response auth (**verify**) | evaluate | WireMock |
| 0 | `passive` | **Any router not listed** | No router API. Device discovery from ARP/nmap sweep + packet sniffer only | n/a | none needed |

Notes:

- **Tier `passive` is the escape hatch.** Today an unsupported router means
  Heimdall can't run at all. A passive adapter (inventory from ARP/nmap,
  traffic from the sniffer, block/quarantine unsupported and reported as such)
  makes every router "supported" at reduced capability. It is cheap and has a
  large audience, so it belongs in Phase 1.
- **Capabilities differ per adapter** (per-device traffic, blocking, RSSI, WAN
  stats…). Use the `AdapterCapabilities` dataclass from doc 11 §2.2; the UI
  greys out features the chosen router can't provide instead of showing empty
  panels. This also enforces CLAUDE.md rule 5 (never present `PER_PORT` data as
  per-device).
- Block/quarantine semantics vary a lot (MAC filter vs firewall rule vs
  DHCP static lease). Each adapter must document which it uses and whether it
  also stops LAN-local traffic — see the `block_device` docstring in
  `sentinel/adapter/base.py`.

## 1.2 Simulator strategy

Principle: **prefer a real implementation in a container over a hand-written
mock**, because a mock only proves we match our own assumptions.

| Situation | Approach |
|---|---|
| Router OS can run in a container/VM (OpenWrt, RouterOS CHR) | Run the real OS as a `sim` Compose service; adapter integration tests hit it. OpenWrt publishes rootfs images suitable for containers (**verify** current image names and that `uhttpd`/`rpcd` start in them); it has no real WiFi clients, so seed DHCP leases and check `get_clients` degrades to empty. CHR needs KVM/QEMU wrapping — mark those tests optional in CI. |
| Vendor firmware only on hardware (UniFi, FRITZ!Box, ASUS, TP-Link, Netgear, Keenetic, Sagemcom variants) | **Build a WireMock simulator** (§1.3). |
| Vendor ships a free VM (OPNsense, pfSense) | Use WireMock for CI; use the VM for occasional manual validation, documented but not automated. |

If a documented emulator exists for a protocol it goes in this table during
Phase 0. None was confirmed for FRITZ!Box TR-064 or UniFi in the research done
for this plan, so those default to WireMock.

## 1.3 WireMock plan (where no simulator exists)

Existing state: `wiremock/` holds `mappings/01-hosts.json` and two
`__files`; its README describes `login.json`, `queries.json` and
`router_info.json`, which do not exist in the tree — the README and tree have
drifted. Fix that as part of Phase 0.

**Layout** — *implemented as a single server with one folder per router* (see
`wiremock/README.md`); stubs must therefore keep URL paths unique per router:

```
wiremock/
  README.md
  mappings/<router-id>/…     # sagemcom-xmo, miwifi-stok, unifi-network, opnsense-rest, …
  __files/<router-id>/…
tests/simulators/<router-id>/Dockerfile   # openwrt-ubus, mikrotik-rest (real OS)
```

Compose: one WireMock service per adapter under a `sim` profile, each on its
own port (the existing `wiremock` service becomes `wiremock-sagemcom-xmo`),
started with `--root-dir /home/wiremock/<adapter>` and `--global-response-templating`.

**How stubs are produced** (cheapest first):

1. **Record from a real device** with WireMock's recorder pointed at the
   router, then scrub MACs/IPs/serials/tokens. Best fidelity; requires the
   hardware (the user owns Sagemcom and Redmi; others need community-donated
   captures — accept scrubbed HAR files via issue template).
2. **Derive from published API docs / reference libraries' test fixtures**
   (UniFi, OPNsense, pfSense have public docs; `fritzconnection`, `aiounifi`,
   `librouteros` and the Home Assistant integrations ship sample payloads —
   check each licence before copying).
3. **Hand-write** only the minimum when neither exists, and mark the stub set
   `fidelity: synthetic` in its README.

**Behaviours every stub set must reproduce** (these are where adapters
actually break, not the happy path):

- Login → token/cookie, and **session expiry** (WireMock *scenarios* flip to a
  401/“not logged in” state after N calls so re-auth is exercised).
- **Lockout**: wrong password → N failures → lockout response. The git log
  shows a real brute-force lockout bug on the Sagemcom; every adapter needs a
  test that failed logins are not retried in a tight loop.
- **Cumulative counters that increase** between polls (response templating
  with a scenario-state counter) so the delta calculator is exercised,
  including a **counter reset** (reboot) and a 32-bit **wrap**.
- Device list changes between polls (join/leave).
- Malformed / empty / HTML-error-page responses (routers often return an HTML
  login page with HTTP 200 on auth failure).
- Self-signed TLS (WireMock can serve HTTPS) for UniFi/MikroTik/OPNsense.

**Contract tests**: each adapter has a test suite parametrised over its
simulator that asserts the `RouterAdapter` contract (DTO types, MACs
normalised, deltas non-negative, `get_wan_stats()` may return `None`).
Real-container sims and WireMock sims run the *same* suite.

## 1.4 Backend design

1. **Registry** (`sentinel/adapter/registry.py`, per doc 11 §2.3): maps
   `adapter_id → AdapterSpec(cls, label, models, fields, capabilities)`.
   `factory.py` stops hard-coding `SUPPORTED_ROUTERS` and builds from the
   registry. New adapters = new package + one `register()` call, still
   behind `RouterAdapter` (CLAUDE.md rule 1: nothing outside the adapter
   layer touches a router).
2. **Field schema per adapter.** `AdapterSpec.fields` declares what the
   Settings form needs, e.g. `[host, port, username, password, api_key,
   api_secret, tls_verify, site]`, each with `secret: bool`. This lets the
   frontend render the form from `GET /api/routers/catalog` with **no
   per-adapter frontend code**.
3. **Router slots.** Keep the existing *primary/secondary* concept (primary
   feeds detection; secondary is visibility-only). Replace the
   `sagemcom`/`miwifi` special-casing with two slots, each holding
   `{adapter_id, host, port, username, tls_verify, extra}` in a new
   `router_profiles` table (non-secret fields only).
4. **Secrets** (CLAUDE.md rule 6): passwords/API secrets stay in Docker-secret
   files, one per slot (`router_primary_password`, `router_secondary_password`,
   plus `…_api_secret`), written through the existing `write_secret_file`
   path. Never stored in Postgres, never in env.
5. **Migration**: Alembic revision creating `router_profiles`, seeding slot
   *primary* = `sagemcom-xmo` and, if a MiWiFi IP is configured, slot
   *secondary* = `miwifi-stok`, reading the existing `router_username`,
   `miwifi_ip` and `active_router` columns; old columns are left in place for
   one release. Behaviour for current installs must be unchanged.
6. **Switching routers at runtime** already has a hook
   (`SentinelScheduler.reload_router_credentials()`); reuse it. Changing the
   *primary adapter type* must: rebuild the adapter, mark existing
   `devices.source_router` rows accordingly, and **not** wipe ML history.
   Open question below.
7. **API**: `GET /api/routers/catalog`, `GET/PUT /api/routers/slots/{primary|secondary}`,
   `POST /api/routers/test` (build adapter, call `get_router_info()`, return
   model/firmware or a precise error; never log the password).
8. **Discovery (optional, Phase 4)**: doc 11's probe-based fingerprinting
   pre-selects the dropdown ("looks like OpenWrt at 192.168.1.1"). The
   explicit user selection is the source of truth; discovery only suggests.

## 1.5 Frontend

- (Partly done: the Equipment tab now has `RouterSelector` — multi-select dropdown plus per-router
  login popup — fed by `GET /api/routers/catalog`.) Replace `PrimaryRouterSelect` with a single
  `RouterSlotForm` rendered for each slot: dropdown from the catalog →
  dynamic fields → **Test connection** button → Save.
- Show the adapter's capability badges (per-device traffic ✔/✘, blocking
  ✔/✘, WiFi RSSI ✔/✘) beside the dropdown so the user knows what they lose
  with, say, `passive`.
- Dropdown groups: *Tested against simulator*, *Community / unverified*.

## 1.6 Phases — Part 1

| Phase | Deliverable | Exit criteria |
|---|---|---|
| 0 | Verify every **verify** cell; pick libs; fix WireMock README drift; capture/scrub fixtures from owned routers | Catalog table has no unverified cells for Pri 1–2 |
| 1 | Registry, `router_profiles` + migration, slot API, dynamic Settings form, `passive` adapter; existing two adapters ported to the registry | Current install upgrades with identical behaviour; contract tests green |
| 2 | `openwrt-ubus` (real container sim) and Sagemcom-variant support | Contract suite passes against the OpenWrt container |
| 3 | `mikrotik-rest`, `unifi-network`, `opnsense-rest`, `pfsense-rest` | Each passes its simulator suite incl. expiry/lockout/wrap cases |
| 4 | `fritzbox-tr064`, `asus-http`, `tplink-router`, `netgear-soap`, discovery suggestions | As above |

---

# Part 2 — Managed-switch monitoring: one pipeline, many drivers

The first target is a web-managed switch (HC-SWTGW218AS). The design goal is
that the **second** switch costs a JSON file and some captured pages, not a new
scraper: everything that is the same for every switch is written once, and
everything that differs is data or one small plug-in.

> **Status (2026-11-09): phases 0 to 3 are built** for the HC-SWTGW218AS: the shared core, the generic web
> driver, its definition and captured-page fixtures, the database tables, the monitor job, the API, the
> Equipment-tab section and the docs. Phases 4 to 6 are not started. Where this text and the code differ, the
> code wins; section 2.9 lists what was built and what changed from the first draft of this plan.
>
> **Run on real hardware (2026-11-09):** the real driver, monitor, attribution and database layer ran against the owner's HC-SWTGW218AS: two polls around an 8 MB download credited 8.47 MB down and 70 KB up to the laptop on Port 1, credited the Heimdall box on Port 3, and left the 8-device uplink (Port 8) as a port total. The Equipment page and the scheduler job were not run against a live install.

## 2.1 Goal, and what the code already decides

**Goal:** for every device plugged into a switch Heimdall can read, show that
device's own upload and download instead of the router's "PORT TOTAL", and keep
saying "port total" where a per-device figure is not possible.

**Hard constraint (unchanged):** cheap switch UIs expose (1) per-port counters
and (2) a MAC address table (MAC → port) *without* byte counts. Per-MAC byte
counters are rare. So there are two ways to get a per-device figure:

| Mode | What the switch offers | Result |
|---|---|---|
| **Direct** | A table with a MAC column *and* byte columns | `PER_DEVICE`, measured |
| **Joined** | Port counters + a MAC table | A port with exactly **one** learned MAC: that port's counters are that device's traffic → `PER_DEVICE`. A port with several MACs (uplink, hub, downstream switch) stays `PER_PORT` |

**The rule already exists in the code.** The Sagemcom adapter does the same
inference one level up: `SagemcomXmoAdapter._single_occupant_port_samples`
gives a device alone on a router port that port's counters as `PER_DEVICE`, and
`_wired_single_occupant_macs` in `sentinel/scheduler/jobs.py` sets
`devices.traffic_granularity` from it (see `docs/router/sagemcom-xmo-api.md`).
The switch applies the same rule one level down.

> **Decision (reverses the earlier version of this plan):** reuse
> `TrafficGranularity.PER_DEVICE`; **no `PER_DEVICE_INFERRED` enum.** That enum
> was proposed before the single-occupant code existed. Two spellings of the same
> inference would make the UI, the ML gating and the digest treat identical data
> differently. The alternative is kept in the open questions.

**Direction is normalised once.** A switch port's *Rx* is what the device
*sent* (its upload) and its *Tx* is what the device *received* (its download).
Drivers always return **port-perspective** counters; the attribution step is
the single place that maps them to the device's point of view (the Sagemcom
adapter does the same swap for its LAN ports). Getting this backwards silently
inverts the upload-ratio exfiltration detector, so it has its own test.

**Known inaccuracy, to be published:** a port is attributed to its one learned
MAC even if a silent device shares it behind an unmanaged hub (a device that
never transmits is never learned). Broadcast and multicast traffic flooded out
of the port is counted as the device's download.

## 2.2 The first switch: HC-SWTGW218AS

Captured on 2026-11-09 from the owner's switch: one login with the owner's
credentials and read-only page fetches (plus two page-navigation commands on the MAC table, which only change which
page the switch displays). Nothing was changed, and the table's "clear" command was never sent. The pages, scrubbed of
addresses, are the fixtures in `tests/fixtures/switches/hc-swtgw218as/`.

| Fact | Evidence |
|---|---|
| 9 ports, one MAC table, firmware `V200.2.4`; the title and model are `HC-SWTGW218AS` | `info.cgi` |
| **Login:** `POST /login.cgi` with `username`, `password`, `Response = md5(username + password)` and `language`; the page's JavaScript also sets the cookie `admin=<that md5>`. The login's own answer is a script that redirects to `/`. The cookie is the whole session: requests that carry it are logged in | `login.cgi`, `formSubmit()` |
| A logged-out request is **HTTP 200** with a script `location.replace("/login.cgi")`, never a 401 | every page when the cookie is missing |
| **Every page except `/` and `/login.cgi` answers `404` with a blank body unless the request carries a `Referer` header** (any value, even empty). A plain `curl` is refused for this reason; a browser is not | bisected header by header |
| **Counters:** `port.cgi?page=stats` has columns `Port`, `State`, `Link Status`, `TxGoodPkt`, `RxGoodPkt`, `TxGoodBytes`, `RxGoodBytes`. Each number is shown as two 32-bit words, `<high>-<low>` (for example `0-130522`); the page's script combines them. So the counters are **64-bit, cumulative, in bytes** | `port.cgi?page=stats` |
| **Direction is the port's:** after a 20 MB download on the laptop plugged into Port 1, Port 1's `TxGoodBytes` rose by 21.0 MB and its `RxGoodBytes` by 76 KB; the uplink port showed the mirror image. So Tx is what the switch sent to the device (its download) and Rx what the device sent (its upload). Counted at layer 2, hence about 5 % above the payload | live measurement |
| **MAC table:** `mac.cgi?page=fwd_tbl`, columns `MAC Address`, `Type`, `Port`, `VLAN ID`. It is **paginated** (10 per page here; 20 and 30 are offered). Which page is shown is state kept by the switch, changed by POSTing `cmd=firstpage` / `nextpage` (the same form also offers `mactblclr`, which clears the table and must never be sent). The page says `Total 11 Items` and `<label id='totalpage'>2 </label>Pages` | `mac.cgi?page=fwd_tbl` |
| The switch's own address appears in its table on port `CPU` | page 2 of the MAC table |
| Link state and speed (`Nego Speed Status`: `1000M`, `10M`, `Auto`) are on `info.cgi`, link up or down also on the stats page | `info.cgi` |
| The HTML is sloppy (some `<th>` cells are closed with `</td>`), so the parser must be tolerant | `info.cgi` |
| A poll costs about 1.5 s (login-free, 4 to 6 requests); the switch answers one request at a time | measured |

**Consequences.** The cookie is a static hash of the credentials, so the session
does not expire, and anyone on the LAN who sees one request can replay the login.
That is the switch's design, not something Heimdall adds, but each poll is one
more exposure; it is on the known-limits page. The switch's wrong-password
response was deliberately **not** captured (a failed login risks locking the
admin account): a rejected login is detected by asking for a real page afterwards
and getting the logged-out one.

**Still unknown** (none of it blocks the driver): whether the switch also speaks
SNMP (the admin menu has no SNMP page, so the web driver is the only route),
whether it has a read-only user, whether repeated wrong passwords lock it, and
whether more than one browser session can be open at once. The driver polls
modestly and never retries a rejected login.

**Credentials.** The owner keeps a `user:pass` file at `secrets/switch_password.txt`
(git-ignored) for capture runs on a dev machine. In production the password goes
through the Equipment tab into the secrets directory, exactly like a router's,
never into the database, the environment or a log.

## 2.3 What varies between switches, and what does not

| Concern | Differs per switch? | Where it lives |
|---|---|---|
| Login: form + hashed cookie, Basic, Digest, token in URL, SNMP community, vendor REST | Yes, but there are only a handful of shapes | **auth strategy** — small, shared, reused by every definition |
| Page / endpoint names | Yes | **definition** (data) |
| Data format: HTML `<table>`, `var ports = [...]` in a script, JSON, XML, plain text | A handful of shapes | **extractor** — small, shared |
| Column names and order, units, bytes vs packets, 32 vs 64-bit, label perspective | Yes | **definition** (matched by header text, not column number) |
| Port names (`1`, `Port 1`, `g3`, `Trk1`) and MAC formats (`aa-bb-…`, `AABB.CCDD.…`) | Yes | **definition** + shared normalisers |
| Delta maths and wrap, the join, occupancy, direction, DB writes, scheduling, back-off, API, UI, secrets, retention, LAN-only guard | **No** | **shared core, written once** |
| A genuinely different protocol: SNMP, SSH, a vendor REST API | Yes | a **code driver** implementing `SwitchSource` |

## 2.4 Architecture

```
 switch ──[driver]──▶ SwitchSnapshot ──[core]──▶ deltas ──▶ attribution ──▶ TrafficSample / SwitchPortStat ──▶ DB, UI
            ▲                                   └────────── pure functions, no I/O, unit-testable ──────────┘
            └─ the ONLY layer that talks to a switch
```

Same shape as the router side: `RouterAdapter` + `catalog.py`. CLAUDE.md rule 1
is extended in spirit: **nothing outside `sentinel/switches/` talks to a
switch**, and detectors never see HTML.

```
sentinel/switches/
  models.py          # SwitchSnapshot, PortCounters, MacEntry, SwitchIdentity (dataclasses)
  source.py          # SwitchSource protocol + SwitchAuthError / SwitchUnreachable / SwitchParseError
  catalog.py         # SwitchSpec + CATALOG — mirrors sentinel/adapter/catalog.py
  registry.py        # @register_driver('web-definition'); build_source(spec, host, user, password)
  ownership.py       # who owns a device's numbers: the router poll or a switch (freshness window)
  store.py           # one poll -> one transaction (port rows, device samples, devices.switch_*)
  core/
    counters.py      # CounterTracker: deltas with reset and 32/64-bit wrap
    attribution.py   # occupancy -> per-device sample or port total, the one direction swap
    monitor.py       # SwitchMonitor: poll each target, back-off, status
  web/               # the generic driver for web-managed switches
    definition.py    # schema (pydantic dataclasses), loader, validation
    template.py      # ${username}, ${md5(username + password)} — whitelist evaluator, no eval
    fetch.py         # the LAN-only guard
    snapshot.py      # pages -> SwitchSnapshot (pure)
    source.py        # WebDefinitionSource(SwitchSource): form login, logged-out detection, pagination
    extract/
      html_table.py  # tolerant table parser, header-text lookup
      values.py      # numbers (plain, hi-lo), speeds, port ids
  definitions/
    hc-swtgw218as.json   # one file per switch family or model
  # planned, not built: web/auth.py (more login styles), extract/js_var.py, json_path.py, text_regex.py,
  # snmp/ (doc 12's reader as a second SwitchSource), tools/capture.py
tests/fixtures/switches/<id>/   # fixture.json, pages/, expected.json
tests/test_switches/            # the generic fixture suite + unit tests; tests/test_api/test_switches.py
```

### The contract every driver implements

```python
@dataclass
class PortCounters:
    port: str                    # the switch's own label: '1', 'g3', 'Trk1'
    rx_bytes: int | None         # received BY the switch on this port  (= the device's upload)
    tx_bytes: int | None         # sent BY the switch out of this port  (= the device's download)
    rx_packets: int | None = None
    tx_packets: int | None = None
    link_up: bool | None = None
    speed_mbps: int | None = None
    counter_bits: int = 64       # 32 turns on wrap handling

@dataclass
class MacEntry:
    mac: str                     # canonical lower-case colon form
    port: str
    vlan: int | None = None
    dynamic: bool = True         # learned, not static

@dataclass
class SwitchSnapshot:
    identity: SwitchIdentity     # model, firmware, own MAC (to exclude it from occupancy)
    ports: list[PortCounters]
    macs: list[MacEntry]
    taken_at: datetime

class SwitchSource(Protocol):
    async def poll(self) -> SwitchSnapshot: ...
    async def aclose(self) -> None: ...
```

A driver returns facts and nothing else. It never computes deltas, never
guesses a direction, never touches the database and never names a device. A
page that no longer matches raises `SwitchParseError` ("the switch's layout
changed"), **never zeros**. A rejected login raises `SwitchAuthError`.

### The catalog entry (what the Equipment tab renders)

```python
SwitchSpec(
    id='hc-swtgw218as', label='HC SW-TGW218AS (web UI)', family='HC web-managed',
    protocol='HTTP form login (MD5 cookie), HTML pages', driver='web-definition', definition='hc-swtgw218as',
    implemented=True,     # its fixture suite passes (tests/fixtures/switches/hc-swtgw218as/)
    tested=True,          # run against the physical switch (2026-11-09)
    default_username='admin', notes='…',
)
```

The form is rendered from `GET /api/switches/catalog` exactly like the router
catalog, so a new switch needs **no frontend code**. The word *definition* is
used on purpose: `router_profiles` / `PROFILE_ROUTERS` already mean something
else.

### A web definition (the real `hc-swtgw218as.json`, abridged)

```jsonc
{
  "version": 1,
  "id": "hc-swtgw218as",
  "match": { "title": "HC-SWTGW218AS" },
  "request_headers": { "Referer": "${base_url}/" },          // this switch answers 404 to a request with no Referer
  "auth": {
    "type": "form",
    "login_url": "/login.cgi",
    "fields":  { "username": "${username}", "password": "${password}",
                 "Response": "${md5(username + password)}", "language": "EN" },
    "cookies": { "admin": "${md5(username + password)}" },    // the cookie is the whole session
    "verify_url": "/info.cgi",                                // a rejected login still answers 200: ask for a real page
    "logged_out_marker": "location\\.replace\\(\"/login\\.cgi\"\\)"
  },
  "pages": {
    "info":  { "url": "/info.cgi" },
    "stats": { "url": "/port.cgi?page=stats" },
    "macs":  { "url": "/mac.cgi?page=fwd_tbl",
               "paginate": { "url": "/mac.cgi?page=fwd_tbl", "first": { "cmd": "firstpage" }, "next": { "cmd": "nextpage" },
                             "total_pages": "id='totalpage'>\\s*(\\d+)", "max_pages": 20, "restore": true } }
  },
  "ports": {
    "table": { "page": "stats", "header_match": ["^Port$", "TxGoodBytes", "RxGoodBytes"],
               "columns": { "port": "^Port$", "link": "^Link Status$", "tx_bytes": "^TxGoodBytes$", "rx_bytes": "^RxGoodBytes$" } },
    "port_id": "^Port\\s*(\\S+)$", "number_format": "hi_lo", "counter_bits": 64, "perspective": "port", "link_up_text": "Link Up",
    "speeds": { "table": { "page": "info", "header_match": ["^Port$", "Nego Speed"], "columns": { "port": "^Port$", "speed": "Nego Speed" } } }
  },
  "macs": { "table": { "page": "macs", "header_match": ["MAC Address", "^Port$", "VLAN"],
                       "columns": { "mac": "MAC Address", "type": "^Type$", "port": "^Port$", "vlan": "VLAN" } } }
}
```

Rules that keep this from growing into a programming language: a definition
has **no loops and no conditions**. Columns are found by **header text**, so a
firmware update that inserts a column does not silently shift the data. If a
firmware needs logic the vocabulary cannot express, write a code driver; do not
grow the definition language.

## 2.5 Adding another switch

| Case | Example | What you write | Python? |
|---|---|---|---|
| **A. Same firmware family, new model** | another HC-style box with different page names | copy the definition, change URLs and header texts, add fixtures | none |
| **B. New web firmware** | a TP-Link Easy Smart, Netgear Plus, Zyxel GS1200 | a new definition; plus a new auth strategy or extractor *only if* none fits (30–80 lines each, unit-tested) | a little |
| **C. A different protocol** | SNMP, a vendor REST API | a class implementing `SwitchSource` plus `@register_driver`; it reuses the whole core | one class |

Checklist for every switch:

1. **Capture** the pages from your own switch, logged in (browser "save page" or `curl`; the HC switch needs a `Referer` header). A capture *tool* that logs in and saves everything is not built: the pages are few.
2. **Scrub** with `python3 scripts/scrub-switch-pages.py` (MACs and private IPs become synthetic), then read the files for host names, serial numbers and SSIDs. `tests/test_switches/test_fixture_privacy.py` fails on any real-looking MAC or non-example address in `tests/fixtures/switches/`.
3. **Write the definition**, copying `hc-swtgw218as.json`.
4. **Write `expected.json`**: the snapshot the pages should produce.
5. **Add the catalog entry** and its facts row (the website's switch table is generated from them and the build fails if a facts row is missing, like routers). Set `implemented=True` only when the fixture suite passes.
6. **Run the generic suite.** It discovers every folder under `tests/fixtures/switches/`, so there is no test code to write.

"Tested" is a separate label, given only after a run on real hardware. Until then
the website says "checked against captured pages".

## 2.6 The shared core

**Counters** (`core/counters.py`) — a new `CounterTracker`, not a change to
`TrafficDeltaCalculator`, so router behaviour is untouched. First sample = no
delta. A decrease is a **wrap** if the driver says `counter_bits=32` *and* the
wrapped delta is plausible for the link speed and interval; otherwise it is a
**reset** (the delta is the new value). The plausibility check stops a reboot or
a "clear counters" click being misread as a wrap. A 32-bit counter at 1 Gb/s
wraps in about 34 s, so a 32-bit switch needs an interval of 15–30 s; longer
intervals get a visible "counters may wrap between polls" warning instead of
silently wrong numbers. Idle ports are evicted from the tracker.

**Attribution** (`core/attribution.py`) — pure functions:

- Occupancy of a port = the set of distinct **dynamic** MACs learned on it, excluding the switch's own MAC, counting a MAC once across VLANs.
- Exactly one MAC → a `PER_DEVICE` `TrafficSample`: device upload = port `rx`, device download = port `tx`.
- More than one → credited to nobody. As built, the port's totals live only in `switch_port_stats` (with the number of devices on it); **no `traffic_samples` row is written**, because the router's own port sample already represents a shared port to the rest of Heimdall and `traffic_samples.mac_address` is a 17-character column that does not fit a switch-port key.
- A MAC that is not in `devices` is **not created** in v1 (the router stays the inventory); it is counted in the switch status ("3 unknown MACs"). Phase 6 can raise NEW_DEVICE for it through the existing placeholder path.

**Who owns a device's number.** Two risks, both of the kind this codebase has
already been bitten by (see the `is_primary` comment in `_upsert_devices`):

1. *Flip-flop.* The router poll rewrites `devices.traffic_granularity` every
   cycle from its own view (`per_port` for anything behind a shared router port).
   Without a rule the value toggles between the router's and the switch's view
   every cycle. **Rule:** new columns `devices.switch_target_id`, `switch_port`,
   `switch_seen_at`; while `switch_seen_at` is fresh (2 × the switch interval),
   `_upsert_devices` keeps `per_device`.
2. *Double counting.* If a device is alone on a router port **and** the switch
   attributes it, both would insert a `PER_DEVICE` row for the same traffic.
   **Rule:** while `switch_seen_at` is fresh, the router poll skips its
   `PER_DEVICE` row for that MAC; the switch is closer to the device and wins.

Both get regression tests.

**Persistence.** Samples go through the existing `_insert_traffic_samples`. A
new hypertable `switch_port_stats` holds per-port totals and deltas (doc 12 §9
has the columns, made driver-neutral). **Add it to the nightly retention job
from day one**: that job today drops chunks of `traffic_samples` and `port_stats`
only, so a new hypertable not named there grows forever.

**Scheduling.** One `SwitchMonitor`, owned by the scheduler, one APScheduler
job; each target is polled concurrently with its own timeout; one failing switch
never delays or fails the router poll. Per-target back-off 1 → 15 minutes
(the same shape as the router reconnect), with `last_ok_at`, `last_error` and
`consecutive_failures` stored and shown. A `SwitchAuthError` is never retried
automatically (a lockout lesson from the Sagemcom): the UI says "login rejected,
fix the password".

**Data model.** `switch_targets(id, spec_id, name, host, port, username,
tls_verify, poll_interval_s, enabled, options JSON, last_ok_at, last_error,
created_at, updated_at)`. The id is server-generated, so the password file name
(`switch_secret_path(id)`, next to `router_secret_path`, same secrets
directory) can never contain user text. The limit of 5 targets is a setting
checked by the API, not a database constraint. Two identical switches are two
targets of one catalog entry.

**API and UI.** `GET /api/switches/catalog`, `GET/POST/PATCH/DELETE
/api/switches`, `POST /api/switches/{id}/test` (log in, read once, report the
model and the port and MAC counts, never the password), optional `POST
/api/switches/detect` using each entry's `match`. The Equipment tab's SWITCHES
placeholder is replaced by a list plus the catalog-rendered form; the device
detail page shows "via <switch>, port N".

**Shared helpers.** `norm_mac`, `to_int`, `LoginThrottle`, `AdapterAuthError`
and `build_base_url` live in `sentinel/adapter/http_adapter.py` today. Move them
to a neutral module and re-export them from `http_adapter`, so existing adapters
and tests do not change and `sentinel/switches/` never imports from
`sentinel/adapter/`.

## 2.7 Safety

The old "paste any URL" design made an admin-only API fetch arbitrary URLs: an
SSRF surface. Definitions shrink it, because the user picks a model and a host,
and the URLs come from a reviewed file.

- **Definitions are data, not code.** Strict schema, unknown keys rejected, URLs must be relative paths on the target host. Templates run in a whitelist evaluator (variables `username`, `password`, `host`; functions `md5`, `sha1`, `sha256`, `base64`, `upper`, `lower`; `+`) and never through `eval`. This is what makes a community-contributed definition safe to merge, and safe to import later.
- Only RFC 1918 / link-local hosts. No redirects to another host. 2 MB response cap. Short timeouts. Only `http`/`https`.
- Credentials, cookies and login bodies are never logged. Errors name the switch, not the secret.
- A rejected login starts a 5-minute cool-down (`LoginThrottle`) so a wrong password cannot turn into a lockout of the switch's admin account.
- If a switch allows one session and logs the owner's browser out, poll modestly, log out cleanly when the definition has a `logout_url`, and say so in the manual.

## 2.8 Testing

- **Generic fixture suite.** Parametrised over every folder in `tests/fixtures/switches/`. Each holds `exchange.json` (recorded request → response pairs served by `httpx.MockTransport`), `pages/` (scrubbed bodies) and `expected.json`. It asserts that the definition validates, the login replays, the snapshot equals `expected.json`, and a second poll with advanced counters gives the expected deltas.
- **Scenarios every definition must also pass**, generated from its own exchange: session expiry (a logged-out page with HTTP 200 → exactly one re-login), wrong password (`SwitchAuthError`, no retry loop, cool-down), a changed or truncated page (`SwitchParseError`, never zeros), an oversized body, an off-host redirect.
- **Core unit tests.** Counters: first sample, reset, 32-bit wrap, implausible wrap read as reset. Attribution: one, several and no MACs, the switch's own MAC, the same MAC in two VLANs, the direction swap. Ownership: no flip-flop against the router's `per_port`, no double row. Template evaluator: whitelist and injection attempts. Parsing: `1,234,567`, the `<high>-<low>` 64-bit form, speeds (`1000M`, `1G`, `Auto`), MAC formats. Units such as `1.2 GB` and hexadecimal are not implemented: no switch captured so far needs them.
- **Driver contract test**, run on every `SwitchSource` (definition-driven or code): canonical MACs, non-negative integers, unique port ids.
- **Property test.** Reordering columns with intact headers gives the same snapshot.
- **Real hardware.** The Phase 0 capture is also the first live run; "Tested" is set only after a documented one.

## 2.9 Phases

| Phase | Deliverable | Exit criteria |
|---|---|---|
| 0 | Capture the HC switch's pages (one read-only login, scrubbed); answer every item in 2.2, including whether it speaks SNMP | Fixtures and `expected.json` committed; the "not yet known" list is empty |
| 1 | Core + web driver + HC definition, **offline**: models, counters, attribution, template, auth, fetch, extractors, loader, generic suite | HC fixtures pass; no database and no UI yet |
| 2 | Persistence and monitor: `switch_targets` and `switch_port_stats` migration, secrets path, `SwitchMonitor` job, device columns, ownership rules, retention | With a fake source, single-MAC ports give `PER_DEVICE` rows, shared ports stay `PER_PORT`, no flip-flop, no double row |
| 3 | API, Equipment tab, device-detail line, **and the docs/website changes in the same change** (CLAUDE.md): manual Part 5 and `network-setup.md`, the SWITCHES placeholder text, the switch table (generated, with a facts file), README "Supported switches", the known-limits page, `wired-monitoring-caveat.md`, `docs/INDEX.md` | The owner's switch shows live per-device numbers; the manual chapter keeps its "Draft" note until checked on a running dashboard |
| 4 | **A second driver, added without touching `core/`**: SNMP BRIDGE-MIB / IF-MIB (doc 12) or a second web definition | Passes the driver contract and fixture suites; the diff touches `web/definitions/` or `snmp/` only |
| 5 | Optional: unknown MAC seen on a switch port → NEW_DEVICE; detection and ML scoring for switch samples, as the Sagemcom single-occupant samples already get | Decided by the owner |
| 6 | Optional: a "Test & preview" authoring UI that fetches a live page, shows its tables and drafts a definition | An aid for writing definitions, never a runtime guess |

`implemented=True` is set per switch when its fixture suite passes; "Tested"
only after a real-hardware run. Nothing is advertised before then.

**What was built (phases 0 to 3), and where it differs from the first draft:**

- Phase 0 found three things the draft did not expect: the **`Referer` requirement**, the **paginated MAC table with state kept on the switch**, and **64-bit counters shown as two 32-bit words**. The definition language gained a `paginate` block (the driver, not the definition, does the walking, and restores the switch's view to page 1 afterwards) and a `hi_lo` number format.
- `core/`: `CounterTracker` (reset and 32-bit wrap, with a plausibility check), `attribute()` (occupancy, the single direction swap), `SwitchMonitor` (per-switch interval, back-off from 60 s doubling to 15 min, one failure never delays another, configuration changes picked up by fingerprint).
- `web/`: definition schema (pydantic, unknown keys rejected, paths only, template whitelist), `snapshot.py` (pure page-to-snapshot), `source.py` (form login, logged-out detection, re-login once, pagination), `fetch.py` (an explicit RFC 1918 / link-local / unique-local allow-list, because Python's `is_private` also accepts documentation and reserved ranges). Separate auth strategies are not split out yet: the one form login lives in `source.py` until a second login style needs the split.
- Persistence: `switch_targets`, `switch_port_stats` (hypertable, pruned by the nightly retention job from day one), `devices.switch_*`; `_upsert_devices` keeps a switch-owned device `per_device` and the router poll skips its own row for it.
- API and UI: `/api/switches` (catalog, CRUD, test, ports), the Equipment tab's Switches section, a badge and note on the device page.
- Docs: manual (Equipment, guide Part 5, troubleshooting), README, known limits, equipment page (generated from `docs/router/switch-facts.json`), CONTRIBUTING "Adding a switch", `scripts/scrub-switch-pages.py`.
- Not built: a capture tool, the SNMP driver (phase 4), unknown-MAC alerts and ML scoring for switch samples (phase 5), the authoring UI (phase 6).

## 2.10 Changes this plan makes to other documents

**`docs/architecture/12-switch-discovery-snmp.md`.** The old statement "nothing
in doc 12 changes" no longer holds. Fix before anyone implements it:

1. **§7 `DeviceEnricher` copies a port's totals onto every MAC learned on that port.** On an uplink with ten MACs, each of the ten gets the whole port's traffic, labelled `per_device`. That breaks CLAUDE.md rule 5. Replaced by `core/attribution.py`.
2. **The same code assigns `bytes_sent_delta = port.bytes_out_delta`**, which is what the device *received*. Upload and download are inverted, and so is `HighUploadDetector`'s input.
3. §3.2 "upgrades every MAC to `per_device`" becomes: only single-occupant ports.
4. `SwitchMonitor._poll_switch` builds an `SnmpClient` directly. It becomes `SnmpSource(SwitchSource)`; the monitor, registry and tables are shared with the web driver.
5. Doc 12's `switches` table (discovered) and `switch_targets` (configured) are merged: `switch_targets` is the one table; LLDP and sweep discovery (doc 12 §5) only *propose* a target, which the user confirms.

**`docs/router/wired-monitoring-caveat.md`:** add the switch route once Phase 3 ships.

**`CLAUDE.md`, rule 1:** proposed wording for the maintainer to adopt: "…and never access a switch outside `sentinel/switches/`". Not edited by this plan.

**`docs/INDEX.md`:** the rows for this document, doc 12 and `docs/router/switch-facts.json` are updated.

---

## Risks

| Risk | Mitigation |
|---|---|
| Scraped pages break on firmware updates | Header-text column matching, `SwitchParseError` (never zeros) shown as "layout changed", fixtures per firmware |
| Single-session switches log the user out of their own browser | Modest poll interval, clean logout, documented clearly |
| A port shared with a silent device behind an unmanaged hub is attributed to the one learned MAC | Published as a known limit; single-MAC rule is the same one the Sagemcom adapter already uses |
| Inverted upload/download | Drivers return port-perspective counters; one swap in `core/attribution.py`; explicit test |
| Router and switch disagree on a device's granularity (flip-flop) or both write a row (double count) | `switch_seen_at` ownership rule in `_upsert_devices` and `_insert_traffic_samples`; regression tests |
| 32-bit counters wrap between polls | `counter_bits` + plausibility check; warning when the interval is too long for the link speed |
| Switch login is a plain MD5 of the credentials sent over HTTP (HC firmware) | Disclosed on the known-limits page; read-only user if the firmware has one |
| The definition language grows into a programming language | No loops or conditions; anything more is a code driver |
| A slow or dead switch delays the router poll | Separate job, per-target timeout and back-off |
| New hypertable never pruned | Added to the nightly retention job in the same change |
| SSRF via a user-supplied URL | No URL field: URLs come from a reviewed definition, relative to the chosen host; LAN-only, no cross-host redirects, size/time caps |
| Simulator fidelity (synthetic stubs hide real quirks) | Prefer real-OS containers; mark synthetic stub sets; contract tests shared |
| Third-party libs unmaintained | Thin in-tree clients where a library is trivial (`httpx` for ubus/REST) |
| Scope: ~13 adapters is large | Strict phases; each adapter ships only with its simulator suite |

## Open questions for the owner

1. **Switching primary router type at runtime:** keep device history and ML
   models across the switch (MAC-keyed, so mostly fine) or require a purge?
   Default proposed: keep history, tag rows by `source_router`.
2. **Inferred wired traffic — proposed answer: reuse `PER_DEVICE`.** The
   Sagemcom adapter already reports a device alone on a router port as
   `PER_DEVICE`, so the switch does the same (section 2.1). The alternative is a
   new `TrafficGranularity.PER_DEVICE_INFERRED` with its own UI badge, applied to
   *both* the router's and the switch's single-occupant samples; that touches the
   enum, the serialisers, the digest and the ML gating. Confirm, or ask for the
   badge.
3. **HTML parsing library — proposed answer: the standard library first.**
   `html.parser` is enough for `<table>` and `<script>` extraction and adds no
   dependency (`requirements.txt` has no HTML parser today). Add `selectolax`
   or `lxml` only if a real capture needs it.
4. **Which switch(es) do you own?** One is known: HC-SWTGW218AS. **May Phase 0
   log in to it once, read-only,** to capture its stats and MAC-table pages?
   (If its admin UI has an SNMP page, SNMP may be the better first driver.)
   Another unanswered point: which ports are single-device and which feed
   another switch or access point?
5. **Which routers beyond yours matter?** Reorder the Part 1 priorities if you
   know the audience (e.g. FRITZ!Box first for a German user base).
6. **Docker secrets for dynamic secrets:** the current pattern writes secret
   files at runtime; 5 switch passwords + 2 router slots + API secrets means
   several more writable secret files. Confirm the secrets volume stays
   writable by the backend, or choose another approved mechanism. (Switch
   passwords reuse `ROUTER_SECRETS_DIR`, one file per target.)
7. **Poll interval for switches:** the router poll is 15 s. Proposed default is
   the same; 32-bit-counter switches need 15–30 s (section 2.6). Single-session
   switches may prefer 30 s or more.
8. **Import of user-supplied definitions** (so a user can add a switch without a
   Heimdall release): safe in principle because a definition is validated data,
   but it is a new trust surface. Proposed: not in v1; contributors add
   definitions through pull requests.
9. **Unknown MACs seen only on a switch** (not in the router's list): raise
   `NEW_DEVICE`? It is a real security signal, but it is Phase 5 scope.
