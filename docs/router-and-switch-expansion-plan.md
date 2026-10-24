# Router selection & web-scraped switch monitoring

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
2. **Part 2 — Web-scraped switch monitoring.** Up to 5 managed switches that
   have no SNMP, only a crude web UI. The user adds each stats-page URL (plus
   credentials if needed) in Settings; a generic scraper extracts per-port /
   per-device upload and download numbers.

### Relationship to existing design docs

- `docs/architecture/11-multi-adapter-auto-detection.md` already specifies an
  `AdapterRegistry`, `AdapterCapabilities`, and per-vendor adapter specs
  (OpenWrt, UniFi, pfSense/OPNsense, MikroTik, ASUS) plus startup discovery.
  **None of that registry is implemented** — only the two adapters above exist.
  Part 1 reuses that design rather than replacing it; this plan adds the
  *Settings-tab selection UX*, a *wider model catalog*, and the *simulator
  strategy*.
- `docs/architecture/12-switch-discovery-snmp.md` specifies the SNMP switch
  path (`sentinel/switches/`, `SwitchMonitor`, BRIDGE-MIB/IF-MIB). Part 2 adds
  a second, SNMP-free *source* feeding the same `SwitchMonitor`. Nothing in
  doc 12 changes.

### Honesty about sources

The protocol/model tables below come from the existing docs plus general
knowledge of these ecosystems. Only OpenWrt's ubus documentation and the
existence of MikroTik CHR container images were re-checked while writing this
plan. Every row marked **verify** must be confirmed in Phase 0 before anyone
writes adapter code against it.

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
`__files__`; its README describes `login.json`, `queries.json` and
`router_info.json`, which do not exist in the tree — the README and tree have
drifted. Fix that as part of Phase 0.

**Layout** — one directory per adapter so stubs can't collide:

```
wiremock/
  README.md
  sagemcom-xmo/{mappings,__files__}/
  openwrt-ubus/…        # only if the real-container approach proves flaky
  unifi-network/…
  opnsense-rest/…
  fritzbox-tr064/…
  …
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

- Replace `PrimaryRouterSelect` + `MiwifiCredentialsForm` with a single
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

# Part 2 — Generic web-scraped switch monitoring

## 2.1 Goal and the constraint that shapes everything

Home-lab switches (TP-Link "Easy Smart", Netgear "Plus", Zyxel GS1200,
D-Link smart, etc.) typically have no SNMP, only a web UI. The user wants to
paste a stats-page URL and get per-device upload/download.

**Hard constraint:** these web UIs almost always expose

1. **per-port** packet/byte counters, and
2. a separate **MAC address table** (MAC → port), usually *without* byte counts.

Per-*MAC* byte counters are rare. So the scraper must support two ways to get
per-device numbers:

| Mode | What the page offers | Result |
|---|---|---|
| **Direct** | A table with a MAC column *and* byte columns | `PER_DEVICE`, measured |
| **Joined** | Port counters page + MAC-table page | If a port has exactly **one** MAC learned, that port's counters are that device's traffic → *inferred* per-device. If a port has several MACs (uplink, hub, downstream switch) → stays `PER_PORT` |

The joined result is **inferred**, not measured. CLAUDE.md rule 5 says wired
traffic must not be shown as per-device measured when it isn't. So the
data model gets an explicit marker (proposal: new
`TrafficGranularity.PER_DEVICE_INFERRED`, rendered with a distinct badge) —
see open question 2.

**Direction is mirrored.** A switch port's *Rx* is what the device *sent*
(its upload); the port's *Tx* is what the device *received* (its download).
Each target gets a `perspective` setting (`port` | `device`) and the default is
`port` → swap on import. Getting this backwards silently inverts the
upload-ratio exfiltration detector, so it needs a test and a UI hint.

## 2.2 Settings UX

A **Switches** panel, max **5 targets**:

| Field | Notes |
|---|---|
| Name | Free text |
| Stats URL | The page with per-port (or per-device) counters |
| MAC-table URL | Optional; enables Joined mode |
| Auth | `none` · `basic` · `digest` · `form login` · `cookie/header` |
| Credentials | Username + password (password → secret file, never DB) |
| Form-login details | Login URL, field names, success marker — only when `form login` |
| Mirror perspective | port / device (default port) |
| Verify TLS | Off allowed (self-signed is the norm) |
| Poll interval | Default = global poll interval, min 10 s |
| Mapping | Auto-detected; editable after **Test & preview** |

**Test & preview** is the core UX: it fetches the page, shows every table it
found, highlights the columns it decided are *port / MAC / rx / tx*, and lets
the user click to correct them. The corrected mapping is saved on the target,
so the heuristics only need to be right *most* of the time.

## 2.3 Fetching and authentication

Plain `httpx.AsyncClient` (CLAUDE.md rule 2), one client per target with its
own cookie jar.

- `basic` / `digest`: `httpx.BasicAuth` / `httpx.DigestAuth`.
- `form login`: POST configured fields, keep cookies; re-login on a response
  that matches the "logged out" marker (login-page HTML with HTTP 200 is the
  usual signal). Some switches hash the password client-side (MD5 in
  JavaScript) — support an optional `password_transform: md5|sha256|none`.
- `cookie/header`: user pastes a cookie or header (stored as a secret) for
  switches whose login can't be replayed; documented as a last resort that
  expires.
- **Single-session switches**: many cheap switches allow one logged-in session
  and *log the browser out* when a second client logs in. Keep polling at a
  modest interval, log out cleanly if a logout URL is configured, and document
  the effect on the user's own browser sessions.
- **Safety**: only RFC1918/link-local hosts; no redirects to other hosts;
  response size cap (2 MB); short timeouts; never follow `file:`/non-http
  schemes; credentials never logged. This is an SSRF surface — an admin-only
  API that fetches arbitrary URLs must be locked to the LAN.

## 2.4 Extraction — and why not trafilatura alone

`trafilatura` is built to strip boilerplate and return the *main article text*
of a page. A switch statistics page is the opposite: it is mostly
navigation, tables and form controls — exactly what trafilatura is designed to
discard — so it is lossy and unpredictable here. Recommendation:

- **Primary:** parse the real DOM with `selectolax` (fast, small) or `lxml`,
  and convert `<table>`s into rows. Many old switch UIs use `<frameset>`/`<iframe>`
  and the stats live in a *sub-document* — fetch frames explicitly, or let the
  user paste the frame URL.
- **Fallback only:** `trafilatura` (with tables enabled) or plain text
  extraction for pages with no usable `<table>`, feeding the regex layer below.

Extraction layers, tried in order; first confident result wins:

1. **Embedded/XHR JSON or XML.** Many switch UIs fetch data from a separate
   endpoint (or inline `var ports = [...]`). If the user supplies that
   endpoint, or we find a JSON blob in a `<script>`, parse it directly —
   most reliable. (The preview shows detected endpoints.)
2. **Table layer.** Find tables whose header cells match the lexicon; pick the
   best-scoring table; map columns.
3. **Key-value layer.** Rows like `Port 3  TxGoodPkt 12  RxGoodPkt 40` or
   definition lists.
4. **Free-text regex layer** over text extraction — last resort.

**Lexicon** (case-insensitive, multi-language-ready, editable):

| Concept | Header keywords |
|---|---|
| port | `port`, `interface`, `if`, `p1`… |
| mac | `mac`, `mac address`, `hardware` |
| rx / in | `rx`, `recv`, `received`, `in`, `ingress`, `inoctets`, `rx bytes` |
| tx / out | `tx`, `sent`, `transmit`, `out`, `egress`, `outoctets`, `tx bytes` |
| unit hint | `bytes`, `octets`, `packets`, `pkts`, `kb`, `mb`, `gb`, `mbps` |

**Value handling** (this is where generic scrapers go wrong):

- Parse `1,234,567`, `1.2 GB`, `850 Kbps`, `0x…`, and locale decimals.
- **Packets vs bytes:** if only packet counters are available the target is
  flagged *packets-only* — usable for liveness but not for upload/download;
  tell the user rather than showing fake Mbps.
- **Cumulative vs rate:** most pages show cumulative counters → reuse the
  existing delta calculator (`sentinel/adapter/sagemcom/delta.py`, move to a
  shared module) including reset and 32-bit wrap handling. Pages showing a
  rate (Mbps) are marked `kind: rate`.
- **Stale page:** if no counter changes for N polls on a port that is link-up,
  flag "not updating" (some UIs cache).
- Normalise MACs (`aa-bb-cc…`, `AABB.CCDD…`, `aabbcc…` → `AA:BB:CC:…`).

**Mapping profile** saved per target:

```json
{
  "mode": "joined",
  "stats":  {"table": {"header_match": "Port.*Rx.*Tx"}, "cols": {"port": 0, "rx": 3, "tx": 5},
             "unit": "bytes", "kind": "cumulative"},
  "macs":   {"table": {"header_match": "MAC"}, "cols": {"mac": 1, "port": 2}},
  "perspective": "port"
}
```

Profiles are matched by header regex, not just column index, so a firmware
update that inserts a column doesn't silently shift the data.

## 2.5 Architecture

New package, beside doc 12's SNMP sources (CLAUDE.md rule 1 spirit: the
scraper is a *source*; detectors never see HTML):

```
sentinel/switches/
  models.py              # shared with doc 12: SwitchPortSample, MacTableEntry
  source.py              # SwitchSource protocol: async poll() -> SwitchPoll
  snmp/…                 # doc 12
  scrape/
    fetcher.py           # httpx client per target, TLS/redirect/size guards
    auth.py              # none/basic/digest/form/cookie strategies
    extract/
      tables.py          # DOM → rows, header scoring
      lexicon.py         # keyword sets
      embedded.py        # JSON/XML endpoints and <script> blobs
      text_fallback.py   # trafilatura / regex
      values.py          # number & unit parsing, MAC normalisation
    profile.py           # mapping profile dataclass + autodetect + validate
    scrape_source.py     # ScrapeSwitchSource(SwitchSource)
```

`SwitchMonitor` (doc 12 §6) consumes any `SwitchSource`; `enricher.py` joins
port counters with the MAC table and emits `TrafficSample`s with the correct
granularity. Data classes are dataclasses with type hints and docstrings, per
CLAUDE.md. Scheduler: a `switch_scrape_job` per enabled target with
exponential back-off on failure and a per-target `last_ok` / `last_error`
shown in the UI.

**Data model**: `switch_targets` table (slot 1–5 with a CHECK constraint /
unique index, name, urls, auth mode, username, non-secret auth config JSON,
mapping profile JSON, perspective, enabled, `last_ok_at`, `last_error`);
passwords in `switch_{slot}_password` secret files. Alembic migration.

**API**: `GET/POST/PATCH/DELETE /api/switches`, `POST /api/switches/preview`
(fetch + extract, return tables and the proposed mapping; does **not** save),
`POST /api/switches/{id}/test`.

## 2.6 Candidate switches (to collect fixtures for)

Not verified; each needs real captured pages in Phase 0 and the exact
stats/MAC-table page names are intentionally not guessed here:

TP-Link TL-SG105E / SG108E (Easy Smart), Netgear GS105E / GS108E / GS308E
(Plus), Zyxel GS1200-5/8, D-Link DGS-1100 smart series, TRENDnet web-smart,
Linksys LGS-series, Mercusys MS108G.

Community contributions: accept a scrubbed HTML capture + mapping profile per
model under `tests/fixtures/switches/<vendor>-<model>/` and list the model as
*supported* only once its fixture test passes.

## 2.7 Testing

- **Fixture tests**: saved HTML/JSON per model → expected `SwitchPoll`
  (offline, fast, deterministic). This is the main safety net.
- **WireMock**: login flows (form + cookie), session expiry/re-login,
  login-page-with-HTTP-200, redirects, oversized responses, frames.
- **Unit tests**: unit/number parsing, MAC normalisation, wrap/reset,
  port-vs-device perspective swap, single-MAC-per-port inference, multi-MAC
  port staying `PER_PORT`, packets-only flagging.
- **Property/fuzz**: random column order and extra columns must not change the
  mapped result when headers are intact.

## 2.8 Phases — Part 2

| Phase | Deliverable | Exit criteria |
|---|---|---|
| 0 | Capture real pages from the user's switch(es); finalise lexicon; decide library (`selectolax` vs `lxml`) | ≥1 real fixture per owned switch |
| 1 | `switch_targets` + migration, fetcher, `none`/`basic`/`digest` auth, table extractor, **Direct** mode, preview endpoint, one-target Settings panel | Owned switch shows correct deltas |
| 2 | **Joined** mode, enricher integration, `PER_DEVICE_INFERRED` badge in Devices UI, perspective handling | Single-MAC port traffic appears under the device, marked inferred |
| 3 | `form login` + `cookie/header`, embedded-JSON layer, up to 5 targets, status/back-off UI | Re-login after expiry proven in WireMock |
| 4 | Key-value/regex fallback, community fixture workflow, docs | Documented "add your switch" guide |

---

## Risks

| Risk | Mitigation |
|---|---|
| Scraped pages break on firmware updates | Header-regex profiles, "not updating"/parse-failure alerts, fixtures per model |
| Single-session switches log the user out of their own browser | Modest poll interval, clean logout, documented clearly |
| Inferred per-device wrongly labelled measured | Distinct granularity value + UI badge + tests |
| Inverted upload/download | `perspective` default + explicit test |
| SSRF via the URL field | LAN-only allow-list, no cross-host redirects, size/time caps |
| Simulator fidelity (synthetic stubs hide real quirks) | Prefer real-OS containers; mark synthetic stub sets; contract tests shared |
| Third-party libs unmaintained | Thin in-tree clients where a library is trivial (`httpx` for ubus/REST) |
| Scope: ~13 adapters is large | Strict phases; each adapter ships only with its simulator suite |

## Open questions for the owner

1. **Switching primary router type at runtime:** keep device history and ML
   models across the switch (MAC-keyed, so mostly fine) or require a purge?
   Default proposed: keep history, tag rows by `source_router`.
2. **Inferred wired traffic:** OK to add `TrafficGranularity.PER_DEVICE_INFERRED`
   (touches the enum, serializers, UI badge, and ML feature gating), or should
   single-MAC ports simply be shown as `PER_PORT` with the device named?
3. **Library choice:** is `selectolax` (fast, minimal, C-based) acceptable, or
   do you prefer `lxml`/`beautifulsoup4` (more tolerant of broken HTML but
   slower)? Switch pages are small, so either is fine; trafilatura is
   proposed only as a fallback.
4. **Which switch(es) do you own?** Phase 0 of Part 2 starts from real
   captures of those — the model decides which auth modes are needed first.
5. **Which routers beyond yours matter?** Reorder the Part 1 priorities if you
   know the audience (e.g. FRITZ!Box first for a German user base).
6. **Docker secrets for dynamic secrets:** the current pattern writes secret
   files at runtime; 5 switch passwords + 2 router slots + API secrets means
   several more writable secret files. Confirm the secrets volume stays
   writable by the backend, or choose another approved mechanism.
