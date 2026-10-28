# Documentation index

The map of every document in this repository, for people and for agents that start cold.
`CLAUDE.md` points here. Read the row, not the file, to decide whether a document matters
for your task.

**Order of trust when documents disagree:** the code, then `reference` documents, then the
website manual, then `plan` documents. A `plan` records how something was decided and built;
it can be out of date the day after it ships. A `proposal` describes something that is not
built (or only partly): never write it up as a feature.

**Keeping this file true:** `python3 scripts/check-docs-index.py` fails when a document has no
row here, a row points at a file that is gone, or a row has no "read when" text. It runs in
`npm run build` (website) and in CI. `--fix` removes dead rows and adds stubs for new documents;
you then write the sentence. Add a row when you add a document, in the same change.

| Kind | Meaning |
|---|---|
| reference | Describes what exists now. Trust it; fix it when the code changes. |
| plan | How a feature was designed and built. History and rationale, not current behaviour. |
| proposal | Not built, or only partly built. Never describe it as shipped. |
| runbook | Steps for a person to follow. |
| guide | Written for users or contributors. |
| record | A log, checklist or report. Evidence, not specification. |
| data | Machine-read facts that other files are generated or checked from. |
| mockup | Design artefacts. Open in a browser. |

## Start here

| Document | Kind | Read when |
|---|---|---|
| `README.md` | guide | You need what Heimdall claims publicly: install commands, the "Defenses & Capabilities" table, the supported-routers table, known limits. Update it with the website whenever those change. |
| `CONTRIBUTING.md` | guide | You are preparing a change for review or adding a router adapter; says what the maintainer wants most. |
| `SECURITY.md` | guide | You touch privileges (host networking, `NET_RAW`/`NET_ADMIN`), credential handling or disclosure wording; Heimdall is alpha and deliberately privileged. |
| `MOCK-ROUTER-SETUP.md` | runbook | You need to develop without the physical router. Covers the same ground as `docs/architecture/10-mock-router.md`; if you change one, check the other. |

## Architecture (current design)

| Document | Kind | Read when |
|---|---|---|
| `docs/architecture/01-system-overview.md` | reference | First, for any backend task: components, data flow, physical deployment, the monitor's own security posture. |
| `docs/architecture/02-router-adapter.md` | reference | You touch `sentinel/adapter/` or the canonical models. Architecture rule 1 (nothing outside the adapter layer talks to a router) lives here. |
| `docs/architecture/03-flask-api.md` | reference | You add or change a REST endpoint, a Socket.IO event or a config key. |
| `docs/architecture/04-detection-pipeline.md` | reference | You add or change a detector or alert type. Holds the alert registry that the website's security-product pages take their alert names from. |
| `docs/architecture/05-ml-anomaly-engine.md` | reference | You touch `sentinel/ml/`. One model per device, and why: it records the production incidents behind the current design. |
| `docs/architecture/06-security-services.md` | reference | You touch ARP watch, fingerprinting, the scanner, threat intel, or the Zeek, ClamAV and OpenCanary ingestion. |
| `docs/architecture/07-database-schema.md` | reference | You change a table, a hypertable or a migration. |
| `docs/architecture/08-dependencies.md` | reference | You add a Python dependency. `sentinel/requirements.txt` is the source of truth; this mirrors it. |
| `docs/architecture/09-docker-compose.md` | reference | You change `docker-compose.yml`, the install tiers, first-run setup or the Suricata, OpenCanary and Zeek configuration. |
| `docs/architecture/10-mock-router.md` | reference | You use or extend the mock Sagemcom adapter or its WireMock recording. |
| `docs/architecture/11-multi-adapter-auto-detection.md` | proposal | You design router adapters or startup discovery. A specification: the `AdapterRegistry` it names is not in `sentinel/`, though many adapters exist under `sentinel/adapter/`. Its heading says "10."; the file is 11. |
| `docs/architecture/12-switch-discovery-snmp.md` | proposal | You consider managed-switch support (LLDP, SNMP BRIDGE-MIB, per-device wired traffic). Not built: no `sentinel/switches/` and no SNMP code. Its heading says "11."; the file is 12. |
| `docs/architecture/13-wifi-monitor.md` | reference | You touch the WiFi Monitor, rogue-AP detection or the WiFi tab. Live-verified on a monitor-mode USB adapter. |
| `docs/architecture/14-passive-adapter.md` | reference | You touch the "Other / not listed" passive mode for routers Heimdall has no adapter for. |

## Router and network facts

| Document | Kind | Read when |
|---|---|---|
| `docs/router/sagemcom-xmo-api.md` | reference | You touch the Sagemcom client. Marks which xpaths were confirmed against a live call; do not trust a tick it does not back. |
| `docs/router/miwifi-api.md` | reference | You touch the Redmi/Xiaomi adapter. Login, router info and the AP-mode device list are confirmed live; block/unblock and quarantine are not. |
| `docs/router/wired-monitoring-caveat.md` | reference | You display or compute wired-device traffic. Architecture rule 5: wired traffic is per port, never per device. |
| `docs/router/network-topology.md` | reference | You need the shape of the owner's home LAN. It holds real addresses: never copy any of them into the website, README or screenshots. |
| `docs/router/equipment-facts.json` | data | You add or change a router in `sentinel/adapter/catalog.py`. The website build fails until the router has an entry here. |

## Frontend

| Document | Kind | Read when |
|---|---|---|
| `docs/frontend/component-map.md` | reference | You add or move a React component or a page. |
| `docs/frontend/ui-design-brief.md` | reference | You change how the dashboard looks. The live colour tokens are in `frontend/src/index.css`; the website's tokens are generated from them. |
| `docs/frontend/mockups/README.md` | mockup | You want the original desktop and mobile layout studies. |

## How features were built (plans)

Each of these shipped unless the row says otherwise. Read one for the reasoning behind a
feature before you change it, not for how it behaves today.

| Document | Kind | Read when |
|---|---|---|
| `docs/capability-review.md` | plan | You want the prioritised list of gaps and the done/not-done marks. Item #4 (rogue AP) still reads "not built", but doc 13 built it. |
| `docs/section-b-implementation-plan.md` | plan | You touch rogue-DHCP detection, WAN bandwidth tracking, AP aliases, WiFi channel visibility or the wired-PHY direction fix. Marked fully implemented. |
| `docs/section-c-implementation-plan.md` | plan | You touch device-type-aware thresholds, the active/passive OS cross-check or credential-exposure scans. Marked fully implemented. |
| `docs/section-d-implementation-plan.md` | plan | You touch time-limited auto-block, the quarantine tier, cross-alert correlation or the security digest. |
| `docs/zeek-clamav-implementation-plan.md` | plan | You touch the Zeek parser or ClamAV scanning. Marked fully implemented. |
| `docs/suricata-ingestion-plan.md` | plan | You touch the Suricata `eve.json` ingester. The same log-tailing pattern as OpenCanary and Zeek. |
| `docs/deployment-tiers-plan.md` | plan | You touch the minimal, intermediate and full tiers and which services each one runs. |
| `docs/network-map-plan.md` | plan | You touch the Network Map tab (the BIFRÖST radial layout). |
| `docs/dashboard-rail-and-palette-plan.md` | plan | You touch the dashboard's right rail or the palette toggle. It shipped with Amber CRT, not the Arctic Ops palette it first named. |
| `docs/router-and-switch-expansion-plan.md` | proposal | You add router adapters or web-scraped switch monitoring. Part 1 is partly built (many adapters exist); Part 2 is not. Its line saying no registry exists predates those adapters. |

## Running and verifying

| Document | Kind | Read when |
|---|---|---|
| `docs/homelab-deployment.md` | runbook | You install on a dedicated machine with a fixed IP. Written around the GitLab Container Registry; check which registry the images are published to before quoting it. |
| `docs/testing/heimdall_verification.md` | record | You plan penetration-style tests of the detectors. A checklist with no results recorded; not evidence that anything passed. |
| `tests/simulators/README.md` | guide | You test a router adapter against a container-based simulator. |
| `wiremock/README.md` | guide | You add or change a WireMock router simulator. |
| `wiremock/__files/*/NOTES.md` | data | You need to know how faithful one router's simulator is (recorded from real hardware or guessed from vendor docs). |

## The website

| Document | Kind | Read when |
|---|---|---|
| `docs/website-plan.md` | plan | You want why the site is shaped as it is. Its first line still says "nothing built"; the status note near the end is current. |
| `docs/website/mockups/README.md` | mockup | You compare the built site with the reviewed mockups. |
| `website/README.md` | guide | You build, develop or deploy the site; lists which files are generated and must not be committed. |
| `website/src/content/docs/manual/index.md` | guide | You want the manual's table of contents. One chapter per dashboard page: change a page, change its chapter. |
| `website/src/content/docs/manual/first-login.md` | guide | You change sign-in, first-run setup or the initial password flow. |
| `website/src/content/docs/manual/dashboard.md` | guide | You change the Dashboard page. |
| `website/src/content/docs/manual/network-map.md` | guide | You change the Network Map page. |
| `website/src/content/docs/manual/devices.md` | guide | You change the Devices page or a device's detail view. |
| `website/src/content/docs/manual/alerts.md` | guide | You change the Alerts page or an alert's wording. |
| `website/src/content/docs/manual/ports.md` | guide | You change the Ports page. |
| `website/src/content/docs/manual/wifi-scan.md` | guide | You change the WiFi page or WiFi Monitor settings. |
| `website/src/content/docs/manual/threats.md` | guide | You change the Threats page, the threat score or the IP lookup. |
| `website/src/content/docs/manual/rules.md` | guide | You change the Rules page. |
| `website/src/content/docs/manual/reports.md` | guide | You change the Reports page or a report chart. |
| `website/src/content/docs/manual/equipment.md` | guide | You change the Equipment page or the router list. |
| `website/src/content/docs/manual/settings.md` | guide | You add, remove or rename a setting. |
| `website/src/content/docs/manual/mobile.md` | guide | You change the mobile layout (breakpoint 768px). |
| `website/src/content/docs/manual/glossary.md` | guide | You introduce or redefine a term users will see. |
| `website/src/content/docs/manual/faq.md` | guide | A change answers, or invalidates, a question users ask. |
| `website/src/content/docs/manual/troubleshooting.md` | guide | A change adds or removes a way for something to show OFF or fail. |

## Facts that live in code, not prose

These are not documents, but the sync rules in `CLAUDE.md` make them part of the same change.
They are only checked for existing.

| Document | Kind | Read when |
|---|---|---|
| `sentinel/adapter/catalog.py` | data | You add or change a supported router; feeds the website's equipment table. |
| `website/src/data/products.ts` | data | You add or change a detector, sensor or container; one entry per security-product page. |
| `website/src/data/commands.ts` | data | You change an install or upgrade command shown on the site. |
| `website/src/components/Flow.astro` | data | You add a source or detector; it draws the home page's flow diagram. |
| `website/src/pages/security/limits.astro` | data | A known limit appears or is fixed. |
| `website/src/pages/install.astro` | data | You change tiers, requirements, upgrade or uninstall. |
| `frontend/src/index.css` | data | You change a colour or design token; the website's `tokens.css` is generated from it. |

