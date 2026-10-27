# Heimdall Website — Plan

Status: **proposal**, nothing built. Written 2026-10-27 from the repo as it stands
(README, `docs/`, `frontend/src/index.css`, `sentinel/adapter/catalog.py`).

## 1. Goals

1. **Get Heimdall installed.** One copy-paste command per tier on the front page.
2. **Teach people to use it.** A user manual that follows the dashboard page by page.
3. **Say plainly what it is and is not.** A home-security / home-lab statement,
   the supported-equipment list, and what works without a supported router.
4. **Explain the security stack.** Each hosted product (Suricata, Zeek, ClamAV,
   OpenCanary, Nmap, Scapy sensors, threat-intel feeds, the ML engine) and how it feeds
   the one alert flow.
5. **Recruit contributors.** Give a home-lab owner with an unsupported router a kit
   (docs + prompts + scripts) that lets their own AI assistant produce a
   mergeable adapter.

Non-goals: accounts, a hosted/cloud Heimdall, a blog, a forum (GitHub Discussions
covers it), telemetry from installed instances.

## 2. Findings that shape the plan

These are facts about the repo today; each one changes what the site can honestly say.

| # | Finding | Consequence |
|---|---------|-------------|
| F1 | **There is no one-line `docker compose` install yet.** `docker-compose.yml` mounts `./secrets/`, `./secrets/routers/`, `./suricata/`, `./opencanary/` and reads `.env`, so it only works from a repo checkout prepared by `scripts/install.sh`. | The site cannot promise "run this one command" until a standalone **install bundle** exists (Phase 0). |
| F2 | **No images are published yet.** `publish-images.yml` is uncommitted/unpushed; the GHCR packages do not exist and will be private until switched to Public. There are no tagged releases (`SECURITY.md`). | Phase 0 depends on a first successful publish, then a `v0.x` tag so the site can pin a version. |
| F3 | **`apt` is a poor primary channel.** Heimdall is a multi-container stack with host networking, `NET_RAW`/`NET_ADMIN`, per-machine generated secrets and tier profiles. A `.deb` would just wrap Docker anyway. | Lead with a bootstrap script + compose bundle. Offer a thin `.deb` as a download from the first release (built; see §5.3), and a signed apt repo on Hetzner later (Phase 5), as a convenience, not the foundation. |
| F4 | **The product's default palette is Amber CRT, not the green/blue in `ui-design-brief.md`.** `themeStore.js` defaults to `amber`; `index.css` also defines `slate`. The brief predates this. | The site follows `index.css` (source of truth) and ships the same two-palette toggle. The brief should be updated to match (small docs fix, listed in Phase 0). |
| F5 | **`docs/router/network-topology.md` holds a real WAN MAC and BSSID** (and other topology). | Content is published from an **allowlist** of files, never a directory glob. That file is excluded and should be scrubbed regardless. |
| F6 | ~~The "no supported router" mode is not built.~~ **Resolved 2026-10-27:** the `passive` adapter now exists (`docs/architecture/14-passive-adapter.md`). | The "works without a router" page is written from that document. Phase 1 still includes a full-stack run in passive mode to confirm each sensor claim end to end before it is published. |
| F7 | **The README supported-routers table is hand-maintained**, as is `catalog.py`. They can drift. | The site generates its equipment table from `catalog.py` plus a small `tested_hardware.yml` (who tested what, when). The README table is generated from the same data. One source of truth. |
| F8 | `docs/homelab-deployment.md` still refers to a GitLab registry. | Not published as-is; rewritten for GHCR when it becomes the Install guide. |

## 3. Audience

| Persona | Arrives wanting | Lands on |
|---------|-----------------|----------|
| **Home-lab tinkerer** | "Does it run on my box, how do I install it?" | Home → Install |
| **Security-curious homeowner** | "What does it protect me from? Is it safe?" | Home → Security → Home security statement |
| **Router owner** | "Is my router supported?" | Equipment |
| **Contributor with an AI assistant** | "How do I add my router?" | Contribute |
| **Security reviewer / skeptic** | "What are the limits, what does it run as root?" | Security statement, `SECURITY.md` |

## 4. Technology and hosting

**Static site. No backend.** Everything is built in CI and served as files.

| Decision | Choice | Why / alternative |
|----------|--------|-------------------|
| Framework | **Astro** with **Starlight** for `/manual` and `/docs` | Markdown-first (the content already is Markdown), built-in search (Pagefind), zero JS by default, themeable via CSS variables so the product tokens drop straight in. *Alternative:* reuse React/Vite from `frontend/` — matches the product stack but means hand-building docs navigation and search. |
| Hosting | **Existing Hetzner web hosting (PHP/Apache, SSH access)** | Updated 2026-10-27: the host runs PHP and offers SSH, so no VPS or Caddy is needed. The site is still static files; PHP is not used for pages. No CMS and no database: nothing to patch or attack. *Alternative:* a Cloud VPS + Caddy if the host's limits get in the way. |
| Deploy | **GitHub Actions** → build → `rsync` over SSH into a new release directory, then switch a symlink (if the host allows symlinks; otherwise rsync `--delay-updates` into the web root) | A dedicated deploy key, stored as a repo secret, restricted in `authorized_keys` (`command=` rsync-only, fixed path) where the host permits. |
| DNS/TLS | Domain pointed at the host; host-managed Let's Encrypt; HTTPS forced and HSTS in `.htaccess` | `curl ... | bash` is only acceptable over HTTPS with no redirect downgrade. |
| Analytics | **None by default.** If wanted: self-hosted Umami/Plausible on the same box | A security tool's site should not ship third-party trackers. |
| Fonts | Self-hosted JetBrains Mono, Rajdhani, MedievalSharp (subset, `woff2`) | No Google Fonts request, matches the product, faster. |
| Source location | `website/` in this repo | Docs and site change together; the build reads `docs/`, `catalog.py` and `README` directly. |

`.htaccess` (shipped in `website/public/`) does the server work:

- force HTTPS, then HSTS;
- serve `/install.sh` as `text/plain`, uncached, with no redirect chain;
- redirect `/download/heimdall.deb` and `/download/heimdall-bundle.tar.gz` to the GitHub `releases/latest/download/` assets;
- no directory listings, clean URLs, a static 404 page.

Headers set there: `Content-Security-Policy` (self only), `X-Content-Type-Options`,
`Referrer-Policy`, `Permissions-Policy`. The only script is the copy-button and
palette toggle, both inline-hashed or same-origin.

## 5. Install channel (the main goal)

### 5.1 What visitors get

```bash
# minimal | intermediate | full
curl -fsSL https://heimdall.it.com/install.sh | sudo bash -s -- --tier=intermediate
```

and, shown right below for people who will not pipe to bash:

```bash
mkdir heimdall && cd heimdall
curl -fsSLO https://heimdall.it.com/releases/v0.1.0/heimdall-bundle.tar.gz
curl -fsSLO https://heimdall.it.com/releases/v0.1.0/heimdall-bundle.tar.gz.sha256
sha256sum -c heimdall-bundle.tar.gz.sha256 && tar xzf heimdall-bundle.tar.gz
./setup.sh --tier=intermediate      # generates secrets/ and .env, then:
docker compose --profile intermediate pull && docker compose --profile intermediate up -d
```

### 5.2 Status of Phase 0 (updated 2026-10-27)

Built and tested, uncommitted: `install/setup.sh`, `install/make-bundle.sh`, `install/get-heimdall.sh` (served as `/install.sh`), `.github/workflows/release-bundle.yml`, tests in `tests/test_install/`, and a CI job running shellcheck plus those tests. The bundle's `.env` sets `COMPOSE_PROFILES`, so `docker compose pull && docker compose up -d` is the same command for every tier. The bootstrap downloads from GitHub Releases (`releases/latest/download/...`), so the site only has to serve the script itself.

Still to do before the command on the home page is true: (1) push these changes; (2) the `ci.yml` concurrency fix, because the first "Publish images" run was **cancelled** (the reusable CI shared a concurrency group with the push-triggered CI run), so no images exist yet; (3) set both GHCR packages Public; (4) tag `v0.1.0`; (5) a clean-VM run of the real command. The first-boot router gap is closed: `setup.sh`/`install.sh` take `--router=passive` (or ask on a terminal), written as `INITIAL_ROUTER` and applied once on a pristine install by `sentinel/adapter/initial_router.py`.

Original checklist, for reference:

### 5.2a What has to exist first (Phase 0)

1. **Install bundle** (`heimdall-bundle.tar.gz`, attached to each GitHub Release and
   mirrored under `/releases/`): `docker-compose.yml` (image-only, no `build:`),
   `.env.example`, `setup.sh`, the `suricata/` and `opencanary/` config dirs,
   and a short README. `setup.sh` is the slimmed `install.sh --pull`: checks Docker,
   generates unique secrets, writes `.env`, prints the exact `compose` command for the tier.
2. **`install.sh` bootstrap** that does only: detect OS, install Docker if missing
   (asks first), download and verify the bundle, run `setup.sh`. It must be short,
   readable and idempotent; the site shows its source on the page.
3. **First publish**: push `publish-images.yml`, make both GHCR packages Public.
4. **Tag `v0.1.0`**, so the bundle URL and image tags are pinned, not `latest`.
5. Fix F4 and F8 in `docs/`.

### 5.3 The `.deb` and the apt question (updated 2026-10-27)

**Decided: the website offers the `.deb` as a download from the first release.**
It is built (`install/deb/make-deb.sh`, tested in `tests/test_install/test_deb_package.py`)
and attached to every GitHub Release by `release-bundle.yml` as
`heimdall_<version>_all.deb`, a stable-name copy `heimdall_all.deb`, and a `.sha256`.
The install page therefore has two tabs: **Script** (`curl ... | bash`) and
**Debian / Ubuntu** (download, verify, `sudo apt install ./heimdall_all.deb`,
`sudo heimdall setup`, `sudo heimdall start`). The download button links to
`.../releases/latest/download/heimdall_all.deb`, so the site never needs a rebuild
for a new release; the displayed version and checksum come from the GitHub API at
build time (or a small client fetch with a static fallback).

What the package is, and is not (F3 still applies): it wraps the same compose
bundle and still depends on Docker, so it is a convenience, not a native
package. It installs under `/opt/heimdall`, a `heimdall` command and a systemd
unit; it **does not start or enable anything** (a LAN sniffer should not start
without a tier and router choice). Purge keeps `.env`, `secrets/` and the Docker
volume, because the database was created with those secrets; `heimdall reset`
is the explicit delete.

**Still Phase 5:** a signed apt repository (`aptly` or `reprepro` run in CI,
dedicated GPG key, the generated static repo rsynced to the web host) so `apt upgrade` finds new versions. Until then
an upgrade means downloading the newer `.deb`; the install page says so
plainly. The `.deb` is `Architecture: all`, so it needs no per-arch build; the
images it pulls are amd64 only until linux/arm64 is added to the publish workflow.

### 5.4 Trust and safety on the install page

- Show the script source and its SHA-256 next to the command.
- State what it changes (copy from README: apt packages, docker group, `secrets/`, `.env`; it does not touch the router).
- State requirements: Linux host with Docker on the same LAN; wired preferred; do **not** expose ports 3000/5000 to the internet.
- Upgrade (`docker compose pull && up -d`; migrations run on start) and uninstall (`down -v` and what that deletes).

## 6. Information architecture

```
/                         Home
/install                  Install (tiers, requirements, upgrade, uninstall, verify)
/manual                   User manual (Starlight)
  /manual/first-login
  /manual/dashboard
  /manual/network-map
  /manual/devices            (+ device detail)
  /manual/alerts
  /manual/threats
  /manual/ports
  /manual/wifi-scan
  /manual/rules
  /manual/reports
  /manual/equipment          (add a router, credentials, primary router)
  /manual/settings           (notifications, auto-block, retention)
  /manual/mobile
  /manual/troubleshooting
  /manual/faq
  /manual/glossary
/security                 Cyber-security capabilities (overview + flow diagram)
  /security/detectors        passive detectors (ARP, DHCP, fingerprint, ML, ...)
  /security/nmap
  /security/suricata
  /security/zeek
  /security/clamav
  /security/opencanary
  /security/threat-intel
  /security/response         block, quarantine, auto-block, correlation
  /security/limits           known, documented limits
/home-security            Home security & home lab statement
/equipment                Supported equipment (generated table)
  /equipment/no-router       What works without a supported router
/contribute               Contribute (overview, test your router, write an adapter)
  /contribute/ai-kit         The AI contribution kit + download
  /contribute/test-your-router
/about                    Project, license (MIT), alpha status, security policy link
/changelog                Releases
```

Top navigation (desktop): `INSTALL · MANUAL · SECURITY · EQUIPMENT · CONTRIBUTE · GITHUB`.
Mobile: collapsed menu; the install block is the first thing under the hero.

## 7. Page-by-page content and sources

| Page | Content | Built from |
|------|---------|------------|
| **Home** | Hero (logo, "A home SOC and NOC in one box", the three-tier install block), live-dashboard screenshot, four value cards (Detect · See · Respond · Stay informed), the flow diagram (§8), supported-routers teaser, alpha banner, contribute call-out | README intro + `docs/images/*.png` |
| **Install** | §5 in full; tier comparison table; requirements; first login; offline "mock router" try-it mode | README Installation, `deployment-tiers-plan.md`, `MOCK-ROUTER-SETUP.md`, rewritten `homelab-deployment.md` |
| **User manual** | One chapter per dashboard page, each with: what you see, what each control does, common tasks ("block a device", "acknowledge an alert", "add a second router"), screenshot, what NOT to infer (e.g. `PORT TOTAL` on wired devices is not per-device traffic). Troubleshooting, FAQ, glossary | `docs/frontend/component-map.md`, the page components under `frontend/src/pages/`, README capabilities, `docs/router/wired-monitoring-caveat.md`. **New writing is required**; no user manual exists today. |
| **Home security statement** | Why Heimdall exists; what a home network's threat model looks like (compromised IoT, ARP/DHCP abuse, exfiltration, C2, exposed services); what Heimdall deliberately is (passive-first, self-hosted, no cloud, your data stays on the box) and is not (not a firewall, not an EDR, not a substitute for patching); legal line: only monitor networks you own or are authorised to monitor | README, `SECURITY.md`, `capability-review.md` |
| **Equipment** | Generated table: family, adapter state, tested-on-real-hardware, automated tests, simulator, what it can/cannot do (block, per-device traffic). A "tested on real hardware" badge only from `tested_hardware.yml`. Link to the test-your-router flow. Switches (Part 2 of the expansion plan) as "planned" | `sentinel/adapter/catalog.py`, `tested_hardware.yml`, expansion plan |
| **No supported router** | Two honest columns: *works today* / *needs development*. See §9 | Verified in Phase 1 |
| **Security overview** | The flow diagram, tier matrix (which products run in which tier), then a card per product linking to its page | `06-security-services.md`, `04-detection-pipeline.md`, `deployment-tiers-plan.md` |
| **Contribute** | Three paths: test (no code), document (scrubbed captures), implement (with AI or by hand). Ground rules, architecture rules, how review works, recognition (tested-by credit in the table) | `CONTRIBUTING.md`, issue templates |
| **AI kit** | §10 | New `docs/contributing-with-ai/` |

All published prose is **edited for the web**, not mirrored. Source docs in the repo
stay the engineering record; the site is the front door.

## 8. The security section: one template per product

Every product page uses the same six blocks, so the reader learns the pattern once:

1. **What it is** (one sentence, plain language)
2. **What it sees** (data source: sniffed packets, router API, logs, files, feeds)
3. **What it catches** (the alert types it raises, e.g. `IDS_SIGNATURE_MATCH`)
4. **How it plugs in** (container → ingestion → detector → alert → correlation → response/notify)
5. **Runs in** (tier badge: minimal / intermediate / full)
6. **Limits** (honest list, e.g. DoH bypasses Zeek DNS; Suricata ruleset unmanaged)

Overview diagram (SVG, drawn with the product palette; also the Home page figure):

```
 SOURCES                     DETECTORS                  ALERT FLOW            RESPONSE & NOTIFY
 ───────                     ─────────                  ──────────            ─────────────────
 Router API (adapter) ─────► Traffic/ML, upload ratio,
                             signal, trust-boundary ──┐
 Scapy sniffer ────────────► ARP, rogue DHCP,          │
                             OS fingerprint ───────────┤
 Nmap (nightly) ───────────► ports, CVEs, creds, OS ───┤
 Zeek logs ────────────────► DNS, C2 beaconing ────────┼─► Alert ─► Correlation ─► Block · Quarantine
 ClamAV ◄── Zeek files ────► MALWARE_DETECTED ─────────┤   store     (pairs →      Auto-block (timed)
 Suricata EVE ─────────────► IDS_SIGNATURE_MATCH ──────┤   (PG)       incident)    Dashboard (WebSocket)
 OpenCanary ───────────────► HONEYPOT_ACCESS ──────────┤                           ntfy · email · digest
 Threat-intel feeds ───────► reputation lookups ───────┘                           CSV · /api/metrics
```

Products to cover and their one-line integration story (each to be confirmed against
`docs/architecture/04-detection-pipeline.md` while writing):

| Product | Role in the flow |
|---------|------------------|
| Router adapter | Inventory, per-device/per-port traffic, WAN, block/quarantine actuator |
| Scapy sensors | Passive ARP, DHCP, OS-fingerprint events on the sniff interface |
| ML engine | Per-device IsolationForest + LOF over that device's own traffic history |
| Nmap | Nightly active scan; open ports, vulns, default credentials, OS cross-check |
| Zeek | DNS and connection logs → DNS_MALICIOUS_QUERY, C2_BEACONING; extracts files |
| ClamAV | Scans Zeek-extracted files → MALWARE_DETECTED |
| Suricata | Signature IDS; EVE alerts tailed into the Heimdall alert feed |
| OpenCanary | Decoy services; any touch is CRITICAL |
| Threat-intel feeds | Feodo, Tor exits, Spamhaus DROP, URLhaus, OTX lookups |
| TimescaleDB / Redis | Time-series storage and the pub/sub bus behind the live dashboard |
| Notifications | ntfy, SMTP, daily digest, CSV export, Prometheus metrics |

## 9. "Without a supported router" page

Written as two lists, populated from a test run in Phase 1 rather than from the docs:

- **Works today (to verify):** sensors that only need the sniff interface: ARP watch,
  rogue-DHCP watch, passive fingerprinting, Suricata, Zeek, ClamAV, OpenCanary,
  nightly Nmap sweep, threat-intel feeds, notifications.
- **Needs a router adapter:** authoritative device list and names, per-device traffic and
  the ML detectors fed by it, WAN stats, WiFi AP/radio data, block and quarantine.
- **Planned development:** the `passive` adapter (inventory from ARP/Nmap sweep) described
  in `router-and-switch-expansion-plan.md`. The page links to the GitHub issue tracking it
  and invites contribution. If the passive adapter is not built by launch, the page says
  "partial coverage today" and does not say "works with any router".

## 10. The AI contribution kit

Goal: someone with a router we do not support, and an AI coding assistant, can produce a
PR that passes review. The kit is **documents in the repo** (versioned, reviewable),
linked and downloadable from the site as one zip.

New directory `docs/contributing-with-ai/`:

| File | Purpose |
|------|---------|
| `README.md` | What the kit is, who it is for, the workflow in 8 steps, what a good PR looks like |
| `AGENTS.md` | Project brief written *for the assistant*: the six non-negotiable architecture rules, code style, directory map, "never do" list (no tight-loop logins, no real data in fixtures, no secrets in env, no faking per-device traffic) |
| `01-identify-your-device.md` | How to find out how the router is managed: vendor docs, existing libraries, browser dev-tools, API type, auth method |
| `02-capture-and-scrub.md` | Capture with HAR or the WireMock recorder, then scrub. Checklist of what to remove (MACs, IPs, SSIDs, serials, tokens, cookies, hostnames) and what to keep (OUI prefix) |
| `scrub_har.py` | Script that does the scrub mechanically and prints a report of what it replaced, so the human reviews the result before sharing it with anyone |
| `03-build-the-stubs.md` | Turn the scrubbed capture into `wiremock/mappings/<router-id>/` stubs and `__files/`, with the session-expiry scenario |
| `04-implement-the-adapter.md` | Step-by-step on `HttpRouterAdapter`, `RouterSpec` in `catalog.py`, factory registration, what to return when the router cannot do something |
| `05-tests-and-definition-of-done.md` | Contract and behaviour tests, how to run them, checklist (lint, tests green, docs written, README row, no real data) |
| `06-report-real-hardware.md` | How to report "works / partly / fails" so the maintainer can flip the row to tested |
| `adapter-template/` | Skeleton adapter, spec entry, stub folder and test file with `TODO`s |
| `prompts/` | Copy-paste prompts: "analyse this capture", "write the stubs", "write the adapter against this template", "review my adapter against AGENTS.md" |
| `switches.md` | Same flow for the SNMP / web-UI switch work in Part 2 of the expansion plan |

Safety rules baked into the kit and stated on the site:

- **Scrub before sharing with any AI service.** A raw HAR contains credentials and your
  network map. The kit makes `scrub_har.py` step one, not an afterthought.
- The contributor never sends their router password to anyone; tests run on stubs.
- An assistant that cannot reach the device must say so rather than invent endpoints.
  "Honesty about sources" (already in the expansion plan) is copied into `AGENTS.md`.
- Merged adapters start as "simulator-tested only" until a real-hardware report arrives.

Site page `/contribute/ai-kit`: a short pitch, the 8-step flow as a numbered strip, a
**Download kit** button (zip built in CI from that directory), the prompt library rendered
with copy buttons, and a "my router is not in the list" shortcut that opens the
`new_router_support` issue template.

## 11. Design (derived from the product UI)

### 11.1 Principles carried over from the product

From `docs/frontend/ui-design-brief.md` and `frontend/src/index.css`:

- Dark NOC aesthetic, flat surfaces, **no background gradients**.
- 1px borders; **3px left accent strip** on cards to show status; thin top gradient line on cards.
- Glowing 7px status dots; pulse on live items; blink on critical.
- Monospace body, Rajdhani/Exo-style headings, MedievalSharp (`--font-nordic`) only for the wordmark.
- Severity chips CRIT / WARN / INFO / OK; the `PORT TOTAL` amber badge.
- Two palettes with a runtime toggle, default **Amber CRT**, alternative **Slate**.

### 11.2 Tokens (copied, not reinterpreted)

The site imports the same CSS variables so a change in the product palette is one copy away.
`website/src/styles/tokens.css` is generated from `frontend/src/index.css` by a build step
rather than pasted, so they cannot drift.

| Token | Amber (default) | Slate |
|-------|-----------------|-------|
| `--color-bg` | `#12100a` | `#10141a` |
| `--color-surface` | `#1a170f` | `#161b23` |
| `--color-surface-elevated` | `#221d13` | `#1c2330` |
| `--color-accent-green` (primary) | `#ffb02d` | `#6fbf8f` |
| `--color-accent-blue` (info) | `#c97a3d` | `#7fb2e0` |
| `--color-accent-amber` (warn) | `#ffd23a` | `#d9a556` |
| `--color-accent-red` (crit) | `#ff5a3a` | `#e6707f` |
| `--color-text-primary` | `#e8dcc8` | `#cdd6e2` |
| `--color-text-secondary` | `#c4b190` | `#93a3b8` |
| `--color-text-muted` | `#a3854d` | `#7186a3` |

The token named `accent-green` is amber in the default palette (a product naming quirk).
The site uses the role names (`primary`, `info`, `warn`, `crit`) in its own CSS and maps them.

The palette toggle in the site header uses the same `data-palette` attribute and
`heimdall_palette` localStorage key, so a visitor's choice follows them between the site
and, if the browser is shared, a locally hosted dashboard on another origin only by
re-selecting; no cross-origin sharing is attempted.

### 11.3 Components (site-specific, built from product parts)

| Component | Derived from | Notes |
|-----------|--------------|-------|
| `TerminalBlock` | `MetricCard` surface + mono | Install command, tier tabs, **copy** button, `$` prompt, blinking cursor (disabled under `prefers-reduced-motion`) |
| `StatusDot` / `Chip` | `StatusDot.jsx`, `Badge.jsx`, `SeverityBar.jsx` | Used for tier badges, tested/untested, severity |
| `CapabilityCard` | dashboard service cards | Left accent strip + top gradient line; accent colour = tier (full=red-ish crit would mislead, so: minimal=primary, intermediate=info, full=warn) |
| `FlowDiagram` | network-map visual language | Inline SVG, nodes as bordered boxes, animated "packet" along edges only on hover/focus |
| `RouterTable` | Devices table | Sticky header, badges for `Implemented / Planned`, `Tested on hardware` |
| `ScreenshotFrame` | topbar of the dashboard | Window chrome with the real PNGs from `docs/images/` |
| `StepStrip` | — | Numbered steps for install and the AI kit |
| `Callout` | alert chips | `note` (info), `caution` (warn), `danger` (crit), used for the legal/safety statements |

### 11.4 Layout

Desktop: 1200px content column, sticky top bar (logo, nav, palette toggle, GitHub stars link).
Manual and docs add the Starlight left sidebar (220px, matching the product sidebar width)
and right-hand "on this page". Mobile: single column, 16px gutters, no horizontal scroll,
the install block is the first element after the hero.

### 11.5 Home page wireframe (desktop)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ◈ HEIMDALL        INSTALL  MANUAL  SECURITY  EQUIPMENT  CONTRIBUTE  GITHUB ◐ │
├──────────────────────────────────────────────────────────────────────────────┤
│ ● ALPHA — monitors and can block devices on your LAN. Read the limits.   [x]  │
│                                                                              │
│   A home SOC and NOC in one box.                                             │
│   Self-hosted security and network operations for the LAN you own.           │
│                                                                              │
│   ┌ INSTALL ───────────────────────────────────────────────────────────┐     │
│   │ [ minimal ] [ intermediate ] [ full ]                              │     │
│   │ $ curl -fsSL https://heimdall.it.com/install.sh | sudo bash -s -- --tier=…│ COPY│
│   │ or: download bundle · verify checksum · view the script            │     │
│   └────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│   ┌───────────────────────────── dashboard screenshot ─────────────────┐     │
│   └────────────────────────────────────────────────────────────────────┘     │
├──────────────────────────────────────────────────────────────────────────────┤
│ ▌DETECT        ▌SEE            ▌RESPOND         ▌STAY INFORMED               │
│  8 passive     devices,        block,           dashboard, ntfy,             │
│  detectors +   traffic, WiFi,  quarantine,      email, daily digest          │
│  Suricata,     ports           auto-block                                    │
│  Zeek, ML                                                                    │
├──────────────────────────────────────────────────────────────────────────────┤
│ HOW IT FITS TOGETHER            [ flow diagram, §8 ]                         │
├──────────────────────────────────────────────────────────────────────────────┤
│ YOUR ROUTER?   Sagemcom ✓hw  Redmi ✓hw  OpenWrt ◐  MikroTik ◐  UniFi ◐ …    │
│ Not listed? Heimdall still runs. → what works   |   Help add yours → AI kit  │
├──────────────────────────────────────────────────────────────────────────────┤
│ footer: MIT · SECURITY.md · GitHub · Discussions · version v0.1.0            │
└──────────────────────────────────────────────────────────────────────────────┘
```

(`✓hw` = tested on real hardware, `◐` = simulator-tested only; same meaning as the README.)

Mockups follow the repo's existing habit: static HTML in `docs/website/mockups/`
(home, install, security product page, equipment) before any Astro work, reviewed in a
browser, then ported.

### 11.6 Accessibility, performance, quality gates

- Contrast check of every token pair in both palettes (muted text on amber is the likely failure); adjust the site's text colour if needed rather than the product's.
- Keyboard-operable tabs and copy buttons; visible focus ring in the accent colour.
- `prefers-reduced-motion` turns off pulse, blink and diagram animation.
- Budgets: home page under 150 KB transferred excluding screenshots; screenshots as WebP with `width`/`height`; Lighthouse ≥ 95 performance/accessibility/SEO in CI.
- Link checker and spell check in CI. Every shell snippet is extracted and run through `shellcheck`.
- Docs-drift guard: the equipment table and tier matrix are generated, and CI fails if they cannot be built.

## 12. Content governance

- **Single source of truth per fact:** routers → `catalog.py` + `tested_hardware.yml`; tiers → `sentinel/deployment_tiers.py`; alert types and services → the existing Python constants; capabilities text → README/docs.
- **Allowlist publishing:** `website/content-manifest.yml` lists exactly which `docs/` files feed the site. New docs are private to the site until added (F5).
- **Screenshots** only from `docs/images/` (demo data). New ones are made against the mock router.
- **Claims are tested:** any sentence like "catches X" must map to an alert type in the code or the verification plan (`docs/testing/heimdall_verification.md`). Anything unverified is labelled as such, the same convention the README already uses.
- **Versioning:** manual pages carry the Heimdall version they were written for; the install page always pins a version.

## 13. Phases

| Phase | Deliverable | Done when |
|-------|-------------|-----------|
| **0 — Install foundation** | First image publish (GHCR public), `v0.1.0` tag, install bundle, `setup.sh`, `install.sh`, checksum; fix F4/F8 | A clean VM installs each tier with the documented command and the dashboard loads |
| **1 — Facts** | Run Heimdall with no adapter and record what works (§9); inventory of UI pages for the manual; `tested_hardware.yml`; generators for equipment table and tokens | Facts file reviewed by the owner |
| **2 — Design** | Static HTML mockups (home, install, security product, equipment, manual page) in both palettes; contrast report | Owner signs off on look |
| **3 — Skeleton and deploy** | Astro project, tokens, layout, `.htaccess`, SSH/rsync CI deploy, HTTPS, headers; Home + Install live | Site reachable on the domain with the install command |
| **4 — Content** | Manual, security section, home-security statement, equipment, no-router page, about, changelog | Every page in §6 exists and passes link/spell/shellcheck |
| **5 — Community** | AI contribution kit and `scrub_har.py` in repo, kit zip in CI, contribute pages, issue-template links; signed apt repo (the `.deb` download itself already ships with the first release) | A volunteer (or a dry run by the maintainer with a fresh assistant) produces a stub set from the kit |
| **6 — Launch** | Lighthouse and a11y pass, final claims review, announce (GitHub README link, relevant home-lab communities) | Launch checklist complete |

Rough order of effort: Phase 0 is the critical path and the largest unknown; the user manual is the largest
single writing job; everything else is small.

## 14. Risks

| Risk | Mitigation |
|------|------------|
| Site promises an install that does not work | Phase 0 gates Phase 3; install snippets are tested in CI on a clean container/VM |
| `curl \| bash` distrust | Readable script, shown inline, checksum, manual alternative, version-pinned |
| Alpha software with host-network, privileged containers presented as a polished product | Alpha banner, security-statement page, `SECURITY.md` link, limits page, no "protects you from" absolutes |
| Contributors paste raw captures into AI services | `scrub_har.py` first, repeated warnings, kit prompts assume scrubbed input |
| Private data leaks through docs (F5) | Allowlist manifest, grep for MAC/IP patterns in CI over published content |
| Tables drift from code | Generated from `catalog.py`; README table generated too |
| Single maintainer cannot answer a flood of "my router" issues | Issue template requires the capture/scrub checklist; "tested" badge is the reward, not a promise of support |

## 15. Decisions and open questions

**Decided (2026-10-27):** domain is `heimdall.it.com`; install route is the bootstrap script; the `.deb` download ships with the first release (built 2026-10-27), the signed apt repo is Phase 5; the passive adapter is built before launch (done), so §9 describes a shipped feature.

**Still open**

1. ~~Which Hetzner product~~ **Resolved:** web hosting with PHP and SSH (Apache `.htaccess`; rsync deploy). Still to confirm on the account: Apache vs nginx, whether symlinks and `mod_headers`/`mod_rewrite` are allowed, and a restricted SSH key.
2. **Project name on the site:** "Heimdall" is a common name (Heimdall dashboard, etc.). Keep it, or add a qualifier ("Heimdall Sentinel")?
3. **Analytics:** none, or self-hosted?
4. **Languages:** English only at launch?
5. **Community venue:** GitHub Discussions only, or also a chat server?
6. **Maintainer identity on the site:** name/handle, or project-only?
