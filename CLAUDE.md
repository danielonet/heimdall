# Heimdall — Home Network Sentinel

## What this project is

A self-hosted, containerised home network security monitor. It connects to a
Sagemcom F@st 5670 router via its proprietary XMO JSON API, collects per-device
traffic data, runs ML anomaly detection, and displays a real-time dashboard with
threat alerts. Everything runs on a dedicated machine on the home LAN as a Docker
Compose stack.

## Tech stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, Flask 3, Flask-SocketIO |
| ML | scikit-learn (IsolationForest), PyOD (LOF) |
| Scheduler | APScheduler (AsyncIOScheduler) |
| HTTP client | httpx (async) |
| Database | PostgreSQL 16 + TimescaleDB |
| ORM | SQLAlchemy 2 async + asyncpg |
| Cache / bus | Redis 7 (Pub/Sub) |
| Frontend | React 19 + Vite + Tailwind CSS |
| Containers | Docker Compose |
| Website | Astro + Starlight (TypeScript), static, deployed over SFTP by GitHub Actions to https://www.heimdall.it.com |

## Repository layout

```
heimdall/
├── CLAUDE.md                  ← you are here
├── README.md
├── docker-compose.yml
├── docs/
│   ├── architecture/          ← backend design documents
│   ├── router/                ← Sagemcom XMO API reference
│   └── frontend/              ← UI design + mockups
├── sentinel/                  ← Python backend
│   ├── adapter/               ← router abstraction layer
│   ├── api/                   ← Flask app + routes
│   ├── detection/             ← threat detector chain
│   ├── ml/                    ← anomaly detection engine
│   ├── security/              ← Scapy, nmap, threat intel
│   ├── db/                    ← SQLAlchemy models + migrations
│   └── scheduler/             ← APScheduler job definitions
├── frontend/                  ← React + Vite SPA
├── install/                   ← setup.sh, bootstrap script, bundle + .deb builders
└── website/                   ← public website + user manual (Astro/Starlight)
    ├── src/pages/             ← home, install, security, equipment, contribute
    ├── src/content/docs/manual/ ← the user manual, one chapter per dashboard page
    ├── src/data/products.ts   ← the security-product pages
    └── public/.htaccess       ← HTTPS, redirects, headers
```

## Non-negotiable architecture rules

1. **Never access the router directly outside the adapter layer.**
   All router communication goes through `sentinel/adapter/sagemcom/xmo_adapter.py`
   which implements `sentinel/adapter/base.py:RouterAdapter`. No other module
   imports from `xmo_client.py` or calls the XMO API directly.

2. **All backend I/O is async.**
   Use `async def` and `await` throughout. The XMO client uses `httpx.AsyncClient`.
   SQLAlchemy uses the async engine. Redis uses `redis.asyncio` (the `aioredis`
   package is archived upstream and cannot even be imported on Python 3.11+;
   its functionality was folded into `redis-py`'s `redis.asyncio` module).

3. **Detectors must subclass `BaseDetector`.**
   Never add detection logic to the adapter, API routes, or scheduler.
   Every detector lives in `sentinel/detection/detectors/` and is registered
   in `sentinel/detection/pipeline.py`.

4. **ML models are per-device, never global.**
   One `IsolationForest` + `LOF` model per MAC address. See
   `docs/architecture/05-ml-anomaly-engine.md`.

5. **Wired devices use PER_PORT traffic granularity.**
   The router API only exposes port-level byte counters for wired devices,
   not per-device. The `TrafficGranularity.PER_PORT` flag on `TrafficSample`
   must be respected — never display wired device traffic as if it is
   per-device measured. See `docs/router/wired-monitoring-caveat.md`.

6. **Secrets via Docker secrets only.**
   Router password, JWT secret, OTX API key — all read from `/run/secrets/`
   files. Never from environment variables or hardcoded values.

## Keep the website and manual in sync with the application

The website (`website/`, published at https://www.heimdall.it.com) is the public
description of what Heimdall does. **Whenever a change adds, removes or alters
something a user can see or rely on, update the website in the same change** — a
feature that exists only in the code, or a page that describes something that no
longer exists, is a bug.

| If you change… | Update… |
|---|---|
| A dashboard page, control, label, setting or workflow | The matching chapter in `website/src/content/docs/manual/` (and the glossary/FAQ/troubleshooting if affected) |
| A detector, alert type, sensor, container, tier or response action | `website/src/data/products.ts` (alert names come from the registry in `docs/architecture/04-detection-pipeline.md`), the diagram in `website/src/components/Flow.astro`, the home-page cards, and the README "Defenses & Capabilities" |
| A router adapter or what one can do (block, quarantine, traffic) | `sentinel/adapter/catalog.py` and `docs/router/equipment-facts.json` (the build fails if an entry is missing), plus the README "Supported routers" table. Mark "Tested" only after a real-hardware run |
| Install, tiers, requirements, upgrade, uninstall, the `.deb` | `website/src/pages/install.astro`, `website/src/data/commands.ts`, the README quick install, and the install scripts' own tests |
| A known limit, or a limit that is now fixed | `website/src/pages/security/limits.astro`, the affected product page's limits, and the README "Known, documented limits" |
| Colours or design tokens in `frontend/src/index.css` | Nothing: `website/src/styles/tokens.css` is generated from it |

Rules for website content:
- Describe only what exists and was checked. Never advertise a planned feature as shipped; label it planned.
- Manual chapters carry a "Draft" note until verified against a running dashboard. Remove the note only after you have actually checked the page.
- No private data on the site: no real MAC addresses, IPs, SSIDs, serial numbers or secrets. Screenshots are synthetic demo data (`docs/images/`).
- Generated files (`website/src/data/routers.json`, `src/styles/tokens.css`, `public/images/`, `public/install.sh`) are not committed. Change their sources.
- Verify before finishing: `cd website && npm run build` (needs Node 22.23.4 or newer), then `python3 scripts/check-links.py dist` and `python3 scripts/check-private.py dist`. Pushes to `main` that touch the site deploy it automatically.

## Where to find what

| Topic | Document |
|-------|---------|
| Full system architecture | `docs/architecture/01-system-overview.md` |
| Router adapter (XMO API) | `docs/architecture/02-router-adapter.md` |
| Flask API + endpoints | `docs/architecture/03-flask-api.md` |
| All threat detectors | `docs/architecture/04-detection-pipeline.md` |
| ML anomaly engine | `docs/architecture/05-ml-anomaly-engine.md` |
| Python security services | `docs/architecture/06-security-services.md` |
| Database schema (SQL) | `docs/architecture/07-database-schema.md` |
| Python dependencies | `docs/architecture/08-dependencies.md` |
| Docker Compose | `docs/architecture/09-docker-compose.md` |
| Sagemcom XMO API xpaths | `docs/router/sagemcom-xmo-api.md` |
| Network topology | `docs/router/network-topology.md` |
| Wired monitoring caveat | `docs/router/wired-monitoring-caveat.md` |
| UI design language | `docs/frontend/ui-design-brief.md` |
| React component map | `docs/frontend/component-map.md` |
| HTML mockups | `docs/frontend/mockups/` |
| Website plan, design, hosting | `docs/website-plan.md`, `website/README.md` |
| Website mockups | `docs/website/mockups/` |

## Code style

- Type hints on every function signature
- Dataclasses for all data transfer objects (not plain dicts)
- `snake_case` for everything Python, `camelCase` for JavaScript/TypeScript
- Docstrings on every class and public method
- `logging` module throughout — never `print()`
- Tests in `tests/` mirroring the `sentinel/` structure
