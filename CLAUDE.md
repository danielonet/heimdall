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
└── frontend/                  ← React + Vite SPA
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

## Code style

- Type hints on every function signature
- Dataclasses for all data transfer objects (not plain dicts)
- `snake_case` for everything Python, `camelCase` for JavaScript/TypeScript
- Docstrings on every class and public method
- `logging` module throughout — never `print()`
- Tests in `tests/` mirroring the `sentinel/` structure
