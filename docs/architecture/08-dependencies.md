# Python Dependencies

Full `requirements.txt` for the `sentinel-backend` container — this mirrors
`sentinel/requirements.txt` exactly (that file, not this doc, is the source
of truth; copy it here, don't hand-maintain a duplicate that can drift again
— see the note below).

> **Note**: an earlier version of this doc described an aspirational
> dependency list from before implementation started (`flask-cors`,
> `flask-limiter`, `gevent`, `psycopg2-binary`, `pyshark`, `dpkt`, `netaddr`,
> `pymisp`, `python-stix2`, `passlib`, `python-jose`, `cryptography`,
> `pyOpenSSL`, `structlog`, `joblib`, `scipy`, `python-dateutil`, among
> others) that was never actually installed — a stale, duplicate root-level
> `requirements.txt` carried the same drift and has been removed. None of
> those packages have any callers in `sentinel/`; if a future feature needs
> one, add it to `sentinel/requirements.txt` and update this doc in the same
> change, not separately.

## requirements.txt

```
# ── Web framework & API ────────────────────────────────────────────────────
Flask==3.0.3
asgiref==3.11.1              # required for Flask's native `async def` view support
Flask-SocketIO==5.3.5
Flask-JWT-Extended==4.5.3
python-socketio==5.9.0
python-engineio==4.8.0       # pulls in simple-websocket, which is what actually
                              # gives Flask-SocketIO's async_mode='threading' real
                              # WebSocket upgrades under a threaded WSGI server

# ── WSGI application server ────────────────────────────────────────────────
gunicorn==21.2.0             # --worker-class gthread (not gevent — see below)

# ── Async database & ORM ───────────────────────────────────────────────────
SQLAlchemy==2.0.51
asyncpg==0.31.0              # async PostgreSQL driver (referenced via the
                              # postgresql+asyncpg:// URL scheme, not imported directly)
alembic==1.12.1              # migrations; env.py runs through the same async
                              # engine/driver, no separate sync driver needed

# ── Redis (Pub/Sub) ─────────────────────────────────────────────────────────
redis==5.0.1                 # includes redis.asyncio; aioredis is archived
                              # upstream and unusable on Python 3.11+

# ── Async HTTP client ───────────────────────────────────────────────────────
httpx==0.25.2
tenacity==8.2.3              # retry with exponential back-off (XMO client, threat intel)

# ── Task scheduling ─────────────────────────────────────────────────────────
APScheduler==3.10.4          # AsyncIOScheduler for all background jobs

# ── Configuration ───────────────────────────────────────────────────────────
pydantic==2.13.4
pydantic-settings==2.14.2    # its env_file support pulls in python-dotenv
                              # transitively — not imported directly here either
python-dotenv==1.2.2

# ── Machine learning & anomaly detection ───────────────────────────────────
scikit-learn==1.9.0          # IsolationForest
PyOD==3.6.1                  # LOF — 1.1.2 predates scikit-learn's __sklearn_tags__
                              # API (sklearn>=1.6) and crashes on LOF.predict()
                              # under scikit-learn==1.9.0 above
numpy==2.4.6
pandas==3.0.3                # Zeek conn.log parsing / beacon-interval feature engineering

# ── Network security ────────────────────────────────────────────────────────
Scapy==2.7.0                 # ARP/DHCP sniffing, passive OS fingerprinting
python-nmap==0.7.1           # nightly active scan (OS detection, vuln/default-account NSE)

# ── Threat intelligence ─────────────────────────────────────────────────────
OTXv2==1.5.12                # AlienVault Open Threat Exchange SDK

# ── Anti-malware integration ────────────────────────────────────────────────
pyclamd==0.4.0                # ClamAV TCP daemon client (Zeek file-extraction pipeline)

# ── Development & testing (not needed at runtime) ───────────────────────────
pytest==7.4.3
pytest-asyncio==0.21.1
```

## Docker image base

```dockerfile
FROM python:3.12-slim

# System packages needed by Scapy, Nmap, and net tools
RUN apt-get update && apt-get install -y \
    nmap \
    libpcap-dev \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
CMD ["gunicorn", "--worker-class", "gthread", "--threads", "4",
     "--workers", "1", "--bind", "0.0.0.0:5000", "sentinel.api.app:create_app()"]
```

> **Note**: `network_mode: host` and `cap_add: [NET_RAW, NET_ADMIN]` are set in
> `docker-compose.yml`, not in the Dockerfile.

## Why these specific packages

| Package | Chosen over | Reason |
|---------|-------------|--------|
| `httpx` | `requests` | Native async support; pairs with `tenacity` retry |
| `sqlalchemy 2.0` | raw `asyncpg` | ORM + async in one; Alembic migration support |
| `flask-socketio` | `websockets` lib | Integrates directly with Flask; Socket.IO protocol handles reconnection |
| `apscheduler` | `celery` | No broker needed for a single-machine deployment |
| `scapy` | raw `libpcap` bindings | Pythonic API; ARP crafting + sniffing in the same library |
| `pyod` (LOF) | `sklearn` only | Better accuracy on small per-device datasets |
| stdlib `logging` | `structlog` / `python-json-logger` | A structured-JSON logger was originally planned but never adopted — plain `logging.basicConfig` (see `sentinel/api/app.py:_configure_logging`) has been sufficient in practice; don't reach for one without an actual log-shipping consumer that needs it |
