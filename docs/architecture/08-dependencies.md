# Python Dependencies

Full `requirements.txt` for the `sentinel-backend` container.

## requirements.txt

```
# ── Web framework ──────────────────────────────────────────────────────────
flask>=3.0
flask-socketio>=5.3
flask-jwt-extended>=4.6
flask-cors>=4.0
flask-limiter>=3.5          # rate-limit /api/login
gunicorn>=21.2              # production WSGI server
gevent>=23.9                # async worker for gunicorn + SocketIO

# ── Configuration ──────────────────────────────────────────────────────────
python-dotenv>=1.0
pydantic-settings>=2.0

# ── Async HTTP ────────────────────────────────────────────────────────────
httpx>=0.27
tenacity>=8.2               # retry with exponential back-off

# ── Database ──────────────────────────────────────────────────────────────
sqlalchemy>=2.0
asyncpg>=0.29               # async PostgreSQL driver
alembic>=1.13               # migrations; env.py runs migrations through the
                             # same async engine/driver, no sync driver needed

# ── Cache / message bus ───────────────────────────────────────────────────
redis>=5.0                  # redis.asyncio covers async pub/sub; aioredis is
                             # archived upstream and unusable on Python 3.11+

# ── Machine learning ──────────────────────────────────────────────────────
scikit-learn>=1.4           # IsolationForest
pyod>=1.1                   # LOF, COPOD, ECOD (40+ algorithms)
numpy>=1.26
pandas>=2.1                 # log parsing, feature engineering
joblib>=1.3                 # model persistence
scipy>=1.12                 # entropy calculation (DNS exfil detection)

# ── Network security ──────────────────────────────────────────────────────
scapy>=2.5                  # ARP sniffing, passive OS fingerprinting
python-nmap>=1.6            # Nmap wrapper
pyshark>=0.6                # Wireshark/tshark Python wrapper
netaddr>=0.10               # IP/subnet manipulation
dpkt>=1.9                   # fast PCAP parsing

# ── Threat intelligence ───────────────────────────────────────────────────
OTXv2>=1.5                  # AlienVault Open Threat Exchange SDK
pymisp>=2.4                 # MISP threat sharing (optional)
python-stix2>=3.0           # STIX 2.1 threat intel bundles

# ── Scheduling ────────────────────────────────────────────────────────────
apscheduler>=3.10           # AsyncIOScheduler for all background jobs

# ── Authentication ────────────────────────────────────────────────────────
passlib[bcrypt]>=1.7        # admin password hashing
python-jose>=3.3            # JWT (used by flask-jwt-extended)

# ── TLS / certificate inspection ─────────────────────────────────────────
cryptography>=42.0          # inspect TLS certs on device open ports
pyOpenSSL>=24.0

# ── AV scanning ───────────────────────────────────────────────────────────
pyclamd>=0.4                # ClamAV TCP daemon client

# ── Utilities ─────────────────────────────────────────────────────────────
python-dateutil>=2.9
structlog>=24.1             # structured JSON logging
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
CMD ["gunicorn", "--worker-class", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker",
     "--workers", "1", "--bind", "0.0.0.0:5000", "sentinel.api.app:create_app()"]
```

> **Note**: `network_mode: host` and `cap_add: [NET_RAW, NET_ADMIN]` are set in
> `docker-compose.yml`, not in the Dockerfile.

## Why these specific packages

| Package | Chosen over | Reason |
|---------|-------------|--------|
| `httpx` | `requests` | Native async support; `tenacity` retry |
| `sqlalchemy 2.0` | raw `asyncpg` | ORM + async in one; Alembic migration support |
| `flask-socketio` | `websockets` lib | Integrates directly with Flask; Socket.IO protocol handles reconnection |
| `apscheduler` | `celery` | No broker needed for single-machine deployment |
| `scapy` | `libpcap` bindings | Pythonic API; ARP crafting + sniffing in the same library |
| `pyod LOF` | `sklearn` only | Better accuracy on small per-device datasets |
| `structlog` | `logging` stdlib | JSON-formatted logs — easier to parse and ship to ELK if needed |
