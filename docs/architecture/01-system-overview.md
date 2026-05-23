# System Overview

## Purpose

Heimdall is a self-hosted home network security monitor. It runs as a Docker
Compose stack on a dedicated machine connected to the home LAN. It monitors all
connected devices, detects threats and anomalous behaviour, and presents a
real-time React dashboard with push-notification alerting.

## Why Python

The backend is written in Python for three reasons:

1. **ML ecosystem** — scikit-learn, PyOD, and River have no Java equivalent.
   Per-device IsolationForest anomaly detection is 10 lines in Python; it would
   require implementing the algorithm from scratch in Java.

2. **Packet analysis** — Scapy is the de-facto standard for ARP spoofing
   detection and passive OS fingerprinting. There is no Java equivalent.

3. **Threat intelligence SDKs** — AlienVault OTX, PyMISP, and python-stix2 are
   Python-first. Using them in Java requires raw HTTP calls with no schema support.

## Component map

| Component | Technology | Responsibility |
|-----------|-----------|----------------|
| Router Adapter | Python abstract base + httpx | XMO API client; auth, poll, normalise |
| Core Application | Flask 3 + Flask-SocketIO | REST API, WebSocket push, auth |
| Detection Pipeline | Python detector chain | Threat detection, rule evaluation |
| ML Engine | scikit-learn + PyOD | Per-device anomaly baseline + scoring |
| Security Services | Scapy, python-nmap, OTX SDK | Packet probing, scanning, threat intel |
| Data Layer | SQLAlchemy async + TimescaleDB | Device registry, time-series traffic |
| Message Bus | Redis Pub/Sub | Decouples adapter from pipeline |
| Task Scheduler | APScheduler | Poll cycles, ML retraining, feed refreshes |
| Frontend | React 19 + Vite | Dashboard, alerts, rule editor |

## Data flow

```
1.  APScheduler fires every 15 s
        └─> SagemcomXmoAdapter.poll()

2.  Adapter calls XMO API (httpx async POST /cgi/json-req)
        └─> normalises response to DeviceSnapshot + TrafficSample + PortStats

3.  Canonical events published to Redis  sentinel:events

4.  DetectionPipeline consumes events
        └─> runs all enabled detectors in sequence
        └─> ML Engine scores each TrafficSample (IsolationForest + LOF)

5.  Alerts written to PostgreSQL
        └─> emitted via Flask-SocketIO to React dashboard

6.  REST API serves device list, alert history, rules to React

7.  Block commands:  React -> Flask API -> Redis -> Adapter -> XMO Firewall API
```

## Physical deployment

The monitoring machine must be on the same LAN subnet as the router
(`10.100.102.0/24`). The `sentinel-backend` container runs with
`network_mode: host` so it can:

- Reach the router admin interface at `http://10.100.102.1/cgi/json-req`
- Sniff ARP packets on the LAN interface (requires `NET_RAW` capability)

The React frontend is served by Nginx on port 3000. The Flask API listens on
port 5000 (localhost only — proxied by Nginx).

## Security posture of the monitor itself

- All secrets in Docker secrets (`/run/secrets/` files) — never env vars
- Flask API bound to `127.0.0.1` — Nginx handles external access
- JWT authentication (15-minute access tokens) on all mutation endpoints
- `NET_RAW` capability granted only to `sentinel-backend`
- Router admin password never stored in the database or logged

## Replacing the router

The entire router integration is isolated behind the `RouterAdapter` abstract
base class in `sentinel/adapter/base.py`. Swapping routers means:

1. Create a new class that subclasses `RouterAdapter`
2. Implement `get_connected_devices()`, `get_traffic_samples()`,
   `get_port_stats()`, `block_device()`, `unblock_device()`, `get_router_info()`
3. Register it in `sentinel/adapter/__init__.py`
4. Change `ROUTER_ADAPTER=sagemcom` in `.env`

Nothing else changes.
