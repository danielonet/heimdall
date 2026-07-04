# Heimdall 🛡️

**Home Network Sentinel** — a self-hosted network security monitor with ML anomaly detection.

Heimdall connects to your home router via its native API, monitors every connected device in real time, detects threats and anomalous behaviour using machine learning, and alerts you through a live dashboard and push notifications.

---

## What it does

- **Sees every device** on your LAN — MAC, IP, hostname, vendor, signal strength, traffic
- **Per-device ML anomaly detection** — learns each device's normal behaviour and alerts on deviations
- **Threat intelligence** — cross-references IPs and domains against AbuseIPDB, URLhaus, Feodo Tracker, Tor exits, and AlienVault OTX
- **ARP spoof detection** — catches man-in-the-middle attacks in real time using Scapy
- **DNS monitoring** — Pi-hole integration for per-device DNS query logging and malware domain blocking
- **Network IDS** — Suricata with Emerging Threats ruleset running as a sidecar
- **Honeypot** — OpenCanary fake device alerts on any unexpected connection
- **Device blocking** — issue firewall rules from the dashboard to block any device instantly
- **Port topology** — monitors physical LAN ports, alerts on unexpected wired connections

## Stack

- **Backend**: Python 3.12 · Flask · Flask-SocketIO · APScheduler
- **ML**: scikit-learn · PyOD
- **Database**: PostgreSQL 16 + TimescaleDB
- **Frontend**: React 19 + Vite
- **Infrastructure**: Docker Compose

## Supported routers

| Router | Status |
|--------|--------|
| Sagemcom F@st 5670 | ✅ Fully implemented (XMO API) |
| OpenWrt | 🔜 Planned (ubus API) |
| pfSense / OPNsense | 🔜 Planned |

Adding a new router requires implementing one Python abstract class: `RouterAdapter`.

## Quick start

```bash
git clone https://gitlab.com/yourname/heimdall.git
cd heimdall
cp .env.example .env           # fill in router IP, credentials
mkdir -p secrets
echo "admin_password" > secrets/router_password.txt
echo "your_jwt_secret" > secrets/jwt_secret.txt
docker compose up -d
```

Dashboard: `http://localhost:3000`
API docs: `http://localhost:5000/api/docs`

## Offline Development

When your router is unavailable, use **mock mode** to test Heimdall offline:

```bash
# Enable the mock adapter (synthetic test data)
USE_MOCK_ROUTER=true docker compose up -d

# Dashboard works normally with synthetic traffic
```

See [`docs/architecture/10-mock-router.md`](docs/architecture/10-mock-router.md) for details.

## Documentation

Full architecture and design documents are in [`docs/`](docs/).
Start with [`docs/architecture/01-system-overview.md`](docs/architecture/01-system-overview.md).

## License

MIT
