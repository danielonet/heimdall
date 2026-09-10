# Heimdall 🛡️

**Home Network Sentinel** — a self-hosted, containerised network security monitor for your home LAN, with real-time detection, per-device ML anomaly detection, and an automated response tier from a live dashboard.

Heimdall connects to your router via its native API, watches every connected device, cross-references live traffic against passive/active detectors and threat-intel feeds, and lets you respond — block, quarantine, or just get notified — from a live dashboard, ntfy push, or email.

---

## Defenses & Capabilities

### Real-time passive detection

Runs continuously via packet sniffing (Scapy) and the router's own polled state — no active probing, so nothing here alerts the device being watched.

| Detector | What it catches |
|---|---|
| **ARP Watch** | A known IP suddenly presenting a different MAC — the signature of ARP spoofing / MITM |
| **Rogue DHCP Watch** | A DHCP OFFER from a source that isn't the known router — a rogue/malicious DHCP server on the LAN |
| **Passive OS Fingerprinting** | Guesses each device's OS from raw TCP SYN characteristics (no active scan) and flags when a known device's fingerprint suddenly changes |
| **Traffic Anomaly (ML)** | Per-device `IsolationForest` + `LOF` models, trained on that device's own history, flag statistically outlier traffic volume |
| **High Upload-Ratio Detection** | Flags a sustained high upload/download ratio — a possible exfiltration signature — with device-type-aware thresholds (a NAS/camera is expected to sustain a higher ratio than a phone) |
| **Signal-Strength Anomaly** | A WiFi device's RSSI shifting and holding at a new level — a possible sign of a MAC-cloned device swap |
| **Hostname/Vendor Mismatch** | A hostname implying a different hardware vendor than the device's actual MAC OUI |
| **AP Trust-Boundary Crossing** | A device moving between the guest and private WiFi networks — CRITICAL if it gains private access it didn't have before |

### Active investigation

| Feature | What it does |
|---|---|
| **Nightly Nmap Scan** | Active OS detection, service enumeration, newly-opened high-risk ports (Telnet/SMB/RDP/VNC/Metasploit-default-handler and more), `--script vuln` CVE findings, and default/blank-credential NSE scripts (`default-accounts`, `ftp-anon`, `mongodb-info`, `mysql-empty-password`, …) against every known device |
| **Active/Passive OS Cross-Check** | Flags when the nightly active scan's OS detection disagrees with the passively-fingerprinted OS on file — a possible spoofing/misclassification signal |

### Deep traffic inspection (Zeek)

| Feature | What it does |
|---|---|
| **DNS Visibility** | Logs every cleartext DNS query on the wire and raises a critical alert when one resolves a domain on the URLhaus malicious-domain feed |
| **C2 Beaconing Detection** | Flags a device making suspiciously regular-interval connections to the same remote host — a classic command-and-control beacon signature invisible to any single-connection check |
| **File-Extraction → ClamAV** | Extracts files from observed cleartext downloads and scans them with ClamAV, alerting on any signature match |

### Network IDS (Suricata)

A signature-based IDS, running as a sidecar and tailed into Heimdall's own alert feed — a different detection style from the mostly-behavioral detectors above, matching live traffic against a maintained rule set (Emerging Threats) for known-bad patterns: exploit signatures, malware C2 traffic, protocol anomalies, scan patterns. Raises an `IDS_SIGNATURE_MATCH` alert per match, severity mapped from the triggering rule's own priority. **Runs with whatever ruleset the container pulls on first boot** — this integration ingests alerts, it doesn't manage or tune the ruleset itself, so a stock Emerging Threats Open set (tuned for enterprise/ISP traffic) may need suppression tuning to stop being noisy on ordinary home traffic.

### Threat intelligence

Nightly-refreshed IP/domain reputation feeds — **Feodo Tracker** (botnet C2 IPs), **Tor exit nodes**, **Spamhaus DROP** (hijacked/spam netblocks), and **URLhaus** (malware-hosting domains) — plus on-demand IP lookups via **AlienVault OTX**.

### Honeypot

**OpenCanary** exposes fake vulnerable services (FTP, Telnet, SSH, HTTP, …) on the network — any interaction at all is inherently suspicious, so every trap trip is a critical alert naming the attacker's source IP.

### Response tiers

| Tier | Effect |
|---|---|
| **Block** | Removes a device from the network entirely, via the router's own device-management mechanism — effective against both WAN and purely-local LAN traffic (e.g. ARP spoofing) |
| **Quarantine** | A softer tier: cuts WAN/internet access via a router firewall rule while leaving the device reachable on the LAN — for a suspect-but-unconfirmed device you don't want to fully cut off yet |
| **Time-limited auto-block** | An automatic block (never a manual one) expires after a configurable window and sends a review notification, instead of staying blocked forever on a possible false positive |
| **Cross-alert correlation** | Recognizes specific alert *pairs* on the same device in a short window (e.g. a brand-new device immediately spoofing, or a known exposure followed by real compromise signs) and escalates them into one higher-severity incident instead of leaving them as two isolated rows |

All response actions are manual by default and can be armed to fire automatically (`auto_block_on_threat`) from the Settings page.

### Visibility

- Full device inventory — MAC, IP, hostname, vendor, device type, signal strength/rate, traffic, which WiFi access point it's on (with a "GROUP BY AP" view)
- Household WAN bandwidth tracking with spike detection
- WiFi radio channel/power/standard visibility per band
- Physical wired port topology (PHY1–PHY5), including the router's per-port byte counters
- Live dashboard over WebSocket (Flask-SocketIO) — device joins/leaves, alerts, and traffic updates push instantly, no polling

### Notifications & reporting

- Push (ntfy.sh) and email (SMTP) channels, configurable from the Settings page
- Daily security digest — a summary of alert counts by severity/type since the last digest, including a calm "all clear" message on a quiet day
- CSV alert export for audit trails / incident record-keeping
- Prometheus-style `/api/metrics` endpoint (device counts, alert rates, poll latency) for pointing an existing Grafana/Prometheus home-lab setup at Heimdall

### Known, documented limits

Being upfront about what Heimdall does **not** do, rather than leaving it to be discovered:

- **Rogue AP / "evil twin" detection** is not implemented — it needs a dedicated 802.11 monitor-mode WiFi radio, which this architecture doesn't provision.
- **Active port-scan detection** (someone scanning *you*) has no dedicated signature — Heimdall's own nightly scan runs *outward* against devices it already knows, it doesn't detect incoming scans.
- **DNS-over-HTTPS/TLS** traffic bypasses DNS visibility (only cleartext UDP/53 is inspected), and **TLS-encrypted downloads** bypass the ClamAV file-extraction pipeline (no TLS interception is configured).
- **Suricata's ruleset is unmanaged by Heimdall** — this integration ingests whatever alerts the container produces, it doesn't fetch, verify, or tune the rule set itself (see the Network IDS section above).

See [`docs/testing/heimdall_verification.md`](docs/testing/heimdall_verification.md) for a full Kali-Linux-based penetration test plan covering every capability above (and every documented gap).

---

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12 · Flask 3 · Flask-SocketIO · APScheduler |
| ML | scikit-learn (`IsolationForest`) · PyOD (`LOF`) |
| Database | PostgreSQL 16 + TimescaleDB |
| Cache / event bus | Redis 7 (Pub/Sub) |
| Frontend | React 19 · Vite · Tailwind CSS |
| Network analysis | Scapy · python-nmap · Zeek · ClamAV · OpenCanary · Suricata |
| Containers | Docker Compose |

## Supported routers

| Router | Status |
|---|---|
| Sagemcom F@st 5670 | ✅ Fully implemented (proprietary XMO JSON API) |
| Anything else | ❌ Not yet — add a router by implementing one Python abstract class, `RouterAdapter` (`sentinel/adapter/base.py`) |

---

## Installation

Requires a Linux host with Docker, on the same LAN as the router it will monitor (several containers run with `network_mode: host` to sniff ARP/DHCP/DNS traffic directly).

Installing on a dedicated home lab box at a fixed internal IP, pulling
pre-built images instead of building from source? See
[`docs/homelab-deployment.md`](docs/homelab-deployment.md) for that specific
walkthrough — the general steps below still apply, this just sequences them
for that setup.

### 1. Choose an installation tier and run the installer

| Tier | Containers beyond core (Postgres/Redis/backend/frontend) | Installer |
|---|---|---|
| **minimal** | none | `sudo ./scripts/install-minimal.sh` |
| **intermediate** | + OpenCanary (honeypot) | `sudo ./scripts/install-intermediate.sh` |
| **full** | + Zeek, ClamAV, Suricata | `sudo ./scripts/install-full.sh` |

Every tier gets the full passive/active detection set above (ARP/DHCP/
fingerprint watchers, ML anomaly detection, nmap, threat intel) and the
same block/quarantine/auto-block response — none of that needs an extra
container. The tier only decides which of Zeek/ClamAV/OpenCanary/Suricata
actually run. See [`docs/deployment-tiers-plan.md`](docs/deployment-tiers-plan.md).

```bash
git clone <this-repo-url> heimdall
cd heimdall
sudo ./scripts/install-full.sh      # or install-minimal.sh / install-intermediate.sh
```

Each is a thin wrapper around `sudo ./scripts/install.sh --tier=<minimal|intermediate|full>`,
which is idempotent (safe to re-run) and handles: system packages (Docker, nmap, libpcap, Node), Python/Node dependencies, a `secrets/` scaffold with dev placeholders, an `.env` scaffold (including `DEPLOYMENT_TIER`) with safe dev defaults, and only the config directories the chosen tier's containers actually need (`suricata/` for full, `opencanary/` for intermediate/full).

### 2. Fill in real secrets and configuration

```bash
# Router admin password — required, everything else has a safe default
echo "your-router-admin-password" > secrets/router_password.txt

# A real random string, not the installer's placeholder
openssl rand -hex 32 > secrets/jwt_secret.txt

# The password you'll log into the Heimdall dashboard with
echo "choose-a-strong-password" > secrets/admin_password.txt

# Optional — AlienVault OTX threat-intel lookups (free API key)
echo "your-otx-api-key" > secrets/otx_api_key.txt
```

Edit `.env` (copied from `.env.example` by the installer) — at minimum, confirm:
- `SNIFF_IFACE` — the LAN-facing interface the monitoring machine sniffs on (`ip link show` to check)
- `ROUTER_IP` — leave blank to auto-discover from the default gateway, or set explicitly
- `LAN_SUBNET` — **add this line yourself**, it isn't in `.env.example`; Zeek uses it to tell local traffic from remote (`docker-compose.yml` silently defaults to `10.100.102.0/24` if unset, which almost certainly isn't your actual subnet)

### 3. Start the stack

```bash
docker compose up -d                        # minimal
docker compose --profile intermediate up -d # intermediate
docker compose --profile full up -d         # full
```

Use whichever matches the tier you installed — `install.sh` prints the
exact command at the end of step 1.

Dashboard: `http://<host-ip>:3000` — log in with `admin` / the password you put in `secrets/admin_password.txt`.

Notifications (ntfy/SMTP) are configured from the Settings page after first login, not via `.env` — see the **NOTIFICATIONS** section there.

### Offline development (no real router needed)

```bash
USE_MOCK_ROUTER=true docker compose up -d
```

The dashboard runs normally against synthetic device/traffic data generated by `MockSagemcomAdapter`. See [`docs/architecture/10-mock-router.md`](docs/architecture/10-mock-router.md).

---

## Documentation

Full architecture and design documents live in [`docs/`](docs/) — start with
[`docs/architecture/01-system-overview.md`](docs/architecture/01-system-overview.md).
A running log of what's built vs. proposed vs. deliberately out of scope is
kept in [`docs/capability-review.md`](docs/capability-review.md).

## License

MIT
