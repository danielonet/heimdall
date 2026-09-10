# Home Lab Deployment — Dedicated Machine, Static IP

A step-by-step runbook for installing Heimdall on a **separate, dedicated
machine** on your LAN (not the dev workstation), reachable at a **fixed
internal IP** you set yourself at the OS level. Tier: **intermediate**
(core stack + OpenCanary). Images: **pulled pre-built** from the GitLab
Container Registry rather than built on the target box.

This is the specific path for this setup — see
[`README.md`](../README.md#installation) for the general installer and the
other two tiers/build modes.

## Why this works with a fixed IP at all

Every Heimdall container runs with `network_mode: host` (see
`docker-compose.yml`) — the stack binds directly to the target machine's own
network interfaces rather than through Docker's NAT bridge. That's required
so `ArpWatcher`/OpenCanary/etc. can see real LAN traffic and appear as a real
device on the network — see `docs/architecture/06-security-services.md`. The
practical upshot for this deployment: whatever IP the machine has *is* the
dashboard's IP, with no port-mapping or reverse-proxy layer to configure. A
static IP just makes that address predictable instead of changing on every
DHCP renewal.

**Prerequisite**: the target machine must be physically on the same LAN
segment as the router (`10.100.102.0/24` — see
`docs/router/network-topology.md`), not behind a separate NAT hop or VLAN. If
it's a VM, its network adapter must be in **bridged** mode, not NAT — NAT
mode puts it on a virtual subnet the router (and the rest of the LAN) can't
reach.

---

## 1. Set a static IP on the target machine

**Pick an address outside the router's DHCP pool.** The router's admin UI
(LAN / DHCP settings) shows the actual pool range — check it there before
picking one; the docs in this repo don't record it. `10.100.102.240` is used
below as an example, near the top of the `/24` and past every device
currently listed in `docs/router/network-topology.md`, but verify it's
actually outside the pool and not already leased.

Find the interface name first — `ip link show` (look for the LAN-facing
one, typically `eth0`/`enp*s0` for wired — this box should be wired, not
WiFi, for a stable monitoring position).

**Ubuntu/Debian with netplan** (`/etc/netplan/`, check for the exact
existing filename with `ls /etc/netplan/`):

```yaml
network:
  version: 2
  ethernets:
    eth0:                        # <- replace with your actual interface name
      dhcp4: no
      addresses: [10.100.102.240/24]
      routes:
        - to: default
          via: 10.100.102.1      # the router
      nameservers:
        addresses: [10.100.102.1, 1.1.1.1]
```

```bash
sudo netplan try     # applies with a 120s auto-revert if it breaks connectivity
sudo netplan apply    # once you've confirmed it works
```

**Desktop Ubuntu with NetworkManager** (if `nmcli` is present and netplan's
renderer is NetworkManager — check with `networkctl status` or just try
`nmcli` first on a desktop install):

```bash
nmcli con show                                   # find your connection's name
nmcli con mod "<connection name>" ipv4.method manual
nmcli con mod "<connection name>" ipv4.addresses 10.100.102.240/24
nmcli con mod "<connection name>" ipv4.gateway 10.100.102.1
nmcli con mod "<connection name>" ipv4.dns "10.100.102.1 1.1.1.1"
nmcli con up "<connection name>"
```

**If you're on this over SSH**: keep the current session open in one
terminal and test the new IP from a *second* connection before closing the
first — a typo here loses you remote access to the box, and `netplan try`'s
auto-revert only covers netplan's own health-check, not a wrong address you
deliberately confirmed. Physical/console access as a fallback is worth
having for this step specifically.

Confirm before moving on: `ip addr show` shows the new address, and
`ping 10.100.102.1` (the router) succeeds.

---

## 2. Publish images to the registry

Do this from a machine with the source checked out and Docker installed —
this dev workstation works. **Not yet done on this machine** (no
`registry.gitlab.com/...` image is built locally here and `docker login`
hasn't been run) — needs a one-time GitLab Deploy Token or personal access
token with `write_registry` scope from
`gitlab.com/danielonnet-group/heimdall` → Settings → Repository → Deploy
tokens (or a PAT under your account).

```bash
docker login registry.gitlab.com
./scripts/build-and-push.sh          # tags :latest and :<git-short-sha>
```

Re-run this after any future change you want the home lab box to pick up —
it's manual/on-demand, not wired into CI (see the script's own header
comment).

---

## 3. Get the repo onto the target machine

Even in "pull pre-built images" mode, `docker-compose.yml`, the install
script, and the `secrets/`/config scaffolding still come from the repo
itself — only the backend/frontend *images* are skipped from a local build.

```bash
git clone https://gitlab.com/danielonnet-group/heimdall.git heimdall
cd heimdall
sudo ./scripts/install.sh --tier=intermediate --pull
```

This installs Docker, scaffolds `secrets/*.txt` (placeholders you'll fill
in next) and `.env` (with `DEPLOYMENT_TIER=intermediate`), and creates
`opencanary/` (the one extra config dir intermediate needs) — see the
script's own header comment for the full list. Safe to re-run.

---

## 4. Fill in real secrets

```bash
echo "your-router-admin-password" > secrets/router_password.txt
openssl rand -hex 32 > secrets/jwt_secret.txt
echo "choose-a-strong-dashboard-password" > secrets/admin_password.txt
echo "your-otx-api-key" > secrets/otx_api_key.txt   # optional — AlienVault OTX
```

`db_pass.txt` is already auto-generated by the installer — leave it as-is.

---

## 5. Edit `.env`

```bash
nano .env
```

- `SNIFF_IFACE` — set it to the interface you configured in step 1 (`eth0`,
  or whatever `ip link show` reported on *this* machine — it may differ
  from the dev workstation's interface name).
- `ROUTER_IP` — leave blank to auto-discover from the default route (now
  correctly `10.100.102.1` per step 1's route), or set it explicitly.
- `LAN_SUBNET` — **not needed for intermediate tier.** It's only read by
  Zeek (`docker-compose.yml`), which is a `full`-tier-only container. Add
  `LAN_SUBNET=10.100.102.0/24` later if you ever upgrade this box to `full`.

---

## 6. Pull the images and start the stack

```bash
docker login registry.gitlab.com     # read access is enough here
IMAGE_TAG=latest docker compose pull
docker compose --profile intermediate up -d
```

Check everything came up: `docker compose ps` — `sentinel-backend`,
`frontend`, `postgres`, `redis`, `opencanary` should all show `Up`/`running`.

---

## 7. Verify

- Dashboard: `http://10.100.102.240:3000` (your chosen static IP) — log in
  with `admin` / whatever you put in `secrets/admin_password.txt`.
- From another device on the LAN (phone, laptop), not just the box itself —
  confirms the static IP and host networking are actually reachable
  network-wide, not just on loopback.
- `docker compose logs -f sentinel-backend` — should show it discovering
  the router and starting its poll loop, no repeated connection errors.

Notifications (ntfy/SMTP) are configured from the dashboard's Settings page
after first login, not via `.env`.

---

## Common gotchas

- **Port conflict with an existing dev.sh setup on the same box** — doesn't
  apply here since this is a separate machine, but worth knowing: `dev.sh`'s
  Flask backend and this stack's `sentinel-backend` both bind port 5000 on
  the host (host networking) — never run both on the same machine at once.
- **ufw/firewall on the target box** — if enabled, make sure it allows
  traffic from the LAN subnet to at least port 3000 (dashboard) and 5000
  (API, proxied through 3000 anyway so usually not needed externally).
- **DHCP pool collision** — if the router later hands the chosen static IP
  to a different device via DHCP, you'll get an intermittent IP conflict.
  Re-check the router's DHCP pool bounds if this happens, or shrink the
  pool / add an explicit DHCP reservation exclusion in the router's admin
  UI.
