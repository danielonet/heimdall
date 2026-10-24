#!/usr/bin/env bash
# install.sh — One-time system setup for Heimdall.
#
# Safe to re-run: every step checks whether the resource already exists
# before doing any work.
#
# Usage:
#   chmod +x scripts/install.sh
#   sudo ./scripts/install.sh          # needs sudo for apt + docker group
#
# What it does:
#   1. System packages  (docker, python3, node, nmap, libpcap, etc.)
#   2. Docker Engine    (official install script if not already present)
#   3. Python packages  (pip install -r requirements.txt)     [skipped with --pull]
#   4. Node packages    (npm install in frontend/)             [skipped with --pull]
#   5. Secrets scaffold (creates secrets/ files with dev placeholders — unique per machine)
#   6. .env scaffold    (creates .env with safe dev defaults, incl. DEPLOYMENT_TIER)
#   7. Config dirs      (suricata/, opencanary/ — only the ones this tier needs)
#   8. ML model dir     (host/console dev only)                [skipped with --pull]
#
# Installation tiers (--tier=minimal|intermediate|full, see
# sentinel/deployment_tiers.py and docs/deployment-tiers-plan.md):
#   minimal      core stack only (postgres/redis/backend/frontend)
#   intermediate minimal + OpenCanary
#   full         everything (+ Zeek, ClamAV, Suricata)
# Prefer the thin wrappers for discoverability:
#   sudo ./scripts/install-minimal.sh
#   sudo ./scripts/install-intermediate.sh
#   sudo ./scripts/install-full.sh
#
# --pull: for a new machine that isn't building from source — skips the
# Python/Node toolchain setup entirely and expects `docker compose pull`
# (after setting HEIMDALL_REGISTRY in .env and `docker login`-ing to it) to fetch pre-built images
# published by scripts/build-and-push.sh. Secrets/.env are still scaffolded
# fresh, so every machine still gets its own unique passwords.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/utils.sh
source "${REPO_ROOT}/scripts/lib/utils.sh"

# ── Argument parsing ──────────────────────────────────────────────────────────
TIER=""
PULL_MODE=false
for arg in "$@"; do
    case "$arg" in
        --tier=*) TIER="${arg#--tier=}" ;;
        --pull) PULL_MODE=true ;;
        *) log_error "Unknown argument: $arg (expected --tier=minimal|intermediate|full, --pull)"; exit 1 ;;
    esac
done
if [ -n "$TIER" ]; then
    case "$TIER" in
        minimal|intermediate|full) ;;
        *) log_error "Invalid --tier=$TIER (must be minimal, intermediate, or full)"; exit 1 ;;
    esac
fi

# ── 0. Must run as root (or with sudo) for apt operations ─────────────────────
if [ "$EUID" -ne 0 ]; then
    log_error "install.sh must be run as root: sudo ./scripts/install.sh"
    exit 1
fi

# Preserve the invoking user for non-root operations (docker group, pip, npm)
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# Resolve the tier interactively only once we know the script will actually
# proceed (root check passed) — no point prompting just to fail afterward.
if [ -z "$TIER" ]; then
    if [ -t 0 ]; then
        echo "Which installation tier?"
        echo "  1) minimal       core stack only — no extra containers"
        echo "  2) intermediate  minimal + OpenCanary"
        echo "  3) full          everything (+ Zeek, ClamAV, Suricata)"
        read -rp "Enter 1/2/3 [3]: " _choice
        case "$_choice" in
            1) TIER="minimal" ;;
            2) TIER="intermediate" ;;
            3|"") TIER="full" ;;
            *) log_error "Invalid choice: $_choice"; exit 1 ;;
        esac
    else
        TIER="minimal"
        log_warn "No --tier given and not running interactively — defaulting to 'minimal'"
    fi
fi

log_section "Heimdall Install"
echo "  Repo root : ${REPO_ROOT}"
echo "  Real user : ${REAL_USER}"
echo "  Tier      : ${TIER}"
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────
log_section "System Packages"

APT_PACKAGES=(
    python3
    python3-pip
    python3-venv
    python3-dev
    build-essential
    nmap
    libpcap-dev
    net-tools
    iproute2
    netcat-openbsd      # nc — used by wait_for_port in run.sh
    postgresql-client   # psql — used by wait_for_postgres in run.sh
    redis-tools         # redis-cli — used by wait_for_redis in run.sh
    curl
    git
    jq
    openssl
)

apt_needs_update=false
for pkg in "${APT_PACKAGES[@]}"; do
    if ! apt_installed "$pkg"; then
        apt_needs_update=true
        break
    fi
done

if $apt_needs_update; then
    log_info "Updating apt cache..."
    apt-get update -qq
    for pkg in "${APT_PACKAGES[@]}"; do
        if apt_installed "$pkg"; then
            log_skip "$pkg"
        else
            log_info "Installing $pkg..."
            apt-get install -y -qq "$pkg"
            log_success "Installed $pkg"
        fi
    done
else
    log_skip "All system packages already installed"
fi

# ── 2. Docker Engine ──────────────────────────────────────────────────────────
log_section "Docker Engine"

if have docker && docker --version &>/dev/null 2>&1; then
    log_skip "Docker $(docker --version | awk '{print $3}' | tr -d ',')"
else
    log_info "Installing Docker via official install script..."
    curl -fsSL https://get.docker.com | sh
    log_success "Docker installed"
fi

# docker compose plugin (modern) or standalone docker-compose
if docker compose version &>/dev/null 2>&1; then
    log_skip "docker compose plugin ($(docker compose version --short 2>/dev/null || true))"
elif have docker-compose; then
    log_skip "docker-compose standalone ($(docker-compose --version | awk '{print $3}' | tr -d ','))"
else
    log_info "Installing docker-compose-plugin..."
    apt-get install -y -qq docker-compose-plugin
    log_success "docker-compose-plugin installed"
fi

# Add the real user to the docker group so they can run docker without sudo
if id -nG "$REAL_USER" | grep -qw docker; then
    log_skip "User ${REAL_USER} already in docker group"
else
    log_info "Adding ${REAL_USER} to docker group..."
    usermod -aG docker "$REAL_USER"
    log_warn "Docker group added — ${REAL_USER} must log out and back in (or run: newgrp docker)"
fi

# Start Docker daemon if not running
if ! docker_running; then
    log_info "Starting Docker daemon..."
    systemctl start docker
    systemctl enable docker
    log_success "Docker daemon started"
else
    log_skip "Docker daemon already running"
fi

if $PULL_MODE; then
    log_section "Node.js / Python / Frontend Packages"
    log_skip "Steps 3-5 (--pull mode: images come from the registry, no build toolchain needed)"
else
    # ── 3. Node.js ────────────────────────────────────────────────────────────
    log_section "Node.js"

    if have node && have npm; then
        log_skip "Node.js $(node --version) / npm $(npm --version)"
    else
        log_info "Installing Node.js LTS via NodeSource..."
        curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
        apt-get install -y -qq nodejs
        log_success "Node.js $(node --version) / npm $(npm --version) installed"
    fi

    # ── 4. Python packages ────────────────────────────────────────────────────
    log_section "Python Packages"

    REQUIREMENTS="${REPO_ROOT}/sentinel/requirements.txt"
    STAMP_FILE="${REPO_ROOT}/.install_stamp"
    VENV_DIR="${REPO_ROOT}/.venv"

    # Debian/Ubuntu system Python is externally-managed (PEP 668) — use a venv,
    # which is also where run.sh looks for its interpreter.
    if [ ! -d "$VENV_DIR" ]; then
        log_info "Creating Python virtual environment..."
        sudo -u "$REAL_USER" python3 -m venv "$VENV_DIR"
    fi

    # Reinstall if requirements.txt is newer than the stamp file
    if [ -f "$STAMP_FILE" ] && [ "$REQUIREMENTS" -ot "$STAMP_FILE" ]; then
        log_skip "Python packages (requirements.txt unchanged since last install)"
    else
        log_info "Installing Python packages from requirements.txt..."
        sudo -u "$REAL_USER" "${VENV_DIR}/bin/pip" install -q -r "$REQUIREMENTS"
        touch "$STAMP_FILE"
        log_success "Python packages installed"
    fi

    # ── 5. Node packages (frontend) ───────────────────────────────────────────
    log_section "Frontend Node Packages"

    FRONTEND_DIR="${REPO_ROOT}/frontend"
    if [ ! -f "${FRONTEND_DIR}/package.json" ]; then
        log_warn "frontend/package.json not found — skipping npm install (frontend not scaffolded yet)"
    elif [ -d "${FRONTEND_DIR}/node_modules" ]; then
        # Re-run only if package.json changed since node_modules was last modified
        if [ "${FRONTEND_DIR}/package.json" -ot "${FRONTEND_DIR}/node_modules" ]; then
            log_skip "node_modules (package.json unchanged)"
        else
            log_info "package.json changed — running npm install..."
            sudo -u "$REAL_USER" bash -c "cd '${FRONTEND_DIR}' && npm install --silent"
            log_success "npm install complete"
        fi
    else
        log_info "Running npm install in frontend/..."
        sudo -u "$REAL_USER" bash -c "cd '${FRONTEND_DIR}' && npm install --silent"
        log_success "npm install complete"
    fi
fi

# ── 6. Secrets scaffold ───────────────────────────────────────────────────────
log_section "Secrets"

SECRETS_DIR="${REPO_ROOT}/secrets"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# Generate a random hex string for use as a secret
gen_secret() { openssl rand -hex 32; }

# Router password: placeholder — user must fill this in manually
ensure_secret "${SECRETS_DIR}/router_password.txt" "CHANGE_ME_router_password"
if grep -q "CHANGE_ME" "${SECRETS_DIR}/router_password.txt" 2>/dev/null; then
    log_warn "secrets/router_password.txt contains placeholder — edit it before connecting to router"
fi

# Auto-generated secrets (safe random values)
if [ ! -f "${SECRETS_DIR}/jwt_secret.txt" ]; then
    gen_secret > "${SECRETS_DIR}/jwt_secret.txt"
    chmod 600 "${SECRETS_DIR}/jwt_secret.txt"
    log_success "Generated secrets/jwt_secret.txt"
else
    log_skip "secrets/jwt_secret.txt"
fi

if [ ! -f "${SECRETS_DIR}/db_pass.txt" ]; then
    gen_secret > "${SECRETS_DIR}/db_pass.txt"
    chmod 600 "${SECRETS_DIR}/db_pass.txt"
    log_success "Generated secrets/db_pass.txt"
else
    log_skip "secrets/db_pass.txt"
fi

if [ ! -f "${SECRETS_DIR}/admin_password.txt" ]; then
    gen_secret > "${SECRETS_DIR}/admin_password.txt"
    chmod 600 "${SECRETS_DIR}/admin_password.txt"
    log_success "Generated secrets/admin_password.txt"
    log_warn "Dashboard login is username 'admin' — password is in secrets/admin_password.txt"
else
    log_skip "secrets/admin_password.txt"
fi

if [ ! -f "${SECRETS_DIR}/otx_api_key.txt" ]; then
    ensure_secret "${SECRETS_DIR}/otx_api_key.txt" "CHANGE_ME_otx_api_key"
    log_warn "secrets/otx_api_key.txt contains placeholder — set your AlienVault OTX API key"
else
    log_skip "secrets/otx_api_key.txt"
fi

# SMTP password: optional, blank is a valid final value (unauthenticated/
# local relay) — unlike the placeholders above, an empty file here is a
# real working state, not a "fill this in" prompt. Compose still requires
# the file to exist to mount it as a secret at all.
if [ ! -f "${SECRETS_DIR}/smtp_password.txt" ]; then
    touch "${SECRETS_DIR}/smtp_password.txt"
    chmod 600 "${SECRETS_DIR}/smtp_password.txt"
    log_success "Created empty secrets/smtp_password.txt (set it from the Notifications page, or edit directly, if your SMTP relay needs auth)"
else
    log_skip "secrets/smtp_password.txt"
fi

# MiWiFi password: optional second router, same "blank is a real working
# state" reasoning as smtp_password.txt above — not configuring a Redmi
# router at all is the common case.
if [ ! -f "${SECRETS_DIR}/miwifi_password.txt" ]; then
    touch "${SECRETS_DIR}/miwifi_password.txt"
    chmod 600 "${SECRETS_DIR}/miwifi_password.txt"
    log_success "Created empty secrets/miwifi_password.txt (set it from the Settings page, or edit directly, if you add a second/Redmi router)"
else
    log_skip "secrets/miwifi_password.txt"
fi

chown -R "$REAL_USER:$REAL_USER" "$SECRETS_DIR"

# ── 7. .env scaffold ──────────────────────────────────────────────────────────
log_section ".env File"

ENV_FILE="${REPO_ROOT}/.env"
if [ -f "$ENV_FILE" ]; then
    log_skip ".env already exists"
    if grep -q "^DEPLOYMENT_TIER=" "$ENV_FILE" && ! grep -q "^DEPLOYMENT_TIER=${TIER}$" "$ENV_FILE"; then
        log_warn "Requested tier '${TIER}' doesn't match .env's existing DEPLOYMENT_TIER — edit .env by hand to change tier on an existing install"
    fi
else
    # Read the generated db_pass so DATABASE_URL is fully populated from the start
    _db_pass=$(cat "${SECRETS_DIR}/db_pass.txt" | tr -d '[:space:]')

    cat > "$ENV_FILE" <<EOF
# Heimdall dev environment — DO NOT commit this file
#
# Secrets are read from secrets/*.txt files (via *_FILE env vars in run.sh).
# Only non-sensitive config lives here.

# ── Deployment ────────────────────────────────────────────────────────────────
# minimal | intermediate | full — must match whichever --profile you bring
# the stack up with. See sentinel/deployment_tiers.py.
DEPLOYMENT_TIER=${TIER}

# ── Router ────────────────────────────────────────────────────────────────────
ROUTER_ADAPTER=sagemcom
ROUTER_IP=           # leave blank to auto-discover from default route
ROUTER_PORT=80
ROUTER_USERNAME=home
POLL_INTERVAL_SECONDS=15

# ── Flask ─────────────────────────────────────────────────────────────────────
FLASK_ENV=development
FLASK_DEBUG=1

# ── Database ──────────────────────────────────────────────────────────────────
DB_PASS=${_db_pass}
DATABASE_URL=postgresql+asyncpg://sentinel:${_db_pass}@localhost/sentinel

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_URL=redis://localhost:6379

# ── ML ────────────────────────────────────────────────────────────────────────
ML_MIN_SAMPLES_TO_TRAIN=100
ML_CONTAMINATION=0.05
ML_MODEL_DIR=${REPO_ROOT}/data/models   # host/console dev override of the Docker default (/data/models)

# ── Network ───────────────────────────────────────────────────────────────────
SNIFF_IFACE=eth0     # LAN-facing interface — check with: ip link show

# ── Notifications (optional) ──────────────────────────────────────────────────
NTFY_URL=
SMTP_HOST=
SMTP_FROM=
EOF
    chown "$REAL_USER:$REAL_USER" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    log_success "Created .env with dev defaults (DATABASE_URL populated from db_pass.txt)"
fi

# ── 8. Config dirs required by docker-compose ────────────────────────────────
log_section "Docker Compose Config Dirs"

# Only scaffold config dirs for containers this tier actually starts —
# opencanary.conf/suricata.yaml are meaningless bind mounts for a container
# that's excluded from the compose profile.
CONFIG_DIRS=()
[ "$TIER" = "intermediate" ] || [ "$TIER" = "full" ] && CONFIG_DIRS+=(opencanary)
[ "$TIER" = "full" ] && CONFIG_DIRS+=(suricata)

for dir in "${CONFIG_DIRS[@]:-}"; do
    [ -z "$dir" ] && continue
    if [ -d "${REPO_ROOT}/${dir}" ]; then
        log_skip "${dir}/ directory"
    else
        mkdir -p "${REPO_ROOT}/${dir}"
        chown "$REAL_USER:$REAL_USER" "${REPO_ROOT}/${dir}"
        log_success "Created ${dir}/"
    fi
done

if $PULL_MODE; then
    log_section "ML Model Directory"
    log_skip "data/models/ (--pull mode: only needed for scripts/run.sh's host-console dev mode)"
else
    # ── 9. ML model dir (host/console dev) ────────────────────────────────────
    log_section "ML Model Directory"

    # sentinel/config.py defaults ML_MODEL_DIR to /data/models (the Docker volume
    # mount). run.sh runs the backend directly on the host, where that path
    # doesn't exist and can't be created without root, so provide a repo-local
    # fallback that the .env scaffold above points ML_MODEL_DIR at.
    if [ -d "${REPO_ROOT}/data/models" ]; then
        log_skip "data/models/ directory"
    else
        mkdir -p "${REPO_ROOT}/data/models"
        chown -R "$REAL_USER:$REAL_USER" "${REPO_ROOT}/data"
        log_success "Created data/models/"
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
log_section "Install Complete"
echo ""
echo "  Next steps:"
echo "  1. Edit ${BOLD}secrets/router_password.txt${NC} with your router admin password"
echo "  2. Edit ${BOLD}secrets/otx_api_key.txt${NC} with your AlienVault OTX key (optional)"
echo "  3. Edit ${BOLD}.env${NC} — set SNIFF_IFACE to your LAN interface (ip link show)"
case "$TIER" in
    minimal)      _compose_cmd="docker compose up -d" ;;
    intermediate) _compose_cmd="docker compose --profile intermediate up -d" ;;
    full)         _compose_cmd="docker compose --profile full up -d" ;;
esac
if $PULL_MODE; then
    echo "  4. Log in to the registry: ${BOLD}docker login <your registry>${NC} (and set HEIMDALL_REGISTRY in .env)"
    echo "  5. Pull the published images: ${BOLD}IMAGE_TAG=latest docker compose pull${NC}"
    echo "  6. Start the stack (tier: ${BOLD}${TIER}${NC}): ${BOLD}${_compose_cmd}${NC}"
else
    echo "  4. Dev mode (backend/frontend on host, infra in Docker): ${BOLD}./scripts/run.sh${NC}"
    echo "     Full container deployment (tier: ${BOLD}${TIER}${NC}): ${BOLD}${_compose_cmd}${NC}"
fi
echo ""
echo "  Where to open the dashboard:"
echo "    Container deployment  → ${BOLD}http://<this-host>:3000${NC}"
echo "    Dev mode (run.sh)     → ${BOLD}http://localhost:5173${NC}  (FRONTEND_HOST=0.0.0.0 ./scripts/run.sh to reach it from another machine)"
echo "  This installer only prepares the host — nothing is listening until you start the stack."
echo ""
if id -nG "$REAL_USER" | grep -qw docker; then
    true
else
    log_warn "Remember: log out and back in (or run 'newgrp docker') for docker group to take effect"
fi
