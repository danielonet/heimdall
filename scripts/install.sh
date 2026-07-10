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
#   3. Python packages  (pip install -r requirements.txt)
#   4. Node packages    (npm install in frontend/ when package.json exists)
#   5. Secrets scaffold (creates secrets/ files with dev placeholders)
#   6. .env scaffold    (creates .env with safe dev defaults)
#   7. Config dirs      (suricata/, opencanary/ — required by docker-compose)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/utils.sh
source "${REPO_ROOT}/scripts/lib/utils.sh"

# ── 0. Must run as root (or with sudo) for apt operations ─────────────────────
if [ "$EUID" -ne 0 ]; then
    log_error "install.sh must be run as root: sudo ./scripts/install.sh"
    exit 1
fi

# Preserve the invoking user for non-root operations (docker group, pip, npm)
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

log_section "Heimdall Install"
echo "  Repo root : ${REPO_ROOT}"
echo "  Real user : ${REAL_USER}"
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

# ── 3. Node.js ────────────────────────────────────────────────────────────────
log_section "Node.js"

if have node && have npm; then
    log_skip "Node.js $(node --version) / npm $(npm --version)"
else
    log_info "Installing Node.js LTS via NodeSource..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt-get install -y -qq nodejs
    log_success "Node.js $(node --version) / npm $(npm --version) installed"
fi

# ── 4. Python packages ────────────────────────────────────────────────────────
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

# ── 5. Node packages (frontend) ───────────────────────────────────────────────
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

chown -R "$REAL_USER:$REAL_USER" "$SECRETS_DIR"

# ── 7. .env scaffold ──────────────────────────────────────────────────────────
log_section ".env File"

ENV_FILE="${REPO_ROOT}/.env"
if [ -f "$ENV_FILE" ]; then
    log_skip ".env already exists"
else
    # Read the generated db_pass so DATABASE_URL is fully populated from the start
    _db_pass=$(cat "${SECRETS_DIR}/db_pass.txt" | tr -d '[:space:]')

    cat > "$ENV_FILE" <<EOF
# Heimdall dev environment — DO NOT commit this file
#
# Secrets are read from secrets/*.txt files (via *_FILE env vars in run.sh).
# Only non-sensitive config lives here.

# ── Router ────────────────────────────────────────────────────────────────────
ROUTER_ADAPTER=sagemcom
ROUTER_IP=           # leave blank to auto-discover from default route
ROUTER_PORT=80
ROUTER_USERNAME=admin
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

for dir in suricata opencanary; do
    if [ -d "${REPO_ROOT}/${dir}" ]; then
        log_skip "${dir}/ directory"
    else
        mkdir -p "${REPO_ROOT}/${dir}"
        chown "$REAL_USER:$REAL_USER" "${REPO_ROOT}/${dir}"
        log_success "Created ${dir}/"
    fi
done

# ── Done ──────────────────────────────────────────────────────────────────────
log_section "Install Complete"
echo ""
echo "  Next steps:"
echo "  1. Edit ${BOLD}secrets/router_password.txt${NC} with your router admin password"
echo "  2. Edit ${BOLD}secrets/otx_api_key.txt${NC} with your AlienVault OTX key (optional)"
echo "  3. Edit ${BOLD}.env${NC} — set SNIFF_IFACE to your LAN interface (ip link show)"
echo "  4. Run:  ${BOLD}./scripts/run.sh${NC}"
echo ""
if id -nG "$REAL_USER" | grep -qw docker; then
    true
else
    log_warn "Remember: log out and back in (or run 'newgrp docker') for docker group to take effect"
fi
