#!/usr/bin/env bash
# run.sh — Start Heimdall in dev mode.
#
# Infrastructure (Postgres, Redis, ClamAV, and optionally the rest) runs
# in Docker. The Python backend and React frontend run in this console so
# you can see logs, set breakpoints, and restart quickly.
#
# Usage:
#   ./scripts/run.sh              # core infra + backend + frontend
#   ./scripts/run.sh --no-backend # infra + frontend only; attach VS Code debugger to backend
#   ./scripts/run.sh --full       # all Docker services including pihole, suricata, etc.
#   ./scripts/run.sh --stop       # stop all Docker infra services and exit
#
# Prerequisites: run scripts/install.sh once first.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/utils.sh
source "${REPO_ROOT}/scripts/lib/utils.sh"

# ── Parse flags ──────────────────────────────────────────────────────────────
FULL_STACK=false
STOP_ONLY=false
NO_BACKEND=false
for arg in "$@"; do
    case "$arg" in
        --full)       FULL_STACK=true  ;;
        --stop)       STOP_ONLY=true   ;;
        --no-backend) NO_BACKEND=true  ;;
        --help|-h)
            echo "Usage: $0 [--full] [--no-backend] [--stop]"
            echo "  --full        Start all Docker services (pihole, suricata, opencanary, unbound)"
            echo "  --no-backend  Start infra + frontend only; launch the Python backend yourself"
            echo "                (use this when attaching the VS Code debugger)"
            echo "  --stop        Stop all Docker infra services and exit"
            exit 0
            ;;
        *) log_error "Unknown argument: $arg"; exit 1 ;;
    esac
done

# Core services always started in Docker
CORE_SERVICES=(postgres redis clamav)

# Additional services started only with --full
EXTRA_SERVICES=(pihole unbound suricata opencanary)

# ── Stop mode ────────────────────────────────────────────────────────────────
if $STOP_ONLY; then
    log_section "Stopping Docker Services"
    cd "$REPO_ROOT"
    export DB_PASS
    DB_PASS=$(read_secret "${REPO_ROOT}/secrets/db_pass.txt")
    docker_compose stop "${CORE_SERVICES[@]}" "${EXTRA_SERVICES[@]}" 2>/dev/null || true
    log_success "All Docker services stopped"
    exit 0
fi

# ── Pre-flight checks ─────────────────────────────────────────────────────────
log_section "Pre-flight Checks"

# Docker daemon
if ! docker_running; then
    log_error "Docker daemon is not running. Start it with: sudo systemctl start docker"
    exit 1
fi
log_success "Docker daemon is running"

# Secrets
for secret in router_password jwt_secret db_pass; do
    if [ ! -f "${REPO_ROOT}/secrets/${secret}.txt" ]; then
        log_error "Missing secret: secrets/${secret}.txt — run scripts/install.sh first"
        exit 1
    fi
done
log_success "Secrets present"

# .env
if [ ! -f "${REPO_ROOT}/.env" ]; then
    log_error ".env file missing — run scripts/install.sh first"
    exit 1
fi
log_success ".env present"

# Warn if router password is still placeholder
ROUTER_PASS=$(read_secret "${REPO_ROOT}/secrets/router_password.txt")
if [[ "$ROUTER_PASS" == *"CHANGE_ME"* ]]; then
    log_warn "secrets/router_password.txt still has placeholder value — router connection will fail"
fi

# ── Load config ───────────────────────────────────────────────────────────────
log_section "Loading Config"

DB_PASS=$(read_secret "${REPO_ROOT}/secrets/db_pass.txt")
JWT_SECRET_FILE="${REPO_ROOT}/secrets/jwt_secret.txt"
ROUTER_PASSWORD_FILE="${REPO_ROOT}/secrets/router_password.txt"
OTX_API_KEY_FILE="${REPO_ROOT}/secrets/otx_api_key.txt"

# Source .env for non-secret settings (ROUTER_IP, SNIFF_IFACE, etc.)
# shellcheck disable=SC1090
set -o allexport
source "${REPO_ROOT}/.env"
set +o allexport

# Construct DATABASE_URL for the console backend (postgres runs on host network)
export DATABASE_URL="postgresql+asyncpg://sentinel:${DB_PASS}@localhost/sentinel"
export REDIS_URL="redis://localhost:6379"
export ROUTER_PASSWORD_FILE
export JWT_SECRET_FILE
export OTX_API_KEY_FILE
# DB_PASS exported so docker compose can interpolate ${DB_PASS} in compose file
export DB_PASS

log_success "Config loaded"

# ── Start Docker infra ────────────────────────────────────────────────────────
log_section "Starting Docker Infrastructure"

cd "$REPO_ROOT"

if $FULL_STACK; then
    SERVICES_TO_START=("${CORE_SERVICES[@]}" "${EXTRA_SERVICES[@]}")
    log_warn "Full stack mode — pihole needs port 53; disable systemd-resolved if it conflicts"
    log_warn "  sudo systemctl stop systemd-resolved"
else
    SERVICES_TO_START=("${CORE_SERVICES[@]}")
fi

for svc in "${SERVICES_TO_START[@]}"; do
    if container_running "heimdall-1-${svc}-1" || \
       container_running "heimdall_${svc}_1"   || \
       docker_compose ps --status running "$svc" 2>/dev/null | grep -q "$svc"; then
        log_skip "Docker service: $svc (already running)"
    else
        log_info "Starting $svc..."
        docker_compose up -d "$svc"
        log_success "Started $svc"
    fi
done

# ── Wait for core services to be healthy ─────────────────────────────────────
log_section "Waiting for Services"

wait_for_port localhost 5432 90   # postgres
wait_for_port localhost 6379 30   # redis
wait_for_port localhost 3310 60   # clamav

# Deeper postgres check: wait until it accepts SQL connections
if have psql; then
    wait_for_postgres "$DB_PASS" 90
else
    log_warn "psql not found — skipping deep postgres health check (install postgresql-client)"
    sleep 3
fi

# ── Database migrations ───────────────────────────────────────────────────────
log_section "Database Migrations"

ALEMBIC_INI="${REPO_ROOT}/alembic.ini"
if [ ! -f "$ALEMBIC_INI" ]; then
    log_warn "alembic.ini not found — skipping migrations (not yet configured)"
else
    log_info "Running alembic upgrade head..."
    cd "$REPO_ROOT"
    python3 -m alembic upgrade head
    log_success "Migrations applied"
fi

# ── Process tracking ─────────────────────────────────────────────────────────
BACKEND_PID=""
FRONTEND_PID=""
LOG_DIR="${REPO_ROOT}/.logs"
mkdir -p "$LOG_DIR"

cleanup() {
    echo ""
    log_section "Shutting Down"

    [ -n "$BACKEND_PID" ]  && kill "$BACKEND_PID"  2>/dev/null && log_info "Stopped backend  (pid $BACKEND_PID)"
    [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null && log_info "Stopped frontend (pid $FRONTEND_PID)"

    # Stop Docker infra services
    cd "$REPO_ROOT"
    docker_compose stop "${CORE_SERVICES[@]}" 2>/dev/null && log_success "Docker infra stopped"

    exit 0
}
trap cleanup SIGINT SIGTERM

# ── Start Python backend ──────────────────────────────────────────────────────
log_section "Python Backend"

cd "$REPO_ROOT"

BACKEND_LOG="${LOG_DIR}/backend.log"
FLASK_APP="sentinel.api.app:create_app()"

if $NO_BACKEND; then
    log_warn "--no-backend: skipping backend start — launch it from VS Code instead"
    echo ""
    echo "  Add this to your VS Code ${BOLD}.vscode/launch.json${NC}:"
    echo ""
    echo '  {'
    echo '    "name": "Heimdall Backend",'
    echo '    "type": "debugpy",'
    echo '    "request": "launch",'
    echo '    "module": "flask",'
    echo '    "args": ["--app", "sentinel.api.app:create_app()", "run",'
    echo '             "--host", "127.0.0.1", "--port", "5000", "--no-debugger"],'
    echo '    "env": {'
    echo "      \"DATABASE_URL\": \"${DATABASE_URL}\","
    echo "      \"REDIS_URL\": \"${REDIS_URL}\","
    echo "      \"ROUTER_PASSWORD_FILE\": \"${ROUTER_PASSWORD_FILE}\","
    echo "      \"JWT_SECRET_FILE\": \"${JWT_SECRET_FILE}\","
    echo "      \"OTX_API_KEY_FILE\": \"${OTX_API_KEY_FILE}\""
    echo '    }'
    echo '  }'
    echo ""
else
    log_info "Flask backend → http://127.0.0.1:5000"
    log_info "Logs also at  → ${BACKEND_LOG}"

    # Stream with a coloured [BACKEND] prefix so output is identifiable in the console
    python3 -m flask --app "$FLASK_APP" run \
        --host 127.0.0.1 --port 5000 --debug \
        2>&1 | tee "$BACKEND_LOG" | sed "s/^/${GREEN}[BACKEND]${NC} /" &
    BACKEND_PID=$!
fi

# ── Start React frontend ──────────────────────────────────────────────────────
log_section "Starting React Frontend"

FRONTEND_DIR="${REPO_ROOT}/frontend"

if [ ! -f "${FRONTEND_DIR}/package.json" ]; then
    log_warn "frontend/package.json not found — frontend not scaffolded yet, skipping"
    log_warn "Once frontend is created, run:  npm create vite@latest frontend -- --template react-ts"
else
    if [ ! -d "${FRONTEND_DIR}/node_modules" ]; then
        log_warn "node_modules missing — running npm install first..."
        npm --prefix "$FRONTEND_DIR" install --silent
    fi

    FRONTEND_LOG="${LOG_DIR}/frontend.log"
    log_info "Vite dev server → http://localhost:5173"
    log_info "Logs also at    → ${FRONTEND_LOG}"

    npm --prefix "$FRONTEND_DIR" run dev \
        2>&1 | tee "$FRONTEND_LOG" | sed "s/^/${CYAN}[FRONTEND]${NC} /" &
    FRONTEND_PID=$!
fi

# ── Status summary ────────────────────────────────────────────────────────────
log_section "Heimdall Running"
echo ""
if $NO_BACKEND; then
    echo "  ${YELLOW}Backend  ${NC} http://127.0.0.1:5000   ${YELLOW}(start manually in VS Code)${NC}"
else
    echo "  ${GREEN}Backend  ${NC} http://127.0.0.1:5000   (pid ${BACKEND_PID})"
fi
[ -n "$FRONTEND_PID" ] && \
echo "  ${CYAN}Frontend ${NC} http://localhost:5173    (pid ${FRONTEND_PID})"
echo ""
echo "  Docker services : ${SERVICES_TO_START[*]}"
echo "  Logs            : ${LOG_DIR}/"
echo ""
echo "  Press ${BOLD}Ctrl+C${NC} to stop Docker infra and exit"
echo ""

# ── Wait ─────────────────────────────────────────────────────────────────────
if ! $NO_BACKEND; then
    # Normal mode: wait for backend; if it dies unexpectedly, clean up everything
    wait "$BACKEND_PID" 2>/dev/null || true
    log_warn "Backend process exited — shutting down"
elif [ -n "$FRONTEND_PID" ]; then
    # --no-backend with frontend: wait for frontend
    wait "$FRONTEND_PID" 2>/dev/null || true
    log_warn "Frontend process exited — shutting down"
else
    # --no-backend with no frontend: keep infra running until Ctrl+C
    log_info "Infra running. Waiting for Ctrl+C..."
    while true; do sleep 60; done
fi
cleanup
