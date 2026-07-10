#!/usr/bin/env bash
# dev.sh — Run the Heimdall app tier (backend + frontend) as console processes.
#
# Unlike run.sh, this script does NOT touch Docker at all. It assumes
# Postgres/Redis (and ClamAV, if you need it) are already reachable —
# started separately via `./scripts/run.sh --stop` … actually via plain
# `docker compose up -d postgres redis clamav`, or a native install of your
# own. This is for iterating on the backend/frontend without the docker
# orchestration in run.sh getting in the way.
#
# Usage:
#   ./scripts/dev.sh                 # backend + frontend
#   ./scripts/dev.sh --no-backend    # frontend only; attach VS Code debugger to backend
#   ./scripts/dev.sh --no-frontend   # backend only
#
# Prerequisites:
#   - scripts/install.sh has been run once
#   - Postgres + Redis are already up and reachable on localhost
#     (e.g. `docker compose up -d postgres redis`)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/utils.sh
source "${REPO_ROOT}/scripts/lib/utils.sh"

VENV_PYTHON="${REPO_ROOT}/.venv/bin/python"
if [ -x "$VENV_PYTHON" ]; then
    PYTHON_BIN="$VENV_PYTHON"
else
    PYTHON_BIN="$(command -v python3 || command -v python)"
fi

# ── Parse flags ──────────────────────────────────────────────────────────────
NO_BACKEND=false
NO_FRONTEND=false
for arg in "$@"; do
    case "$arg" in
        --no-backend)  NO_BACKEND=true  ;;
        --no-frontend) NO_FRONTEND=true ;;
        --help|-h)
            echo "Usage: $0 [--no-backend] [--no-frontend]"
            echo "  --no-backend    Skip the Python backend (attach VS Code debugger instead)"
            echo "  --no-frontend   Skip the React frontend"
            echo ""
            echo "Does not start or stop Docker infra — bring up Postgres/Redis yourself first,"
            echo "e.g.: docker compose up -d postgres redis clamav"
            exit 0
            ;;
        *) log_error "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ── Pre-flight checks ─────────────────────────────────────────────────────────
log_section "Pre-flight Checks"

for secret in router_password jwt_secret db_pass admin_password; do
    if [ ! -f "${REPO_ROOT}/secrets/${secret}.txt" ]; then
        log_error "Missing secret: secrets/${secret}.txt — run scripts/install.sh first"
        exit 1
    fi
done
log_success "Secrets present"

if [ ! -f "${REPO_ROOT}/.env" ]; then
    log_warn ".env file missing — continuing with secrets/defaults"
else
    log_success ".env present"
fi

# ── Load config ───────────────────────────────────────────────────────────────
log_section "Loading Config"

DB_PASS=$(read_secret "${REPO_ROOT}/secrets/db_pass.txt")
JWT_SECRET_FILE="${REPO_ROOT}/secrets/jwt_secret.txt"
ROUTER_PASSWORD_FILE="${REPO_ROOT}/secrets/router_password.txt"
OTX_API_KEY_FILE="${REPO_ROOT}/secrets/otx_api_key.txt"
ADMIN_PASSWORD_FILE="${REPO_ROOT}/secrets/admin_password.txt"

if [ -f "${REPO_ROOT}/.env" ]; then
    # shellcheck disable=SC1090
    set -o allexport
    source "${REPO_ROOT}/.env"
    set +o allexport
fi

export DATABASE_URL="postgresql+asyncpg://sentinel:${DB_PASS}@localhost/sentinel"
export REDIS_URL="redis://localhost:6379"
export ROUTER_PASSWORD_FILE
export JWT_SECRET_FILE
export OTX_API_KEY_FILE
export ADMIN_PASSWORD_FILE

log_success "Config loaded"

# ── Verify infra is already reachable ─────────────────────────────────────────
log_section "Checking Infra"

if ! nc -z localhost 5432 2>/dev/null; then
    log_error "Postgres is not reachable on localhost:5432"
    log_error "Start it first, e.g.: docker compose up -d postgres redis clamav"
    exit 1
fi
log_success "Postgres is reachable"

if ! wait_for_redis 5; then
    log_error "Start it first, e.g.: docker compose up -d postgres redis clamav"
    exit 1
fi

if have psql; then
    wait_for_postgres "$DB_PASS" 30
else
    log_warn "psql not found — skipping deep postgres health check"
fi

# ── Database migrations ───────────────────────────────────────────────────────
log_section "Database Migrations"

ALEMBIC_INI="${REPO_ROOT}/alembic.ini"
if [ ! -f "$ALEMBIC_INI" ]; then
    log_warn "alembic.ini not found — skipping migrations"
else
    log_info "Running alembic upgrade head..."
    cd "$REPO_ROOT"
    "$PYTHON_BIN" -m alembic upgrade head
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
    echo "      \"OTX_API_KEY_FILE\": \"${OTX_API_KEY_FILE}\","
    echo "      \"ADMIN_PASSWORD_FILE\": \"${ADMIN_PASSWORD_FILE}\""
    echo '    }'
    echo '  }'
    echo ""
else
    log_info "Flask backend → http://127.0.0.1:5000"
    log_info "Logs also at  → ${BACKEND_LOG}"
    "$PYTHON_BIN" -m flask --app "$FLASK_APP" run \
        --host 127.0.0.1 --port 5000 --debug \
        2>&1 | tee "$BACKEND_LOG" | sed "s/^/${GREEN}[BACKEND]${NC} /" &
    BACKEND_PID=$!
fi

# ── Start React frontend ──────────────────────────────────────────────────────
log_section "Starting React Frontend"

FRONTEND_DIR="${REPO_ROOT}/frontend"

if $NO_FRONTEND; then
    log_warn "--no-frontend: skipping frontend start"
elif [ ! -f "${FRONTEND_DIR}/package.json" ]; then
    log_warn "frontend/package.json not found — frontend not scaffolded yet, skipping"
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
log_section "Heimdall Running (app tier only — infra managed separately)"
echo ""
if $NO_BACKEND; then
    echo "  ${YELLOW}Backend  ${NC} http://127.0.0.1:5000   ${YELLOW}(start manually in VS Code)${NC}"
else
    echo "  ${GREEN}Backend  ${NC} http://127.0.0.1:5000   (pid ${BACKEND_PID})"
fi
[ -n "$FRONTEND_PID" ] && \
echo "  ${CYAN}Frontend ${NC} http://localhost:5173    (pid ${FRONTEND_PID})"
echo ""
echo "  Logs : ${LOG_DIR}/"
echo ""
echo "  Press ${BOLD}Ctrl+C${NC} to stop (infra keeps running — this script doesn't own it)"
echo ""

# ── Wait ─────────────────────────────────────────────────────────────────────
if [ -n "$BACKEND_PID" ]; then
    wait "$BACKEND_PID" 2>/dev/null || true
    log_warn "Backend process exited — shutting down"
elif [ -n "$FRONTEND_PID" ]; then
    wait "$FRONTEND_PID" 2>/dev/null || true
    log_warn "Frontend process exited — shutting down"
else
    log_info "Nothing to run (both --no-backend and --no-frontend set, or frontend not scaffolded)."
fi
cleanup
