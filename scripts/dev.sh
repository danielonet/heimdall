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
#   ./scripts/dev.sh --no-auto-block # every detector/rule still raises its
#                                     alert normally — none of them call
#                                     block_device() or flip is_blocked.
#                                     For running the Kali attack-test plan
#                                     safely: confirm every finding fires
#                                     correctly before re-arming auto-block.
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
NO_AUTO_BLOCK=false
for arg in "$@"; do
    case "$arg" in
        --no-backend)   NO_BACKEND=true   ;;
        --no-frontend)  NO_FRONTEND=true  ;;
        --no-auto-block) NO_AUTO_BLOCK=true ;;
        --help|-h)
            echo "Usage: $0 [--no-backend] [--no-frontend] [--no-auto-block]"
            echo "  --no-backend     Skip the Python backend (attach VS Code debugger instead)"
            echo "  --no-frontend    Skip the React frontend"
            echo "  --no-auto-block  Disable every auto-block code path (detectors, rules,"
            echo "                   identity-link propagation, enforcement reconciliation) —"
            echo "                   they still raise their alert exactly as normal, just never"
            echo "                   call block_device() or flip is_blocked. Use while running"
            echo "                   an attack-simulation test plan (e.g. from a Kali box) so"
            echo "                   findings can be confirmed without devices actually getting"
            echo "                   cut off mid-test. Only re-run without this flag once every"
            echo "                   finding the test plan expects has been verified."
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

# --no-auto-block always wins over whatever .env sets, regardless of
# argument/file order — exported after sourcing .env above, not before.
if $NO_AUTO_BLOCK; then
    export DISABLE_AUTO_BLOCK=true
fi

log_success "Config loaded"

if [ "${DISABLE_AUTO_BLOCK:-}" = "true" ]; then
    echo ""
    echo "  ${YELLOW}${BOLD}⚠ AUTO-BLOCK DISABLED${NC}${YELLOW} — every detector/rule still raises its alert"
    echo "  normally, but none of them will call block_device() or mark a device blocked."
    echo "  Safe to run the attack-test plan now. Re-arm by starting without --no-auto-block"
    echo "  once every expected finding has been confirmed.${NC}"
    echo ""
fi

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
BACKEND_PORT=5000
FRONTEND_PORT=5173
LOG_DIR="${REPO_ROOT}/.logs"
mkdir -p "$LOG_DIR"

# _stop_pid_tree PID NAME — SIGTERM, wait briefly, SIGKILL if still alive.
# Targets the whole process group (negative PID) first, not just PID itself:
# Flask's --debug reloader forks a child worker process that a plain `kill
# $PID` never reaches, which is exactly what used to leave port 5000 held
# open after Ctrl+C. Falls back to a direct-PID kill in case this job never
# actually got its own process group (depends on the shell's job-control
# state) — either way, _free_port below is the actual guarantee.
_stop_pid_tree() {
    local pid="$1" name="$2"
    [ -z "$pid" ] && return
    kill -0 "$pid" 2>/dev/null || return
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
    for _ in $(seq 1 20); do
        kill -0 "$pid" 2>/dev/null || { log_info "Stopped ${name} (pid ${pid})"; return; }
        sleep 0.2
    done
    log_warn "${name} (pid ${pid}) still running after SIGTERM — sending SIGKILL"
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null
}

# _free_port PORT — last-resort guarantee, independent of PID-tracking above:
# whatever is still bound to this port when the script exits gets killed
# directly. Covers the reloader-child case even if the process-group kill
# above didn't reach it, and also a stale process left over from a previous
# crashed run.
_free_port() {
    local port="$1"
    have fuser || return
    if fuser "${port}/tcp" &>/dev/null; then
        log_warn "Port ${port} still in use after shutdown — force-freeing it"
        fuser -k "${port}/tcp" &>/dev/null || true
    fi
}

cleanup() {
    echo ""
    log_section "Shutting Down"
    _stop_pid_tree "$BACKEND_PID"  "backend"
    _stop_pid_tree "$FRONTEND_PID" "frontend"
    _free_port "$BACKEND_PORT"
    _free_port "$FRONTEND_PORT"
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
    echo "             \"--host\", \"127.0.0.1\", \"--port\", \"${BACKEND_PORT}\", \"--no-debugger\"],"
    echo '    "env": {'
    echo "      \"DATABASE_URL\": \"${DATABASE_URL}\","
    echo "      \"REDIS_URL\": \"${REDIS_URL}\","
    echo "      \"ROUTER_PASSWORD_FILE\": \"${ROUTER_PASSWORD_FILE}\","
    echo "      \"JWT_SECRET_FILE\": \"${JWT_SECRET_FILE}\","
    echo "      \"OTX_API_KEY_FILE\": \"${OTX_API_KEY_FILE}\","
    if [ "${DISABLE_AUTO_BLOCK:-}" = "true" ]; then
        echo "      \"ADMIN_PASSWORD_FILE\": \"${ADMIN_PASSWORD_FILE}\","
        echo "      \"DISABLE_AUTO_BLOCK\": \"true\""
    else
        echo "      \"ADMIN_PASSWORD_FILE\": \"${ADMIN_PASSWORD_FILE}\""
    fi
    echo '    }'
    echo '  }'
    echo ""
else
    log_info "Flask backend → http://127.0.0.1:${BACKEND_PORT}"
    log_info "Logs also at  → ${BACKEND_LOG}"
    # Piping the backgrounded command directly (`cmd | tee | sed &`) makes
    # $! capture sed's PID, not Flask's — cleanup() would then be killing
    # the log formatter while the real process (and its reloader child)
    # kept running and holding the port. Process substitution keeps Flask
    # itself as the backgrounded command so $! is the right PID.
    "$PYTHON_BIN" -m flask --app "$FLASK_APP" run \
        --host 127.0.0.1 --port "$BACKEND_PORT" --debug \
        > >(tee "$BACKEND_LOG" | sed "s/^/${GREEN}[BACKEND]${NC} /") 2>&1 &
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
    log_info "Vite dev server → http://localhost:${FRONTEND_PORT}"
    log_info "Logs also at    → ${FRONTEND_LOG}"
    # See the backend block above for why this isn't a plain trailing pipe.
    npm --prefix "$FRONTEND_DIR" run dev \
        > >(tee "$FRONTEND_LOG" | sed "s/^/${CYAN}[FRONTEND]${NC} /") 2>&1 &
    FRONTEND_PID=$!
fi

# ── Status summary ────────────────────────────────────────────────────────────
log_section "Heimdall Running (app tier only — infra managed separately)"
echo ""
if $NO_BACKEND; then
    echo "  ${YELLOW}Backend  ${NC} http://127.0.0.1:${BACKEND_PORT}   ${YELLOW}(start manually in VS Code)${NC}"
else
    echo "  ${GREEN}Backend  ${NC} http://127.0.0.1:${BACKEND_PORT}   (pid ${BACKEND_PID})"
fi
[ -n "$FRONTEND_PID" ] && \
echo "  ${CYAN}Frontend ${NC} http://localhost:${FRONTEND_PORT}    (pid ${FRONTEND_PID})"
if [ "${DISABLE_AUTO_BLOCK:-}" = "true" ]; then
    echo "  ${YELLOW}${BOLD}Auto-block DISABLED${NC}${YELLOW} — alerts only, no device will actually be blocked${NC}"
fi
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
