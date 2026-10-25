#!/usr/bin/env bash
# Shared helpers sourced by install.sh and run.sh

# ── Colours ──────────────────────────────────────────────────────────────────
if [ -t 1 ] && command -v tput &>/dev/null && tput colors &>/dev/null; then
    RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4); CYAN=$(tput setaf 6); BOLD=$(tput bold); NC=$(tput sgr0)
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

# ── Logging ───────────────────────────────────────────────────────────────────
log_info()    { echo "${BLUE}▸${NC} $*"; }
log_success() { echo "${GREEN}✔${NC} $*"; }
log_warn()    { echo "${YELLOW}⚠${NC} $*"; }
log_error()   { echo "${RED}✖${NC} $*" >&2; }
log_section() { echo ""; echo "${BOLD}${CYAN}══ $* ══${NC}"; }
log_skip()    { echo "${YELLOW}↷${NC} $* (already done, skipping)"; }

# ── Command / package checks ─────────────────────────────────────────────────

# Returns 0 if the given command exists on PATH
have() { command -v "$1" &>/dev/null; }

# Returns 0 if the apt package is installed
apt_installed() { dpkg -s "$1" &>/dev/null 2>&1; }

# Returns 0 if the pip package is importable
pip_installed() { python3 -c "import $1" &>/dev/null 2>&1; }

# ── Wait helpers ──────────────────────────────────────────────────────────────

# wait_for_port HOST PORT [TIMEOUT_SECS]
wait_for_port() {
    local host="$1" port="$2" timeout="${3:-60}"
    local elapsed=0
    log_info "Waiting for ${host}:${port}..."
    until nc -z "$host" "$port" 2>/dev/null; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -ge "$timeout" ]; then
            log_error "Timed out waiting for ${host}:${port} after ${timeout}s"
            return 1
        fi
    done
    log_success "${host}:${port} is reachable"
}

# wait_for_postgres DB_PASS [TIMEOUT_SECS]
wait_for_postgres() {
    local db_pass="$1" timeout="${2:-90}"
    local elapsed=0
    log_info "Waiting for PostgreSQL to accept connections..."
    until PGPASSWORD="$db_pass" psql -h localhost -U sentinel -d sentinel \
          -c "SELECT 1" &>/dev/null 2>&1; do
        sleep 2
        elapsed=$((elapsed + 2))
        if [ "$elapsed" -ge "$timeout" ]; then
            log_error "Timed out waiting for PostgreSQL after ${timeout}s"
            return 1
        fi
    done
    log_success "PostgreSQL is ready"
}

# wait_for_redis [TIMEOUT_SECS]
wait_for_redis() {
    local timeout="${1:-30}"
    local elapsed=0
    log_info "Waiting for Redis..."
    until redis-cli -h localhost ping &>/dev/null 2>&1 || \
          nc -z localhost 6379 2>/dev/null; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -ge "$timeout" ]; then
            log_error "Timed out waiting for Redis after ${timeout}s"
            return 1
        fi
    done
    log_success "Redis is ready"
}

# ── Docker helpers ────────────────────────────────────────────────────────────

# Returns 0 if the Docker daemon is reachable
docker_running() { docker info &>/dev/null 2>&1; }

# Returns 0 if the named container is running
container_running() { docker ps --format '{{.Names}}' | grep -q "^$1$"; }

# Detect docker compose command (plugin vs standalone)
docker_compose() {
    if docker compose version &>/dev/null 2>&1; then
        docker compose "$@"
    elif have docker-compose; then
        docker-compose "$@"
    else
        log_error "Neither 'docker compose' plugin nor 'docker-compose' found"
        return 1
    fi
}

# compose_up SERVICE...  →  `docker compose up -d`, but a host port that is
# already taken (e.g. a native postgres/redis, or a leftover container) only
# produces a warning instead of aborting the script. Any other failure still
# returns non-zero.
compose_up() {
    local output rc=0
    output=$(docker_compose up -d "$@" 2>&1) || rc=$?
    [ -n "$output" ] && echo "$output"
    if [ "$rc" -eq 0 ]; then
        return 0
    fi
    if echo "$output" | grep -qiE "port is already allocated|address already in use"; then
        log_warn "Port already in use while starting: $* — continuing (assuming the port is served by an existing service)"
        return 0
    fi
    return "$rc"
}

# ── Secrets helpers ───────────────────────────────────────────────────────────

# read_secret FILE_PATH  →  prints the secret value, or empty string
read_secret() {
    local path="$1"
    [ -f "$path" ] && cat "$path" | tr -d '[:space:]' || echo ""
}

# ensure_secret FILE_PATH VALUE  →  creates the file with VALUE if it doesn't exist
ensure_secret() {
    local path="$1" value="$2"
    if [ -f "$path" ]; then
        log_skip "Secret $(basename "$path")"
    else
        echo "$value" > "$path"
        chmod 600 "$path"
        log_success "Created secret $(basename "$path")"
    fi
}
