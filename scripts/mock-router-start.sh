#!/usr/bin/env bash
# mock-router-start.sh — Quick start for offline dev using the synthetic mock
# router adapter (USE_MOCK_ROUTER=true) — no real router or WireMock needed.
#
# This flips USE_MOCK_ROUTER on in .env, brings up Postgres/Redis in Docker,
# and hands off to dev.sh for the actual backend/frontend processes. See
# dev.sh for what "app tier only" means and its prerequisites.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/utils.sh
source "${REPO_ROOT}/scripts/lib/utils.sh"

cd "$REPO_ROOT"

log_section "Heimdall Mock Router Quick Start"

if [ ! -f secrets/db_pass.txt ] || [ ! -f secrets/router_password.txt ] || [ ! -f secrets/jwt_secret.txt ]; then
    log_error "Secrets missing — run scripts/install.sh first"
    exit 1
fi

if [ ! -f .env ]; then
    log_info "Creating .env from .env.example..."
    cp .env.example .env
fi

if grep -q '^USE_MOCK_ROUTER=' .env; then
    sed -i 's/^USE_MOCK_ROUTER=.*/USE_MOCK_ROUTER=true/' .env
else
    echo 'USE_MOCK_ROUTER=true' >> .env
fi
log_success "USE_MOCK_ROUTER=true in .env"

if ! docker_running; then
    log_error "Docker daemon is not running. Start it with: sudo systemctl start docker"
    exit 1
fi

export DB_PASS
DB_PASS=$(read_secret "${REPO_ROOT}/secrets/db_pass.txt")
log_info "Starting Postgres + Redis..."
docker_compose up -d postgres redis

echo ""
echo "📊 Dashboard:    http://localhost:5173"
echo "🔌 API:          http://localhost:5000"
echo "📚 Docs:         docs/architecture/10-mock-router.md"
echo ""

exec "${REPO_ROOT}/scripts/dev.sh"
