#!/usr/bin/env bash
# install-minimal.sh — Heimdall MINIMAL tier: core stack only
# (postgres/redis/backend/frontend), no extra Docker containers.
# See docs/deployment-tiers-plan.md.
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh" --tier=minimal "$@"
