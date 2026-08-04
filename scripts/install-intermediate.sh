#!/usr/bin/env bash
# install-intermediate.sh — Heimdall INTERMEDIATE tier: MINIMAL + OpenCanary.
# See docs/deployment-tiers-plan.md.
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh" --tier=intermediate "$@"
