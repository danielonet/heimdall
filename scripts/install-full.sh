#!/usr/bin/env bash
# install-full.sh — Heimdall FULL tier: everything, including Zeek,
# ClamAV, and Suricata. See docs/deployment-tiers-plan.md.
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh" --tier=full "$@"
