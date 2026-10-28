#!/usr/bin/env bash
# make-bundle.sh — build heimdall-bundle.tar.gz (+ .sha256) for a GitHub release.
#
# The bundle is what https://heimdall.it.com/install.sh downloads: everything
# needed to run Heimdall from pre-built images, without the source tree.
#
# Usage:
#   ./scripts/make-bundle.sh v0.1.0                       # → dist/
#   ./scripts/make-bundle.sh v0.1.0 ghcr.io/me/heimdall   # custom registry
#
# Run by .github/workflows/release.yml on every v* tag. The images it points
# at (REGISTRY/sentinel-backend and REGISTRY/frontend, tagged with the version
# minus its leading "v") are pushed by the same workflow.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/utils.sh
source "${REPO_ROOT}/scripts/lib/utils.sh"

VERSION="${1:-}"
REGISTRY="${2:-ghcr.io/danielonet/heimdall}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dist}"

if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
    log_error "Usage: make-bundle.sh vX.Y.Z [REGISTRY]  (got: '${VERSION}')"
    exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
B="${STAGE}/heimdall"
mkdir -p "$B"/{opencanary,suricata,zeek}

# Compose file without `build:` lines — the bundle has no source to build
# from, so every service must come from its image.
sed '/^    build: /d' "${REPO_ROOT}/docker-compose.yml" > "$B/docker-compose.yml"

cp "${REPO_ROOT}/packaging/setup.sh"          "$B/setup.sh"
cp "${REPO_ROOT}/.env.example"                "$B/.env.example"
cp "${REPO_ROOT}/LICENSE"                     "$B/LICENSE"
cp "${REPO_ROOT}/opencanary/opencanary.conf"  "$B/opencanary/"
cp "${REPO_ROOT}/suricata/suricata.yaml"      "$B/suricata/"
cp "${REPO_ROOT}/zeek/local.zeek"             "$B/zeek/"
chmod 755 "$B/setup.sh"
echo "$VERSION"  > "$B/VERSION"
echo "$REGISTRY" > "$B/REGISTRY"

mkdir -p "$OUT_DIR"
tar -C "$STAGE" --owner=0 --group=0 -czf "${OUT_DIR}/heimdall-bundle.tar.gz" heimdall
(cd "$OUT_DIR" && sha256sum heimdall-bundle.tar.gz > heimdall-bundle.tar.gz.sha256)

log_success "Built ${OUT_DIR}/heimdall-bundle.tar.gz (${VERSION}, images from ${REGISTRY})"
