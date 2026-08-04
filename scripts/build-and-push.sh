#!/usr/bin/env bash
# build-and-push.sh — Build sentinel-backend and frontend images and push
# them to GitLab Container Registry, so a new machine can install with
# `docker compose pull` instead of building from source.
#
# Manual/on-demand ONLY — this is deliberately not wired into CI. Run it
# yourself whenever you want to publish a new image version.
#
# Usage:
#   ./scripts/build-and-push.sh              # tags :latest + :<git-short-sha>
#   ./scripts/build-and-push.sh v1.2.0        # also tags :v1.2.0
#
# Prerequisites:
#   docker login registry.gitlab.com
#   (a GitLab Deploy Token or personal access token with `write_registry`
#   scope — never hardcode credentials into this script or docker-compose.yml)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/utils.sh
source "${REPO_ROOT}/scripts/lib/utils.sh"

REGISTRY="registry.gitlab.com/danielonnet-group/heimdall"
IMAGES=(sentinel-backend frontend)
EXTRA_TAG="${1:-}"

log_section "Build & Push"

if ! have docker; then
    log_error "docker not found"
    exit 1
fi

if ! grep -q "\"${REGISTRY%%/*}\"" "${HOME}/.docker/config.json" 2>/dev/null; then
    log_error "Not logged in to ${REGISTRY%%/*} — run: docker login ${REGISTRY%%/*}"
    log_error "(use a GitLab Deploy Token or personal access token with 'write_registry' scope)"
    exit 1
fi

GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
log_info "Tagging with :latest and :${GIT_SHA}$( [ -n "$EXTRA_TAG" ] && echo " and :${EXTRA_TAG}")"

cd "$REPO_ROOT"
for name in "${IMAGES[@]}"; do
    context="./sentinel"
    [ "$name" = "frontend" ] && context="./frontend"

    log_info "Building ${name}..."
    docker build -t "${REGISTRY}/${name}:latest" "$context"
    docker tag "${REGISTRY}/${name}:latest" "${REGISTRY}/${name}:${GIT_SHA}"
    [ -n "$EXTRA_TAG" ] && docker tag "${REGISTRY}/${name}:latest" "${REGISTRY}/${name}:${EXTRA_TAG}"

    log_info "Pushing ${name}..."
    docker push "${REGISTRY}/${name}:latest"
    docker push "${REGISTRY}/${name}:${GIT_SHA}"
    [ -n "$EXTRA_TAG" ] && docker push "${REGISTRY}/${name}:${EXTRA_TAG}"

    log_success "Pushed ${REGISTRY}/${name} (latest, ${GIT_SHA}$( [ -n "$EXTRA_TAG" ] && echo ", ${EXTRA_TAG}"))"
done

log_section "Done"
echo "  On a new machine, pull with: IMAGE_TAG=latest docker compose pull"
echo "  Or pin a specific build:     IMAGE_TAG=${GIT_SHA} docker compose pull"
