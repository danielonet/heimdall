#!/usr/bin/env bash
# make-bundle.sh — build the end-user install bundle from this checkout.
#
# Output (in ./dist, or $OUT_DIR):
#   heimdall-bundle.tar.gz         compose file + config + setup.sh
#   heimdall-bundle.tar.gz.sha256
#   install.sh                     the bootstrap script, copied unchanged
#
# The bundle's docker-compose.yml is derived from the repo's: `build:` keys
# and the dev-only wiremock service are removed, so it runs from published
# images alone. Usage: install/make-bundle.sh [version]   (default: latest)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-latest}"
OUT_DIR="${OUT_DIR:-${ROOT}/dist}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

DIR="${STAGE}/heimdall"
mkdir -p "$DIR" "$OUT_DIR"

python3 - "${ROOT}/docker-compose.yml" "${DIR}/docker-compose.yml" <<'PY'
import re
import sys

src, dst = sys.argv[1:3]
lines = open(src).read().split('\n')
out, skipping = [], False
for line in lines:
    # Top-level service blocks start at two-space indent; a comment block that
    # introduces wiremock runs up to the next service's own comment/definition.
    if line.startswith('  # WireMock:'):
        skipping = True
    elif skipping and (line.startswith('  # full tier only') or re.match(r'^  [a-z]', line) and not line.startswith('  wiremock')):
        skipping = False
    if skipping:
        continue
    if re.match(r'^    build: ', line):
        continue
    out.append(line)
open(dst, 'w').write('\n'.join(out))
PY

cp "${ROOT}/install/setup.sh" "${DIR}/setup.sh"
cp "${ROOT}/LICENSE" "${DIR}/LICENSE"
mkdir -p "${DIR}/suricata" "${DIR}/opencanary" "${DIR}/zeek"
cp "${ROOT}/suricata/suricata.yaml" "${DIR}/suricata/"
cp "${ROOT}/opencanary/opencanary.conf" "${DIR}/opencanary/"
cp "${ROOT}/zeek/local.zeek" "${DIR}/zeek/"
echo "$VERSION" > "${DIR}/VERSION"
cat > "${DIR}/README.txt" <<TXT
Heimdall ${VERSION} — install bundle

  ./setup.sh                          # asks for the dashboard login; generates secrets and .env for this machine
  docker compose pull && docker compose up -d

Dashboard: http://<this-machine>:3000, signed in with the user name and password you chose at setup
(the password is in secrets/admin_password.txt; the user name is ADMIN_USERNAME in .env).
Docs: https://github.com/danielonet/heimdall   Security policy: SECURITY.md in that repo.
TXT

tar -C "$STAGE" --owner=0 --group=0 -czf "${OUT_DIR}/heimdall-bundle.tar.gz" heimdall
(cd "$OUT_DIR" && sha256sum heimdall-bundle.tar.gz > heimdall-bundle.tar.gz.sha256)
cp "${ROOT}/install/get-heimdall.sh" "${OUT_DIR}/install.sh"
echo "Built ${OUT_DIR}/heimdall-bundle.tar.gz (${VERSION})"
