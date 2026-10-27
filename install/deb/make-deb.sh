#!/usr/bin/env bash
# make-deb.sh — build the heimdall .deb from this checkout.
#
# Output (in ./dist, or $OUT_DIR):
#   heimdall_<version>_all.deb
#   heimdall_all.deb               same file under a stable name (for "latest" links)
#   heimdall_<version>_all.deb.sha256
#   heimdall_all.deb.sha256        verifies heimdall_all.deb
#
# The package ships the install bundle under /opt/heimdall, a `heimdall`
# command, and a systemd unit that is installed but NOT enabled: nothing starts
# until the user runs `sudo heimdall setup` and `sudo heimdall start`.
# Usage: install/deb/make-deb.sh [version]   (v0.1.0, 0.1.0, or omitted for a dev build)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VERSION="${1:-dev}"
OUT_DIR="${OUT_DIR:-${ROOT}/dist}"

# Debian versions start with a digit; '~' sorts a dev build before the release.
DEB_VERSION="${VERSION#v}"
[[ "$DEB_VERSION" =~ ^[0-9] ]] || DEB_VERSION="0.0.0~${DEB_VERSION}"

command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required (apt install dpkg-dev)" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="${STAGE}/pkg"
mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/lib/systemd/system" "$PKG/usr/share/doc/heimdall" "$OUT_DIR"

# Reuse the bundle so the package and the tarball can never differ.
OUT_DIR="${STAGE}/bundle" "${ROOT}/install/make-bundle.sh" "$VERSION" >/dev/null
mkdir -p "$PKG/opt"
tar -xzf "${STAGE}/bundle/heimdall-bundle.tar.gz" -C "$PKG/opt"
# The bundle's own README tells people to run ./setup.sh; the package has a command for that.
cat > "$PKG/opt/heimdall/README.txt" <<TXT
Heimdall ${VERSION} — installed by the heimdall package.

  sudo heimdall setup      generate secrets and .env
  sudo heimdall start      pull images, start now and at boot
  sudo heimdall status | logs | password | upgrade | stop

Dashboard: http://<this-machine>:3000, user "admin".
Docs: https://heimdall.it.com
TXT

install -m 0755 "$HERE/heimdall" "$PKG/usr/bin/heimdall"
install -m 0644 "$HERE/heimdall.service" "$PKG/lib/systemd/system/heimdall.service"
for s in postinst prerm postrm; do install -m 0755 "$HERE/$s" "$PKG/DEBIAN/$s"; done
chmod 0755 "$PKG/opt/heimdall/setup.sh"

install -m 0644 "$ROOT/LICENSE" "$PKG/usr/share/doc/heimdall/copyright"
printf 'heimdall (%s) stable; urgency=medium\n\n  * Release %s. See https://github.com/danielonet/heimdall/releases\n\n -- Daniel Driechlinger <noreply@heimdall.it.com>  %s\n' \
    "$DEB_VERSION" "$VERSION" "$(date -R)" | gzip -9n > "$PKG/usr/share/doc/heimdall/changelog.gz"

# Packages must not be group-writable (the build umask may be 002).
chmod -R go-w "$PKG"
chmod 0755 "$PKG/DEBIAN"
(cd "$PKG" && find opt usr lib -type f -print0 | sort -z | xargs -0 md5sum > DEBIAN/md5sums)
SIZE=$(du -sk --exclude=DEBIAN "$PKG" | cut -f1)

cat > "$PKG/DEBIAN/control" <<CTL
Package: heimdall
Version: ${DEB_VERSION}
Architecture: all
Maintainer: Daniel Driechlinger <noreply@heimdall.it.com>
Installed-Size: ${SIZE}
Depends: docker.io | docker-ce, docker-compose-v2 | docker-compose-plugin, openssl, iproute2, systemd | systemd-sysv
Recommends: ca-certificates
Section: net
Priority: optional
Homepage: https://heimdall.it.com
Description: Home network security monitor (Docker stack)
 Heimdall watches your home network: it finds every device, learns what is
 normal for each one, and alerts on anything that is not. It runs as a Docker
 Compose stack from published images.
 .
 This package installs the stack definition under /opt/heimdall and the
 'heimdall' command. Nothing is started until you run 'sudo heimdall setup'
 and 'sudo heimdall start'.
CTL

DEB="${OUT_DIR}/heimdall_${DEB_VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$PKG" "$DEB" >/dev/null
cp "$DEB" "${OUT_DIR}/heimdall_all.deb"
# Each name gets a checksum file that verifies under that name (sha256sum -c checks the name inside it).
(cd "$OUT_DIR" && sha256sum "heimdall_${DEB_VERSION}_all.deb" > "heimdall_${DEB_VERSION}_all.deb.sha256" \
    && sha256sum heimdall_all.deb > heimdall_all.deb.sha256)
echo "Built ${DEB} (${DEB_VERSION})"
