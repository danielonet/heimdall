#!/usr/bin/env bash
# deploy-sftp.sh — make the web root an exact copy of a built site, over SFTP with a key.
#
# Hetzner web hosting offers SFTP (not a shell), so this uses lftp instead of rsync.
#
#   DEPLOY_HOST=… DEPLOY_USER=… DEPLOY_PATH=/public_html website/scripts/deploy-sftp.sh dist
#
# Environment: DEPLOY_HOST, DEPLOY_USER, DEPLOY_PATH (required); DEPLOY_PORT (22);
#   DEPLOY_KEY_FILE (~/.ssh/deploy_key); DEPLOY_KNOWN_HOSTS_FILE (~/.ssh/known_hosts).
# The host key must already be in the known-hosts file: it is checked strictly, never auto-accepted.
# Files that exist only on the server are deleted, except under apt/ (reserved for the package repository)
# and .well-known/ (the host puts certificate-verification files there).
set -euo pipefail

SRC="${1:?usage: deploy-sftp.sh <built-site-dir>}"
: "${DEPLOY_HOST:?}" "${DEPLOY_USER:?}" "${DEPLOY_PATH:?}"
PORT="${DEPLOY_PORT:-22}"
KEY="${DEPLOY_KEY_FILE:-$HOME/.ssh/deploy_key}"
KNOWN="${DEPLOY_KNOWN_HOSTS_FILE:-$HOME/.ssh/known_hosts}"

[ -f "$SRC/index.html" ] || { echo "deploy: $SRC has no index.html: refusing to deploy an empty or wrong directory" >&2; exit 1; }
[ -f "$KEY" ] || { echo "deploy: no key at $KEY" >&2; exit 1; }
[ -s "$KNOWN" ] || { echo "deploy: no known hosts at $KNOWN" >&2; exit 1; }
# --delete on the wrong path would wipe something else; require a real directory below the root.
case "$DEPLOY_PATH" in /?*|[!/]?*) ;; *) echo "deploy: DEPLOY_PATH looks unsafe: '$DEPLOY_PATH'" >&2; exit 1 ;; esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
script="$work/commands.lftp"
# lftp starts one ssh per connection; a wrapper file avoids quoting the options inside lftp's own settings.
ssh_wrapper="$work/ssh"
cat > "$ssh_wrapper" <<WRAP
#!/bin/sh
exec ssh -a -x -i '${KEY}' -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile='${KNOWN}' -o BatchMode=yes "\$@"
WRAP
chmod 700 "$ssh_wrapper"
cat > "$script" <<LFTP
set sftp:connect-program "${ssh_wrapper}"
set net:max-retries 3
set net:timeout 30
set cmd:fail-exit yes
open -u '${DEPLOY_USER},' -p ${PORT} sftp://${DEPLOY_HOST}
mkdir -p -f '${DEPLOY_PATH}'
mirror --reverse --delete --parallel=4 --verbose=1 --exclude-glob apt/ --exclude-glob .well-known/ '${SRC}' '${DEPLOY_PATH}'
bye
LFTP
lftp -f "$script" < /dev/null
