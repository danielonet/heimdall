#!/usr/bin/env bash
# setup.sh — prepare this directory to run Heimdall from the published images.
#
# Ships inside the install bundle next to docker-compose.yml. It needs no
# sudo and no source checkout: it checks Docker, generates this machine's own
# secrets, detects the LAN interface and subnet, and writes .env. It never
# overwrites an existing secret or .env, so it is safe to re-run.
#
# Usage:  ./setup.sh [--tier=minimal|intermediate|full] [--router=sagemcom|passive] [--iface=eth0] [--subnet=192.168.1.0/24] [--skip-disk-check]
#         ./setup.sh --prune-old-images
#
# The dashboard login is not made here: the first time you open the dashboard it asks you to
# create the admin account, and keeps only a salted hash of the password in its database. No
# password is written to disk by this script. An install that already has a non-empty
# secrets/admin_password.txt keeps logging in with it.
#
# Afterwards:  docker compose pull && docker compose up -d
# (.env sets COMPOSE_PROFILES, so the same command works for every tier.)
#
# --prune-old-images removes the Heimdall images of older versions. Every release has its own image tag, so each
# upgrade would otherwise leave the previous backend and frontend images behind (up to about 1.4 GB per version). The
# one-line installer, 'heimdall upgrade' and the systemd service run it for you once the new version is up. Only
# Heimdall's own two images are touched (never the database, Redis, Suricata or anything else), only tags other
# than the one in use, and never with --force: an image a container still uses stays. To keep older versions,
# put KEEP_OLD_IMAGES=1 in .env.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'; else B=''; G=''; Y=''; R=''; N=''; fi
info() { echo "${B}▸${N} $*"; }
ok()   { echo "${G}✔${N} $*"; }
warn() { echo "${Y}⚠${N} $*" >&2; }
die()  { echo "${R}✖${N} $*" >&2; exit 1; }

# ── Images of older versions ────────────────────────────────────────────────
# Every release has its own image tag (IMAGE_TAG in .env), so an upgrade used to leave the previous version's
# backend and frontend images on the disk. prune_old_images removes them once the new version is pulled and
# running. It is deliberately narrow:
#   - only the two images Heimdall publishes (sentinel-backend and frontend, under HEIMDALL_REGISTRY), and only
#     their tags other than the one in use, plus their untagged leftovers (what remains when a moving tag such as
#     :latest is pulled again). The database, Redis, Suricata and every other image are never touched.
#   - never --force: Docker itself refuses to remove an image a container still uses, and that image stays.
#   - nothing at all unless the version in use is really on this machine, so a failed pull keeps the old images.
#   - it never fails an upgrade: a problem is a warning, and the images are simply left for next time.
keep_old_images() {
    case "${HEIMDALL_KEEP_OLD_IMAGES:-}" in 1|true|yes) return 0 ;; esac
    grep -Eqx 'KEEP_OLD_IMAGES=(1|true|yes)' .env 2>/dev/null
}

in_list() { local needle="$1" item; shift; for item in "$@"; do [ "$item" = "$needle" ] && return 0; done; return 1; }

# remove_image TARGET WHAT: ok/warn line either way; succeeds only if the image was removed.
remove_image() {
    local out
    if out=$(docker image rm "$1" 2>&1); then
        ok "Removed $2"
    else
        warn "Kept $2: ${out%%$'\n'*}"
        return 1
    fi
}

prune_old_images() {
    if keep_old_images; then
        info "Keeping the images of older versions (KEEP_OLD_IMAGES=1)."
        return 0
    fi
    local listing ref repo tag id line digests removed=0 kept=0 i
    local -a current=() current_ids=() repos=()
    listing=$(docker compose config --images 2>/dev/null) \
        || { warn "Could not read the image list from docker-compose.yml: no old images removed."; return 0; }
    while IFS= read -r ref; do
        case "$ref" in */sentinel-backend:*|*/frontend:*) current+=("$ref") ;; esac
    done <<< "$listing"
    if [ "${#current[@]}" -eq 0 ]; then
        warn "Heimdall's own images are not in docker-compose.yml: no old images removed."
        return 0
    fi
    for ref in "${current[@]}"; do
        id=$(docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null) \
            || { warn "$ref is not on this machine yet: keeping the older images."; return 0; }
        current_ids+=("$id")
        repos+=("${ref%:*}")
    done
    for ((i = 0; i < ${#repos[@]}; i++)); do
        repo="${repos[i]}"
        # Other tags of this repository, and copies with no tag (pulled by digest). A tag that points at the image in
        # use under another name is not "old", so it stays.
        while read -r tag id; do
            [ -n "${id:-}" ] || continue
            in_list "$id" "${current_ids[@]}" && continue
            if [ "$tag" = "<none>" ]; then
                if remove_image "$id" "an untagged $repo image"; then removed=$((removed + 1)); else kept=$((kept + 1)); fi
            elif remove_image "$repo:$tag" "$repo:$tag"; then removed=$((removed + 1)); else kept=$((kept + 1)); fi
        done < <(docker image ls --no-trunc --format '{{.Tag}} {{.ID}}' "$repo" 2>/dev/null)
        # Untagged leftovers: pulling a moving tag again moves it to the new image and leaves the old one with no name.
        # Its RepoDigests still say where it came from, which is how it is told apart from anyone else's image.
        while IFS= read -r id; do
            [ -n "$id" ] || continue
            digests=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$id" 2>/dev/null) || continue
            while IFS= read -r line; do
                [[ "$line" == "$repo@"* ]] || continue
                if remove_image "$id" "an untagged $repo image"; then removed=$((removed + 1)); else kept=$((kept + 1)); fi
                break
            done <<< "$digests"
        done < <(docker image ls --filter dangling=true --no-trunc --format '{{.ID}}' 2>/dev/null)
    done
    if [ "$removed" -gt 0 ]; then
        ok "Removed $removed older Heimdall image(s) to save disk space."
    elif [ "$kept" -eq 0 ] && [ -t 1 ]; then
        info "No older Heimdall images to remove."
    fi
    return 0
}

TIER="" IFACE="" SUBNET="" ROUTER="" SKIP_DISK_CHECK="" PRUNE_ONLY=""
for arg in "$@"; do
    case "$arg" in
        --tier=*)   TIER="${arg#--tier=}" ;;
        --router=*) ROUTER="${arg#--router=}" ;;
        --iface=*)  IFACE="${arg#--iface=}" ;;
        --subnet=*) SUBNET="${arg#--subnet=}" ;;
        --skip-disk-check) SKIP_DISK_CHECK=1 ;;
        --prune-old-images) PRUNE_ONLY=1 ;;
        -h|--help)  awk 'NR > 1 { if (/^#/) { sub(/^# ?/, ""); print } else exit }' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "Unknown argument: $arg" ;;
    esac
done
[ -z "$PRUNE_ONLY" ] || [ "$#" -eq 1 ] || die "--prune-old-images does not combine with other options."

[ "$(uname -s)" = "Linux" ] || die "Heimdall must run on Linux: it sniffs the LAN with host networking."
[ -f docker-compose.yml ] || die "docker-compose.yml not found next to setup.sh — run this from the extracted bundle."
command -v docker >/dev/null || die "Docker is not installed. See https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "The 'docker compose' plugin is missing. See https://docs.docker.com/compose/install/linux/"
if [ -n "$PRUNE_ONLY" ]; then
    prune_old_images
    exit 0
fi
command -v openssl >/dev/null || die "openssl is required to generate secrets."

if [ -z "$TIER" ]; then
    if [ -t 0 ]; then
        echo "Which installation tier?"
        echo "  1) minimal       core stack only"
        echo "  2) intermediate  + OpenCanary honeypot"
        echo "  3) full          + Zeek, ClamAV, Suricata (needs ~4 GB RAM)"
        read -rp "Enter 1/2/3 [1]: " choice
        case "${choice:-1}" in 1) TIER=minimal ;; 2) TIER=intermediate ;; 3) TIER=full ;; *) die "Invalid choice: $choice" ;; esac
    else
        TIER=minimal
        warn "No --tier given and not interactive — using 'minimal'"
    fi
fi
case "$TIER" in minimal|intermediate|full) ;; *) die "Invalid --tier=$TIER (minimal, intermediate or full)" ;; esac

if [ -z "$ROUTER" ] && [ -t 0 ] && [ ! -f .env ]; then
    echo "Which router is on your network?"
    echo "  1) Sagemcom F@st (XMO)"
    echo "  2) Another router, or not sure — Heimdall finds devices itself (passive mode)"
    echo "  3) A router from the supported list — I'll pick it in the dashboard"
    read -rp "Enter 1/2/3 [3]: " choice
    case "${choice:-3}" in 1) ROUTER=sagemcom ;; 2) ROUTER=passive ;; 3) ROUTER="" ;; *) die "Invalid choice: $choice" ;; esac
fi
case "$ROUTER" in ""|sagemcom|passive) ;; *) die "Invalid --router=$ROUTER (sagemcom or passive; other routers are chosen in the dashboard)" ;; esac

# ── LAN interface and subnet ────────────────────────────────────────────────
if [ -z "$IFACE" ]; then
    IFACE=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
fi
[ -n "$IFACE" ] || { IFACE=eth0; warn "Could not detect the LAN interface — defaulting to eth0. Edit SNIFF_IFACE in .env (see: ip link show)."; }
case "$IFACE" in wl*) warn "$IFACE is a WiFi interface: sniffing works best from a wired port." ;; esac

if [ -z "$SUBNET" ]; then
    SUBNET=$(ip -4 route show dev "$IFACE" scope link 2>/dev/null | awk '$1 ~ /\// { print $1; exit }')
fi
[ -n "$SUBNET" ] || { SUBNET=192.168.1.0/24; warn "Could not detect the LAN subnet — defaulting to $SUBNET. Edit LAN_SUBNET in .env."; }
info "Tier: $TIER · interface: $IFACE · subnet: $SUBNET"

# ── Disk space ──────────────────────────────────────────────────────────────
# Stop before anything is written or pulled if the images for this tier will not fit. The need is the on-disk
# size of every image of the tier that is not already pulled, plus a reserve for the operating system and the
# database's own growth. Sizes are in MB: backend, frontend, database and Redis were measured; Suricata, ClamAV
# (with its signature database), OpenCanary and Zeek are rounded-up estimates, so treat the total as approximate.
VERSION_TAG=latest
[ -f VERSION ] && VERSION_TAG=$(tr -d '[:space:]' < VERSION)
# Release tags are vX.Y.Z but the published image tags drop the 'v'.
VERSION_TAG="${VERSION_TAG#v}"

RESERVE_MB=1024
image_mb() {
    case "$1" in
        */sentinel-backend:*) echo 1350 ;;
        */frontend:*) echo 100 ;;
        timescale/timescaledb-ha:*) echo 4550 ;;
        redis:*) echo 60 ;;
        *suricata*) echo 450 ;;
        *clamav*) echo 800 ;;
        *opencanary*) echo 1100 ;;
        *zeek*) echo 500 ;;
        *) echo 500 ;;
    esac
}
# MB still to download for a tier: images of that tier that are not on this machine yet.
tier_need_mb() {
    local total=0 img
    while IFS= read -r img; do
        [ -n "$img" ] || continue
        docker image inspect "$img" >/dev/null 2>&1 && continue
        total=$((total + $(image_mb "$img")))
    done < <(IMAGE_TAG="$VERSION_TAG" docker compose --profile "$1" config --images 2>/dev/null)
    echo "$total"
}
gb() { awk -v mb="$1" 'BEGIN { printf "%.1f GB", mb / 1024 }'; }

if [ -z "$SKIP_DISK_CHECK" ]; then
    check_dir=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)
    check_dir=${check_dir:-/var/lib/docker}
    # Images are stored under Docker's data directory; if it cannot be read or does not exist yet, use the nearest parent.
    while [ "$check_dir" != / ] && { [ ! -d "$check_dir" ] || ! df -Pk "$check_dir" >/dev/null 2>&1; }; do check_dir=$(dirname "$check_dir"); done
    free_mb=$(df -Pk "$check_dir" 2>/dev/null | awk 'NR == 2 { print int($4 / 1024) }')
    if [ -z "$free_mb" ]; then
        warn "Could not measure the free disk space on $check_dir — skipping the disk check."
    else
        images_mb=$(tier_need_mb "$TIER")
        need_mb=$((images_mb + RESERVE_MB))
        if [ "$free_mb" -lt "$need_mb" ]; then
            echo "${R}✖${N} Not enough disk space to install the '$TIER' tier." >&2
            echo "    Free on $check_dir:  $(gb "$free_mb")" >&2
            echo "    Needed:  $(gb "$need_mb")  (images $(gb "$images_mb") + $(gb "$RESERVE_MB") reserved for the system and the database)" >&2
            echo "    Short by:  $(gb $((need_mb - free_mb)))" >&2
            if [ "$TIER" != minimal ]; then
                minimal_mb=$(($(tier_need_mb minimal) + RESERVE_MB))
                [ "$free_mb" -lt "$minimal_mb" ] || echo "    The minimal tier needs $(gb "$minimal_mb") and would fit: ./setup.sh --tier=minimal" >&2
            fi
            echo "    Free some space (for example 'docker system prune') or use a larger disk, then run setup again." >&2
            echo "    To install anyway: ./setup.sh --skip-disk-check" >&2
            exit 1
        fi
        ok "Disk space: $(gb "$free_mb") free on $check_dir, this tier needs about $(gb "$need_mb")"
    fi
fi

# ── Secrets ─────────────────────────────────────────────────────────────────
umask 077
mkdir -p secrets secrets/routers
chmod 700 secrets secrets/routers

gen() { [ -f "secrets/$1" ] && { ok "secrets/$1 already exists — kept"; return; }; openssl rand -hex 32 > "secrets/$1"; ok "Generated secrets/$1"; }
blank() { [ -f "secrets/$1" ] && return; : > "secrets/$1"; ok "Created empty secrets/$1 ($2)"; }

gen jwt_secret.txt
gen db_pass.txt
# Empty on a new install: the admin account is created in the browser. A file left by an older install is kept.
blank admin_password.txt "the admin account is created in the dashboard"
# Blank is a valid, working state for all of these; the dashboard writes them
# when you enter a router login, API key or SMTP password. Compose needs the
# files to exist, or Docker creates a directory at the mount path instead.
blank router_password.txt "set from the Equipment tab"
blank miwifi_password.txt "set from the Equipment tab"
blank smtp_password.txt "set from the Notifications tab"
blank telegram_bot_token.txt "set from the Notifications tab"
blank otx_api_key.txt "optional AlienVault OTX key"
blank abusech_auth_key.txt "optional free key from https://auth.abuse.ch/ for the URLhaus feed"

# ── .env ────────────────────────────────────────────────────────────────────
if [ -f .env ]; then
    ok ".env already exists — kept"
    # An .env written before ARM was handled still names the x86-only ClamAV image, which cannot be pulled on ARM.
    case "$(uname -m)" in
        aarch64|arm64)
            if ! grep -q '^CLAMAV_IMAGE=' .env; then
                printf '\n# Added by setup.sh: the default ClamAV image has no ARM version.\nCLAMAV_IMAGE=clamav/clamav-debian:stable\n' >> .env
                ok "Set CLAMAV_IMAGE in .env to an image that exists for ARM"
            fi ;;
    esac
    grep -q "^COMPOSE_PROFILES=${TIER}\$" .env 2>/dev/null || [ "$TIER" = minimal ] \
        || warn "Requested tier '$TIER' differs from the existing .env. Edit COMPOSE_PROFILES and DEPLOYMENT_TIER there to change tier."
else
    profiles=""; [ "$TIER" = minimal ] || profiles="$TIER"
    # clamav/clamav:stable is published for x86-64 only; the Debian build of the same scanner has an arm64 image.
    clamav_line="# CLAMAV_IMAGE=clamav/clamav:stable"
    case "$(uname -m)" in aarch64|arm64) clamav_line="CLAMAV_IMAGE=clamav/clamav-debian:stable" ;; esac
    cat > .env <<ENV
# Heimdall — written by setup.sh. Secrets live in secrets/, not here.

# minimal | intermediate | full. COMPOSE_PROFILES makes a plain
# 'docker compose up -d' start exactly the containers this tier needs.
DEPLOYMENT_TIER=${TIER}
COMPOSE_PROFILES=${profiles}

# Image version to run. Change it, then: docker compose pull && docker compose up -d
IMAGE_TAG=${VERSION_TAG}

# After an upgrade the images of older versions are removed to save disk space (up to about 1.4 GB per version).
# Remove the leading # to keep them instead.
# KEEP_OLD_IMAGES=1

# Router chosen at setup. 'passive' = no router login, devices found from the ARP table.
# Applied once, on first start; change it afterwards on the Equipment tab.
INITIAL_ROUTER=${ROUTER}

# LAN-facing interface to sniff, and its subnet (used by Zeek).
SNIFF_IFACE=${IFACE}
LAN_SUBNET=${SUBNET}

# ClamAV image (full tier). Set automatically to the Debian build on ARM, where the default image does not exist.
${clamav_line}

# Read by docker-compose.yml to build the database URL.
DB_PASS=$(tr -d '[:space:]' < secrets/db_pass.txt)
ENV
    chmod 600 .env
    ok "Wrote .env"
fi

echo ""
echo "${B}Ready.${N} Start Heimdall:"
echo ""
echo "    docker compose pull && docker compose up -d"
echo ""
echo "  Dashboard:  http://<this-machine>:3000"
if [ -s secrets/admin_password.txt ]; then
    echo "  Login:      the existing one (user and password file kept from before: $(pwd)/secrets/admin_password.txt)"
else
    echo "  First visit: the dashboard asks you to create your admin account (user name and password)."
    echo "               Do that straight away, before anyone else on your network opens the page."
fi
echo "  Then open the Equipment tab and pick your router (or 'Other / not listed')."
echo "  Do not expose ports 3000 or 5000 to the internet."
