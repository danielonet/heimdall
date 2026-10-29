#!/usr/bin/env bash
# get-heimdall.sh — install or upgrade Heimdall from the published release.
#
#   curl -fsSL https://heimdall.it.com/install.sh | bash -s -- --tier=intermediate
#
# What it does, in order (nothing else):
#   1. checks for Linux, Docker and the compose plugin (installs Docker only if you pass --install-docker)
#   2. downloads heimdall-bundle.tar.gz and its .sha256 from the GitHub release and verifies the checksum
#   3. unpacks it into --dir (default ~/heimdall); an existing .env and secrets/ are never overwritten
#   4. runs the bundle's setup.sh (generates secrets, detects your LAN interface and subnet).
#      On a fresh install it first asks for the dashboard user name and password (Enter keeps the
#      user "admin" and generates a password). Unattended: --admin-user and --admin-password-file.
#   5. runs 'docker compose pull && docker compose up -d' (skip with --no-start)
# It does not touch your router or network configuration. It needs no sudo unless Docker itself does.
#
# Options: --tier=minimal|intermediate|full  --dir=PATH  --version=vX.Y.Z (default: latest)
#          --router=sagemcom|passive  --install-docker  --no-start  --yes (no prompts)  --iface=NAME  --subnet=CIDR
#          --admin-user=NAME  --admin-password-file=PATH (the password lives in that file, never on the command line)
set -euo pipefail

REPO="danielonet/heimdall"
BASE_OVERRIDE="${HEIMDALL_BUNDLE_URL_BASE:-}"   # tests / mirrors

main() {
    local tier="" dir="" version="latest" install_docker=false start=true yes=false setup_args=() admin_pw="" pw_file=""
    for arg in "$@"; do
        case "$arg" in
            --tier=*) tier="${arg#--tier=}" ;;
            --dir=*) dir="${arg#--dir=}" ;;
            --version=*) version="${arg#--version=}" ;;
            --install-docker) install_docker=true ;;
            --no-start) start=false ;;
            --yes|-y) yes=true ;;
            --iface=*|--subnet=*|--router=*|--admin-user=*) setup_args+=("$arg") ;;
            --admin-password-file=*) pw_file="$(readlink -f "${arg#--admin-password-file=}")"; setup_args+=("--admin-password-file=$pw_file") ;;
            -h|--help) echo "Usage: install.sh [--tier=minimal|intermediate|full] [--router=sagemcom|passive] [--dir=PATH] [--version=vX.Y.Z] [--install-docker] [--no-start] [--yes] [--iface=NAME] [--subnet=CIDR] [--admin-user=NAME] [--admin-password-file=PATH]"; return 0 ;;
            *) die "Unknown option: $arg" ;;
        esac
    done

    [ "$(uname -s)" = "Linux" ] || die "Heimdall needs Linux: it sniffs your LAN with host networking."
    command -v curl >/dev/null || die "curl is required."
    command -v sha256sum >/dev/null || die "sha256sum is required."

    if [ -z "$dir" ]; then
        if [ "$(id -u)" -eq 0 ] && [ -z "${SUDO_USER:-}" ]; then dir=/opt/heimdall; else dir="$(user_home)/heimdall"; fi
    fi

    # With no --tier, ask — but only if there is a terminal to ask on (stdin is the script itself when piped).
    if [ -z "$tier" ] && ! $yes && [ -r /dev/tty ]; then
        echo "Which installation tier?"
        echo "  1) minimal       core stack only"
        echo "  2) intermediate  + OpenCanary honeypot"
        echo "  3) full          + Zeek, ClamAV, Suricata (needs ~4 GB RAM)"
        local choice; read -rp "Enter 1/2/3 [1]: " choice < /dev/tty
        case "${choice:-1}" in 1) tier=minimal ;; 2) tier=intermediate ;; 3) tier=full ;; *) die "Invalid choice: $choice" ;; esac
    fi
    [ -n "$tier" ] && setup_args+=("--tier=$tier")

    # Same idea for the router, on a fresh install only (an existing .env keeps its choice).
    if [[ " ${setup_args[*]-} " != *" --router="* ]] && [ ! -f "$dir/.env" ] && ! $yes && [ -r /dev/tty ]; then
        echo "Which router is on your network?"
        echo "  1) Sagemcom F@st (XMO)"
        echo "  2) Another router, or not sure — Heimdall finds devices itself (passive mode)"
        echo "  3) A router from the supported list — I'll pick it in the dashboard"
        local rchoice; read -rp "Enter 1/2/3 [3]: " rchoice < /dev/tty
        case "${rchoice:-3}" in 1) setup_args+=("--router=sagemcom") ;; 2) setup_args+=("--router=passive") ;; 3) ;; *) die "Invalid choice: $rchoice" ;; esac
    fi

    # The dashboard login, on a fresh install only (an existing one keeps its login). The password is held in
    # a variable, handed to setup.sh through a private temp file, and never appears in argv or `ps`.
    if [ -z "$pw_file" ] && [ ! -f "$dir/secrets/admin_password.txt" ] && ! $yes && [ -r /dev/tty ]; then
        local user_given=false
        [[ " ${setup_args[*]-} " == *" --admin-user="* ]] && user_given=true
        echo ""
        echo "Dashboard login — what you will sign in with the first time."
        if ! $user_given; then
            local entered
            while :; do
                read -rp "User name [admin]: " entered < /dev/tty
                entered="${entered:-admin}"
                if [[ "$entered" =~ ^[A-Za-z0-9._-]{3,32}$ ]]; then setup_args+=("--admin-user=$entered"); break; fi
                warn "Use 3-32 letters, digits, dots, dashes or underscores."
            done
        fi
        local again
        while :; do
            read -rsp "Password (at least 12 characters; press Enter to generate one): " entered < /dev/tty; echo >&2
            [ -n "$entered" ] || break
            if [ "${#entered}" -lt 12 ]; then warn "The password must be at least 12 characters."; continue; fi
            if [[ "$entered" =~ ^[[:space:]]|[[:space:]]$ ]]; then warn "The password must not start or end with a space."; continue; fi
            read -rsp "Repeat the password: " again < /dev/tty; echo >&2
            if [ "$entered" = "$again" ]; then admin_pw="$entered"; break; fi
            warn "The two entries differ — try again."
        done
    fi

    ensure_docker "$install_docker"
    local docker=(docker)
    if ! docker info >/dev/null 2>&1; then
        if command -v sudo >/dev/null && sudo docker info >/dev/null 2>&1; then
            docker=(sudo docker)
            warn "Your user cannot talk to Docker directly; using sudo. (sudo usermod -aG docker \$USER, then log in again, to avoid this.)"
        else
            die "Cannot reach the Docker daemon. Is it running, and is your user in the 'docker' group?"
        fi
    fi

    local base
    if [ -n "$BASE_OVERRIDE" ]; then base="$BASE_OVERRIDE"
    elif [ "$version" = latest ]; then base="https://github.com/${REPO}/releases/latest/download"
    else base="https://github.com/${REPO}/releases/download/${version}"; fi

    info "Installing Heimdall (${version}) into ${dir}"
    local tmp; tmp="$(mktemp -d)"
    # shellcheck disable=SC2064  # expanded now on purpose: $tmp is local to main, gone when EXIT fires
    trap "rm -rf '$tmp'" EXIT
    curl -fsSL -o "$tmp/heimdall-bundle.tar.gz" "$base/heimdall-bundle.tar.gz" || die "Could not download $base/heimdall-bundle.tar.gz"
    curl -fsSL -o "$tmp/heimdall-bundle.tar.gz.sha256" "$base/heimdall-bundle.tar.gz.sha256" || die "Could not download the checksum file"
    (cd "$tmp" && sha256sum -c heimdall-bundle.tar.gz.sha256 >/dev/null) || die "Checksum mismatch — refusing to install."
    ok "Checksum verified"
    if [ -n "$admin_pw" ]; then
        # $tmp is mode 700 (mktemp -d) and removed by the EXIT trap; setup.sh copies the password into secrets/.
        ( umask 077; printf '%s\n' "$admin_pw" > "$tmp/admin_password" )
        setup_args+=("--admin-password-file=$tmp/admin_password")
        admin_pw=""
    fi

    local upgrading=false; [ -f "$dir/docker-compose.yml" ] && upgrading=true
    mkdir -p "$dir"
    tar -xzf "$tmp/heimdall-bundle.tar.gz" -C "$dir" --strip-components=1
    [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER:" "$dir"

    (cd "$dir" && ./setup.sh ${setup_args[@]+"${setup_args[@]}"}) </dev/null
    if $upgrading && [ -f "$dir/.env" ]; then
        # An upgrade must move IMAGE_TAG to the version just unpacked; setup.sh leaves an existing .env alone.
        local new_tag; new_tag="$(tr -d '[:space:]' < "$dir/VERSION")"; new_tag="${new_tag#v}"
        sed -i "s/^IMAGE_TAG=.*/IMAGE_TAG=${new_tag}/" "$dir/.env"
        ok "Upgrade: IMAGE_TAG is now ${new_tag}"
    fi

    if ! $start; then
        info "Not starting (--no-start). When ready: cd ${dir} && docker compose pull && docker compose up -d"
        return 0
    fi
    (cd "$dir" && "${docker[@]}" compose pull && "${docker[@]}" compose up -d)
    wait_for_dashboard
}

user_home() { getent passwd "${SUDO_USER:-$(id -un)}" | cut -d: -f6; }

ensure_docker() {
    command -v docker >/dev/null && docker compose version >/dev/null 2>&1 && return 0
    if [ "$1" = true ]; then
        info "Installing Docker with the official script (https://get.docker.com)"
        if [ "$(id -u)" -eq 0 ]; then curl -fsSL https://get.docker.com | sh; else curl -fsSL https://get.docker.com | sudo sh; fi
        warn "Add yourself to the docker group (sudo usermod -aG docker \$USER) and log in again to use Docker without sudo."
    else
        die "Docker with the compose plugin is required. Install it (https://docs.docker.com/engine/install/) or re-run with --install-docker."
    fi
}

wait_for_dashboard() {
    info "Waiting for the dashboard (first start downloads images and can take a few minutes)..."
    local i tries=$(( ${HEIMDALL_WAIT_SECONDS:-300} / 5 ))
    # shellcheck disable=SC2034
    for i in $(seq 1 "$tries"); do
        if curl -fs -o /dev/null http://localhost:3000; then ok "Heimdall is up: http://<this-machine>:3000"; return 0; fi
        sleep 5
    done
    warn "Not answering on :3000 yet. Check: docker compose ps   and   docker compose logs sentinel-backend"
}

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'; else B=''; G=''; Y=''; R=''; N=''; fi
info() { echo "${B}▸${N} $*"; }
ok()   { echo "${G}✔${N} $*"; }
warn() { echo "${Y}⚠${N} $*" >&2; }
die()  { echo "${R}✖${N} $*" >&2; exit 1; }

# Everything runs from main so a truncated download executes nothing.
main "$@"
