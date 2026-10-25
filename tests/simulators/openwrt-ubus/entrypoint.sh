#!/bin/sh
# Starts ubusd + rpcd + uhttpd (with the ubus JSON-RPC bridge) and seeds the
# root password and a few DHCP leases so get_clients/get_dhcp_leases have data.
# There is no WiFi hardware in a container, so wireless client lists are empty.
set -e

SIM_PASSWORD="${SIM_PASSWORD:-sim-password}"
# The rootfs image ships root with an EMPTY password, which rpcd accepts for
# any input — so set a real one, or a "wrong password" test would pass login.
printf '%s\n%s\n' "${SIM_PASSWORD}" "${SIM_PASSWORD}" | passwd root >/dev/null
if grep -q '^root::' /etc/shadow; then
    echo "FATAL: could not set the root password" >&2
    exit 1
fi

mkdir -p /tmp/dhcp.leases.d
cat > /tmp/dhcp.leases <<LEASES
$(( $(date +%s) + 3600 )) aa:bb:cc:00:00:01 192.168.1.20 laptop *
$(( $(date +%s) + 3600 )) aa:bb:cc:00:00:02 192.168.1.21 nas *
LEASES

ubusd &
sleep 1
rpcd &
sleep 1
exec uhttpd -f -p 0.0.0.0:80 -h /www -u /ubus -U /var/run/ubus/ubus.sock
