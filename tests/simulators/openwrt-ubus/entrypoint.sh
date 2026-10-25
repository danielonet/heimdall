#!/bin/sh
# Starts ubusd + rpcd + uhttpd (with the ubus JSON-RPC bridge) and seeds the
# root password and a few DHCP leases so get_clients/get_dhcp_leases have data.
# There is no WiFi hardware in a container, so wireless client lists are empty.
set -e

SIM_PASSWORD="${SIM_PASSWORD:-sim-password}"
echo "root:${SIM_PASSWORD}" | chpasswd 2>/dev/null || {
    HASH="$(openssl passwd -1 "${SIM_PASSWORD}" 2>/dev/null || true)"
    [ -n "$HASH" ] && sed -i "s|^root:[^:]*:|root:${HASH}:|" /etc/shadow
}

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
