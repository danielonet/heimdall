# Real OpenWrt userland exposing the same /ubus JSON-RPC endpoint a router does.
# Used by the openwrt-ubus adapter's integration tests (docs/router-and-switch-expansion-plan.md §1.2).
#
# UNVERIFIED: the base tag and package names follow OpenWrt's published
# rootfs images; confirm the tag exists (hub.docker.com/r/openwrt/rootfs)
# before relying on this. Override with --build-arg OPENWRT_TAG=...
ARG OPENWRT_TAG=x86-64-23.05.5
FROM openwrt/rootfs:${OPENWRT_TAG}

RUN mkdir -p /var/lock /var/run \
 && opkg update \
 && opkg install ubus rpcd uhttpd uhttpd-mod-ubus

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
