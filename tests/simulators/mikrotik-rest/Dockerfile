# MikroTik RouterOS CHR (Cloud Hosted Router) lab instance serving the RouterOS 7 REST API.
# CHR is a QEMU/KVM VM, so this wraps a community image; the container needs /dev/kvm
# (see ../docker-compose.yml). Mark CI tests that use it as optional.
#
# UNVERIFIED: image and tag come from the community project
# github.com/EvilFreelancer/docker-routeros; confirm they exist before relying
# on this. Override with --build-arg ROUTEROS_TAG=...
# CHR is free for lab use under MikroTik's licence (speed-limited to 1 Mbit/s unlicensed).
ARG ROUTEROS_TAG=7.16
FROM evilfreelancer/docker-routeros:${ROUTEROS_TAG}

# REST is served by the `www` (80) / `www-ssl` (443) services; default login admin / (empty password).
EXPOSE 80 443
