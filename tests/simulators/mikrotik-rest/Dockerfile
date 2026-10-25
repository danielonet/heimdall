# MikroTik RouterOS CHR (Cloud Hosted Router) lab instance serving the RouterOS 7 REST API.
# CHR is a QEMU/KVM VM, so this wraps a community image; the container needs /dev/kvm and
# /dev/net/tun (see ../docker-compose.yml). Mark CI tests that use it as optional.
#
# Verified: evilfreelancer/docker-routeros:7.16 pulls and serves /rest on port 80.
# CHR is free for lab use under MikroTik's licence (speed-limited to 1 Mbit/s unlicensed).
ARG ROUTEROS_TAG=7.16
FROM evilfreelancer/docker-routeros:${ROUTEROS_TAG}

# The image boots QEMU with `-cpu host -smp 4`, which reboot-loops forever on some hosts
# (seen on an AMD Athlon Silver). A generic CPU and one vCPU boot reliably in ~20 s.
RUN sed -i -e 's/-smp 4,sockets=1,cores=4,threads=1/-smp 1/' -e 's/-cpu host\$CPU_FEATURES/-cpu qemu64/' /routeros/entrypoint.sh \
 && grep -q -- '-cpu qemu64' /routeros/entrypoint.sh \
 && grep -q -- '-smp 1' /routeros/entrypoint.sh

# REST is served by the `www` (80) / `www-ssl` (443) services; default login admin / (empty password).
EXPOSE 80 443
