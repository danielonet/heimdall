# Router simulators

Routers whose OS can run in a container are tested against the real thing; every
other router is tested against WireMock stubs (`wiremock/mappings/<router-id>/`).

| Router id | Simulator | Start | Notes |
|---|---|---|---|
| `openwrt-ubus` | OpenWrt rootfs container | `docker compose -f tests/simulators/docker-compose.yml up --build openwrt-ubus` | `root` / `sim-password` on `localhost:8081`; no WiFi clients, leases are seeded |
| `mikrotik-rest` | RouterOS CHR (QEMU) | `... up --build mikrotik-rest` | needs `/dev/kvm`; `admin` / empty password on `localhost:8082` |

Both Dockerfiles are **unverified** (they could not be built where they were written) —
confirm the base image tags before relying on them.
