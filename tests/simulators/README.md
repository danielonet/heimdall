# Router simulators

Routers whose OS can run in a container are tested against the real thing; every
other router is tested against WireMock stubs (`wiremock/mappings/<router-id>/`).

| Router id | Simulator | Start | Notes |
|---|---|---|---|
| `openwrt-ubus` | OpenWrt rootfs container | `docker compose -f tests/simulators/docker-compose.yml up --build openwrt-ubus` | `root` / `sim-password` on `localhost:8081`; no WiFi clients, leases are seeded |
| `mikrotik-rest` | RouterOS CHR (QEMU) | `... up --build mikrotik-rest` | needs `/dev/kvm`; `admin` / empty password on `localhost:8082` |

Both images were built and run, and their adapters are tested against them
(`tests/test_adapter/test_openwrt_adapter.py`, `test_mikrotik_adapter.py` — skipped when the
simulator isn't up; override addresses with `OPENWRT_URL` / `MIKROTIK_URL`).

Quirks found by running them:

- **OpenWrt:** the rootfs ships `root` with an empty password, which rpcd accepts for any input;
  `entrypoint.sh` sets a real one. No procd/netifd, so `system board`/`network.interface dump`
  don't exist — the adapter falls back to `luci-rpc getBoardJSON`.
- **RouterOS:** the base image boots QEMU with `-cpu host -smp 4`, which reboot-loops on some hosts
  (seen on an AMD Athlon Silver); the Dockerfile patches it to `-cpu qemu64 -smp 1`. Needs
  `/dev/kvm` **and** `/dev/net/tun`.
- Neither container passes real client traffic, so blocking and per-client counters cannot be
  verified here.
