# WireMock router simulators

One WireMock server (`docker compose --profile dev up wiremock -d`, port 8080) serves stubs for
every router that has no container-friendly OS. Each router has its **own folder**, named after
its adapter id in `sentinel/adapter/catalog.py`:

```
wiremock/
├── mappings/<router-id>/NN-name.json   request → response stubs
└── __files/<router-id>/…             response bodies, plus NOTES.md (fidelity + quirks)
```

Routers whose real OS runs in Docker (OpenWrt, MikroTik CHR) are **not** here — see
[`tests/simulators/`](../tests/simulators/README.md).

| Router id | Auth modelled | Failure behaviour modelled | Fidelity |
|---|---|---|---|
| `sagemcom-xmo` | none | — | recorded shape (hosts only) |
| `miwifi-stok` | stok token | HTML page with HTTP 200 on a stale token | from `docs/router/miwifi-api.md` |
| `unifi-network` | cookie session | session expires after 2 polls (401), re-login resets; bad login → 403 | synthetic |
| `opnsense-rest` | Basic (`sim-key`/`sim-secret`) | 401 | synthetic |
| `pfsense-rest` | `X-API-Key: sim-api-key` | 401 | synthetic |
| `fritzbox-tr064` | Digest header presence | 401 digest challenge | synthetic |
| `asus-http` | `login.cgi` cookie | HTML redirect with HTTP 200 when logged out | synthetic |
| `tplink-router` | `stok` + `sysauth` | `success:false` login, 403 | synthetic, crypto not real |
| `netgear-soap` | SOAPAction routing | 401 for unknown calls | synthetic |
| `keenetic-rci` | challenge → login scenario | 401 until logged in | synthetic |

**Synthetic** means hand-written from public API docs and reference libraries, not recorded from a
device; each folder's `__files/<router-id>/NOTES.md` lists what to verify. Replace stubs with
scrubbed recordings as soon as someone has the hardware.

Adapter tests that run against these stubs: `tests/test_adapter/test_wiremock_adapters.py` (skipped when WireMock is down).

Counters (`rx_bytes`, …) use WireMock response templating (`{{now format='unix'}}`) so they grow
between polls; the server is started with `--global-response-templating`.

## Use

```bash
docker compose --profile dev up wiremock -d
curl -s http://localhost:8080/proxy/network/api/s/default/stat/sta   # 401 until you POST /api/auth/login
```

Point an adapter at `http://localhost:8080` (host `localhost`, port `8080`). All routers share one
port, so paths must stay unique per router; prefix scenario names with the router id.

## Adding a router

1. Add it to `sentinel/adapter/catalog.py` with `simulator=SimulatorKind.WIREMOCK`.
2. Create `mappings/<router-id>/` and `__files/<router-id>/` (reference bodies as `<router-id>/file`).
3. `tests/test_adapter/test_catalog.py` fails until the folder has at least one valid mapping.

## Recording real traffic

Use WireMock's recorder against the real router (`POST /__admin/recordings/start` with
`targetBaseUrl`), then move the generated files into the router's folder and **scrub MACs, IPs,
serials and tokens** before committing.
