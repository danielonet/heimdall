# Contributing to Heimdall

Thanks for helping! Heimdall is an alpha, single-maintainer project, so small,
focused PRs are easiest to review. The highest-value contributions right now
are **new router adapters** and **web-UI fixtures for switches** — see
[`docs/router-and-switch-expansion-plan.md`](docs/router-and-switch-expansion-plan.md)
for the roadmap.

## Help test your router

Heimdall has only ever run on the maintainer's own Sagemcom and Redmi routers.
Every other family in the [supported routers table](README.md#supported-routers)
is built against simulators written from public docs, so **real-hardware
testers are the most valuable contribution you can make** — no coding needed.

If you own a UniFi, OpenWrt, MikroTik, OPNsense, pfSense, FRITZ!Box, ASUS,
TP-Link, Netgear or Keenetic device (or any other router):

1. Open an issue titled `Router test: <vendor> <model> <firmware>`.
2. Say what you tried: selecting it on the Equipment tab, saving the login,
   and (once its adapter exists) whether devices and traffic showed up.
3. Optionally attach a **scrubbed** capture of the router's API responses
   (WireMock recorder or browser HAR) — see [`wiremock/README.md`](wiremock/README.md#recording-real-traffic).
   Remove MACs, IPs, serials, SSIDs and tokens first (see the ground rules below).

A router moves to "Tested on real hardware" in the README once someone
reports it working on a physical unit. If you'd rather write the adapter,
the roadmap is in
[`docs/router-and-switch-expansion-plan.md`](docs/router-and-switch-expansion-plan.md).

## Ground rules

- Be kind. Assume good faith.
- Security problems go through [`SECURITY.md`](SECURITY.md), **not** public issues.
- **Never commit real network data.** Scrub MAC addresses, SSIDs, serial
  numbers, public IPs, tokens and hostnames that identify you or your
  household from fixtures, logs, docs and screenshots. Use obviously-fake
  values (`AA:BB:CC:DD:EE:FF`, `MyHomeWiFi`). Keep the vendor prefix (first 3
  MAC bytes) if a test depends on vendor lookup.

## Architecture rules (non-negotiable)

These are enforced in review; the full list lives in [`CLAUDE.md`](CLAUDE.md).

1. **Router access only through the adapter layer** — implement
   `sentinel/adapter/base.py:RouterAdapter`; nothing else talks to a router.
2. **All backend I/O is async** (`httpx.AsyncClient`, SQLAlchemy async,
   `redis.asyncio`).
3. **Detection logic only in detectors** — subclass `BaseDetector` in
   `sentinel/detection/detectors/` and register it in
   `sentinel/detection/pipeline.py`.
4. **ML models are per-device**, never global.
5. **Respect traffic granularity** — wired traffic is `PER_PORT` unless the
   source genuinely measures per device. Never present aggregate data as
   per-device. See `docs/router/wired-monitoring-caveat.md`.
6. **Secrets via Docker secrets only** (`/run/secrets/…`), never env vars or
   hard-coded values.

Style: type hints on every signature, dataclasses for DTOs, docstrings on
classes and public methods, `logging` (never `print()`), `snake_case` in
Python and `camelCase` in JS/TS, tests in `tests/` mirroring `sentinel/`.

## Getting set up

Requires a Linux host with Docker. Fastest path, **no router needed**:

```bash
git clone https://github.com/danielonet/heimdall.git && cd heimdall
sudo ./scripts/install-minimal.sh     # one-off: packages, secrets/, .env
./scripts/mock-router-start.sh        # synthetic router data, backend + frontend on this console
```

The dashboard is at `http://localhost:5173` (the Vite dev server; run with
`FRONTEND_HOST=0.0.0.0` to reach it from another machine. The containerised
build is on port 3000). Log in as `admin`, password in
`secrets/admin_password.txt`). See [`MOCK-ROUTER-SETUP.md`](MOCK-ROUTER-SETUP.md)
for details; the available flags are documented at the top of
[`scripts/dev.sh`](scripts/dev.sh) and [`scripts/run.sh`](scripts/run.sh).

## Running the tests

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r sentinel/requirements.txt
pytest -q
```

The suite needs PostgreSQL/TimescaleDB and Redis (CI starts both as service
containers). Locally: `docker compose up -d postgres redis`, then
`export DATABASE_URL=postgresql+asyncpg://sentinel:<db_pass>@localhost/sentinel`
(the password is in `secrets/db_pass.txt`), `alembic upgrade head`, and run
`pytest -q`. Without a database most tests error rather than skip.

Frontend:

```bash
cd frontend && npm ci && npm run lint && npm run build
```

CI runs the same checks on every PR — please make sure they pass locally first.

## Adding a router adapter

1. Read [`docs/architecture/02-router-adapter.md`](docs/architecture/02-router-adapter.md)
   and [`docs/architecture/11-multi-adapter-auto-detection.md`](docs/architecture/11-multi-adapter-auto-detection.md).
2. Create `sentinel/adapter/<vendor>/` with a thin HTTP client and an adapter
   subclassing `RouterAdapter`. Normalise MACs, return the dataclasses from
   `sentinel/adapter/models.py`, and be explicit about what your router cannot
   do (per-device traffic, blocking, WAN stats → return `None`/documented
   limits rather than faking data).
3. **Do not retry failed logins in a tight loop** — routers lock accounts out.
4. Add tests in `tests/test_adapter/` using **scrubbed** captured responses.
5. Document the protocol in `docs/router/<vendor>-api.md`.
6. Open the "New router / switch support" issue template first if you want to
   talk design before coding.

## Pull requests

- One logical change per PR; link the issue it closes.
- Include tests for behaviour changes and bug fixes.
- Update docs when behaviour changes (README, `docs/`).
- Commit messages: short imperative subject, optional body explaining *why*.
  Conventional prefixes (`feat:`, `fix:`, `docs:`, `chore:`) are used in this
  repo's history.
- By contributing you agree your work is released under the project's
  [MIT license](LICENSE).
