# Three-tier deployment: MINIMAL / INTERMEDIATE / FULL

## Context

Heimdall's Docker Compose stack currently has one shape: every optional
security container (Suricata, Zeek, ClamAV, OpenCanary) and every backend
integration is always deployed and always running, unconditionally. As the
product matures toward real installs, not every deployment needs (or can
afford, resource-wise) the full stack — some users just want visibility,
others want the works. This introduces three concrete install profiles:

- **MINIMAL** — core stack only (postgres, redis, backend, frontend). All
  Python-library-based detection stays active (the 6 ML/rule detectors,
  WAN bandwidth, cross-alert correlation, threat intel feeds, nmap
  scanning, ARP/DHCP/passive-fingerprint watchers) since none of it needs
  an extra container — plus the existing auto-block/quarantine response,
  unchanged and available in every tier per your direction.
- **INTERMEDIATE** — MINIMAL + OpenCanary. Chosen as the one "lightweight
  middle ground" container: it's a handful of idle socket listeners (no
  packet inspection, no signature database), has no dependency on any
  other optional service, and any hit is inherently high-confidence (a
  connection to a fake service is never legitimate traffic). By contrast,
  ClamAV only ever receives files from Zeek's file-extraction watcher
  (`_zeek_file_scan_job` in scheduler.py) and Zeek/Suricata are both full
  DPI engines — meaningfully heavier and, for ClamAV, functionally inert
  without Zeek alongside it. That ruled them out as "lightweight."
- **FULL** — everything: + Zeek, ClamAV, Suricata.

Auto-block/quarantine is **not** gated by tier — it stays exactly what it
is today, a single user-facing Settings toggle (`auto_block_on_threat`,
checked in `_raise_threat_alert`), available and unaffected in all three
tiers, per your explicit direction to drop the NOC/SOC "watch vs act"
split.

One pre-existing bug gets fixed as part of this, since FULL explicitly
promises Suricata IDS alerts and today they can never arrive: `docker-compose.yml`
never mounts the `suricata-logs` volume into `sentinel-backend`, so
`SuricataEveLogReader` polls a path that never exists inside that
container, regardless of tier.

## Docker Compose: one file, Compose profiles

Single source of truth — avoids the file-drift already found between the
current `docker-compose.yml` and its own architecture doc. Tag each
optional service; services with no `profiles` key always run:

```yaml
services:
  opencanary:
    profiles: ["intermediate", "full"]
  zeek:
    profiles: ["full"]
  clamav:
    profiles: ["full"]
  suricata:
    profiles: ["full"]
  wiremock:
    profiles: ["dev"]   # cleanup: was untagged, isn't a real tier at all
  sentinel-backend:
    volumes:
      - suricata-logs:/var/log/suricata:ro   # new — fixes the bug above
```

Resulting commands: `docker compose up -d` (MINIMAL), `docker compose
--profile intermediate up -d` (INTERMEDIATE), `docker compose --profile
full up -d` (FULL).

## `scripts/install.sh` + thin per-tier wrappers

- `install.sh` gains a required `--tier=minimal|intermediate|full` flag.
  Writes `DEPLOYMENT_TIER=<tier>` into the generated `.env`. Config-dir
  scaffolding becomes conditional: `opencanary/` only for
  intermediate/full, `suricata/` config only for full (currently both are
  created unconditionally). Final printed next-steps message includes the
  tier-correct `docker compose [--profile X] up -d` command — matches the
  script's existing convention of scaffolding everything but leaving the
  actual `up` to the user.
- New `scripts/install-minimal.sh`, `scripts/install-intermediate.sh`,
  `scripts/install-full.sh` — each a one-line `exec
  "$(dirname "$0")/install.sh" --tier=X "$@"`. Gives discoverable,
  literal "3 installation scripts" without duplicating the real logic.

## Backend

**New `sentinel/deployment_tiers.py`** — pure module, the single source of
truth both the scheduler and API read from:
```python
TIER_SERVICES = {
    'minimal':      {'opencanary': False, 'zeek': False, 'clamav': False, 'suricata': False},
    'intermediate': {'opencanary': True,  'zeek': False, 'clamav': False, 'suricata': False},
    'full':         {'opencanary': True,  'zeek': True,  'clamav': True,  'suricata': True},
}
ALWAYS_ON_SERVICES = [
    'postgres', 'redis', 'router_poll', 'arp_watch', 'dhcp_watch',
    'fingerprint', 'nmap', 'threat_intel',
]

def services_for_tier(tier: str) -> dict[str, bool]:
    """Unknown/misconfigured tier values fall back to 'minimal' — never
    silently assume a container is present that wasn't actually deployed."""
    return TIER_SERVICES.get(tier, TIER_SERVICES['minimal'])

def active_service_keys(tier: str) -> list[str]:
    gated = services_for_tier(tier)
    docker_keys = {
        'opencanary': ['opencanary'],
        'zeek': ['zeek_dns', 'zeek_beacon'],
        'clamav': ['clamav'],
        'suricata': ['suricata'],
    }
    active = list(ALWAYS_ON_SERVICES)
    for flag, keys in docker_keys.items():
        if gated[flag]:
            active.extend(keys)
    return active
```
These 13 keys map 1:1 onto `ServiceStatusPanel.jsx`'s existing 13 rows.

**`sentinel/config.py`** — add `DEPLOYMENT_TIER: str = 'full'` (default
preserves today's actual behavior — everything already runs
unconditionally today, so 'full' is the correct no-surprise default for
existing installs that haven't set the var).

**`sentinel/scheduler/scheduler.py`**:
- `SentinelScheduler.__init__` gains `deployment_tier: str = 'full'`;
  stores `self._tier = deployment_tier` and `self._tier_services =
  services_for_tier(deployment_tier)`.
- `_run_loop` (currently one unconditional block, lines ~226–334):
  OpenCanary's construction + its `canary_poll` `add_job` call move
  behind `if self._tier_services['opencanary']:`; Zeek's 3 components +
  their 3 `add_job` calls (`zeek_dns_poll`, `zeek_beacon_scan`,
  `zeek_file_scan`) behind `if self._tier_services['zeek']:`; ClamAV
  construction behind `if self._tier_services['clamav']:` (and
  `_zeek_file_scan_job` adds an explicit `if self._clamav_scanner:` guard
  before calling it, being defensive rather than relying on the tier
  table's current zeek/clamav coincidence); Suricata behind `if
  self._tier_services['suricata']:`. Everything else (detection pipeline,
  WAN bandwidth, correlation, threat intel, nmap, ARP/DHCP/fingerprint
  watchers) stays exactly as unconditional as it is today — these are the
  always-on Python-library set.
- `init_scheduler()` reads `settings.DEPLOYMENT_TIER` and passes it
  through to the `SentinelScheduler(...)` constructor call.
- `security_services_snapshot()` gains two new keys: `'deployment_tier':
  self._tier` and `'active_services': active_service_keys(self._tier)`.

**`sentinel/api/routes/system.py`** — `/api/health` threads
`deployment_tier`/`active_services` into its JSON from
`security_services_snapshot()`. Also fixes the existing fallback path
(when the scheduler isn't initialized) to return the same key shape
instead of today's stale 4-key subset.

## Frontend

**`frontend/src/components/dashboard/ServiceStatusPanel.jsx`** — refactor
from 13 hardcoded `<Row>` JSX elements into a `ROWS` config array (`{key,
icon, label, ok, detail}`, one entry per existing row, key matching the
backend's 13 service keys above), then `ROWS.filter(r =>
activeServices.includes(r.key)).map(...)`. `activeServices =
health?.active_services || []`. This is the concrete mechanism satisfying
"UI will dynamically list the active defenses" — no other code changes
needed since every row already reads from `health` today, they just also
need to not render at all when their key is absent.

Small addition: a `DEPLOYMENT: MINIMAL/INTERMEDIATE/FULL` read-only badge
using `health.deployment_tier`, placed in the Settings page's ROUTER panel
(next to existing `Field` items) — cheap, directly answers "what tier am I
running" without new plumbing.

No changes to `AutoBlockSection`, `_raise_threat_alert`, nav items, or the
RULES/THREATS tabs — auto-block and the rule engine are pure-Python/DB
capabilities with no Docker dependency, so they're unaffected by tier and
stay exactly as they are today.

## Docs

`docs/architecture/09-docker-compose.md` — add the profiles/tier section;
also fix the drift already found during research (missing `wiremock`
entry, stale `frontend` networking snippet, incomplete volume list) while
touching this file. README gets a short "Installation tiers" section
pointing at the 3 wrapper scripts.

## Verification

- Backend: new `tests/test_config/test_deployment_tiers.py` — covers all
  3 known tiers' `services_for_tier()`/`active_service_keys()` output plus
  the unknown-tier-falls-back-to-minimal case.
- Extend scheduler tests (existing `object.__new__(SentinelScheduler)`
  pattern) to confirm `security_services_snapshot()['active_services']`
  matches the tier passed at construction.
- `python3 -m py_compile` on every touched backend file; full `pytest
  tests/ -q` run against `sentinel_test` before calling this done.
- `docker compose config -q`, `docker compose --profile intermediate
  config -q`, `docker compose --profile full config -q` — confirm all 3
  profile combinations parse cleanly.
- Frontend: `npm run lint && npm run build`; manual browser check needed
  on your end (no browser access in this sandbox) to confirm
  ServiceStatusPanel actually hides/shows rows correctly per tier.
