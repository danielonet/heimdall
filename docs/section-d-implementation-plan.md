# Section D: time-limited auto-block, quarantine tier, cross-alert correlation, security digest

## Context

`docs/capability-review.md`'s Section D ("Extra defenses / response tooling")
proposed 4 items (#13-#16). Three parallel research agents (block/quarantine
mechanics, `RuleEngine`/correlation feasibility, notification/cron patterns)
plus a direct check of the manual block route confirmed all four are
buildable — none are hardware-blocked like Section B's rogue-AP item was —
but two carry real design decisions worth stating up front:

- **#13 Time-limited auto-block**: `Device.is_blocked` is a bare boolean
  today with no timestamp anywhere (`sentinel/db/models.py:45`) — this needs
  real schema additions, not a repurposing. Research also surfaced a race:
  `_raise_threat_alert` always *re-issues* a block even if `is_blocked` is
  already `True` (regression-tested at
  `tests/test_scheduler/test_threat_auto_block.py:106-125`, deliberately —
  a stale cache bit let a real attack through once). An expiry job must
  refresh the expiry timer on every re-block, or it could unblock a device
  moments after a *fresh* threat re-blocked it.
- **#14 Quarantine tier**: confirmed there's no dead code to resurrect — the
  old `Device/Firewall/Chains/Chain[Name="Custom"]` WAN-only mechanism was
  fully removed after being tested and rejected for full blocking; only the
  xpath/payload shape survives in `docs/router/sagemcom-xmo-api.md:206-265`.
  That doc also flags a real precondition: a rule added to the `Custom`
  chain reports `Status: "DISABLED"` unless the router's *active firewall
  security level* is itself set to `"Custom"` — a router-wide setting
  unrelated to any single device, confirmed live as `"DROP"` on this unit
  but never checked by any code path. **Flipping that automatically would
  be a global, hard-to-reverse change to the router's whole firewall
  posture** — out of scope for what a per-device quarantine action should
  ever touch. The plan below only *reads* that value (to warn if
  quarantine won't actually enforce) and never writes it.
- **#15 Cross-alert correlation**: confirmed `RuleEngine`'s condition model
  (`sentinel/detection/rules_engine.py`) operates on one live
  `DeviceSnapshot`/`TrafficSample` per poll and has no concept of the
  `alerts` table at all — it structurally cannot express "alert X followed
  by alert Y." Also confirmed `_raise_threat_alert` is only one of **four**
  alert-creation paths (`NEW_DEVICE` and 6 other types come from
  `DetectionPipeline`/`poll_cycle` directly, `RULE_TRIGGERED` from
  `RuleEngine`, `HONEYPOT_ACCESS` from `OpenCanaryIngester` — none of which
  route through `_raise_threat_alert`). A correlation engine that only
  hooks `_raise_threat_alert` would miss the exact pattern named in the
  item ("NEW_DEVICE immediately followed by ARP_SPOOF"), since `NEW_DEVICE`
  never touches it. **The correct design is a new periodic job that queries
  the persisted `alerts` table directly**, not an extension of `RuleEngine`.
- **#16 Security digest**: confirmed `NotificationService.notify()` is
  *not* currently wired to fire automatically for every alert — its only
  two call sites are inside `RuleEngine._fire`, gated by an admin-defined
  `Rule` with a `NOTIFY` action. So today, ntfy/SMTP pings only happen for
  rule-matched alerts, not the ~14 other alert types raised via
  `_raise_threat_alert`/`DetectionPipeline`. A digest reading the `alerts`
  table directly becomes the *first* mechanism that guarantees eventual
  notification for every alert type — a good, not just incidental, fit.

---

## #13 — Time-limited auto-block with review

**`sentinel/db/models.py`**: add `Device.blocked_at: Mapped[datetime | None]`
and `Device.blocked_until: Mapped[datetime | None]` (both nullable
`TIMESTAMP(timezone=True)`, no default). `blocked_until IS NULL` means "no
expiry" — this is how **manual** admin blocks (via the existing
`POST /devices/<mac>/block` route) stay indefinite by design; only
**auto**-blocks (through `_raise_threat_alert`) get a timer. New migration
(`down_revision` = current head `d94c1b6e8a37`) adding both columns,
mirroring `b3f8a02e7c15_device_ap_alias.py`'s shape.

**`sentinel/db/models.py`**: add `AppSettings.auto_block_expiry_hours:
Mapped[int]` (`server_default='24'`). `0` means "auto-blocks never expire"
(admin opt-out, same spirit as `auto_block_on_threat` itself). New
migration chained after the above, mirroring
`a7c4e91b2f6d_app_settings_auto_block.py`. **`SettingsRepository`**: add
`get_auto_block_expiry_hours`/`set_auto_block_expiry_hours`, exact
three-part shape of `get_auto_block_on_threat`/`set_auto_block_on_threat`
(`sentinel/db/repositories.py:210-216`).

**`sentinel/scheduler/scheduler.py`'s `_raise_threat_alert`** (lines
645-696): when it performs a block (`blocked_now=True`), additionally set
`device.blocked_at = now` and `device.blocked_until = now +
timedelta(hours=expiry_hours)` if `expiry_hours > 0` else `None` — refreshed
on **every** successful (re-)block, addressing the race flagged above:
a fresh threat always resets the clock, so the expiry job can never unblock
a device that was just legitimately re-blocked for a new reason.

**New interval job `_block_expiry_job`** (mirrors `_data_retention_job`'s
try/except-wrapped shape, `scheduler.py:430-464`, but as an `'interval'`
trigger like `_canary_poll_job` rather than `CronTrigger` — a 24h SLA
checked only once nightly could leave a block live ~24h past due in the
worst case): queries `select(Device).where(Device.is_blocked.is_(True),
Device.blocked_until.isnot(None), Device.blocked_until < now)`; for each,
`await adapter.unblock_device(mac)`, on success sets `is_blocked = False`,
`blocked_at = None`, `blocked_until = None`, and calls
`self._notifier.notify(title='Auto-block expired', message=f'{hostname or
mac} was auto-unblocked after {expiry_hours}h — review and re-block if
still suspicious', severity='WARNING')` directly (confirmed accessible,
`self._notifier` is already a plain instance attribute). Also inserts a
low-severity `Alert(alert_type='AUTO_BLOCK_EXPIRED', severity='INFO', ...)`
so the event is visible in the Alerts feed/history, not just a
transient notification. New `block_expiry_check_interval_s` constructor
param (default e.g. 900s/15min) threaded through `__init__` →
`_run_loop`'s `add_job` → `init_scheduler()` → a new
`Settings.BLOCK_EXPIRY_CHECK_INTERVAL_SECONDS` config field, mirroring
`canary_poll_interval_s` exactly.

**Frontend**: `DeviceHeader.jsx` — when `device.is_blocked` and
`device.blocked_until` is set, show a small "auto-unblocks in Xh Ym" line
next to the block status (manual blocks, `blocked_until: null`, show
nothing extra — already correctly "indefinite").

**Tests**: extend `tests/test_scheduler/test_threat_auto_block.py` to
assert `blocked_at`/`blocked_until` get set on auto-block and refreshed on
re-block. New `tests/test_scheduler/test_block_expiry.py` mirroring
`test_data_retention.py`'s real-`SentinelScheduler`-construction pattern
(needs `self._adapter` too, so may end up closer to
`test_threat_auto_block.py`'s `object.__new__` + manual `sched._adapter =
MockSagemcomAdapter()` — whichever touches less unrelated constructor
state once written) — covers: expires an overdue block, leaves a
not-yet-due block alone, ignores `blocked_until IS NULL` (manual blocks),
sends the notification, writes the `AUTO_BLOCK_EXPIRED` alert.

---

## #14 — Quarantine tier (WAN-only, LAN-preserving)

**`sentinel/adapter/base.py`**: new abstract methods `quarantine_device(self,
mac: str) -> bool` / `unquarantine_device(self, mac: str) -> bool`,
docstring explicitly contrasting with `block_device` (WAN-only vs.
full LAN removal) and citing the `DefaultPolicy` precondition.

**`sentinel/adapter/sagemcom/xmo_adapter.py`**: new methods building the
`Device/Firewall/Chains/Chain[Name="Custom"]/Rules` rule via `addChild`
(not `addObject` — confirmed live quirk) per the exact payload shape in
`docs/router/sagemcom-xmo-api.md:206-207` (`{"value": {"Rule": {...}}}`),
matched to the device's IP (DROP rule scoped to that source IP, WAN-bound
only). `unquarantine_device` removes it (`deleteObject` on the created
rule's uid, mirroring the existing `delete_object` client method already
used elsewhere). **After creating the rule**, `quarantine_device` does a
**read-only** `getValue` on `Device/Firewall/Levels/Level[Name="Custom"]/
DefaultPolicy` — if it's not `"Custom"`-active (exact live semantics to
confirm during implementation, per the caveat above), logs a warning and
the method still returns `True` (the rule *was* created) but the caller
(`_set_quarantined` route, see below) surfaces a
`quarantine_enforced: false`-style flag in its response so the admin knows
to check the router's own Security Level setting manually. **Nothing in
this codebase ever writes `DefaultPolicy`.**

**`sentinel/adapter/mock/mock_adapter.py`**: `self._quarantined_macs: set[str]`
mirroring `self._blocked_macs` exactly (add/discard, unconditional
`True`, no `DISABLED`-status simulation needed for the mock).

**DB**: `Device.is_quarantined: Mapped[bool]` (`server_default='false'`),
mirroring `is_blocked` exactly. New migration.

**API routes** (`sentinel/api/routes/devices.py`): new
`POST /devices/<mac>/quarantine` / `POST /devices/<mac>/unquarantine`,
mirroring `block_device`/`unblock_device`/`_set_blocked` (lines 114-150)
exactly — same `@jwt_required()`, same thread-safe
`scheduler.call_adapter`-style bridge (new `scheduler.quarantine_device`/
`unquarantine_device` thin wrappers mirroring `scheduler.block_device`,
`scheduler.py`'s "Thread-safe bridge for Flask routes" section).
**Manual-only for this round** — no detector auto-triggers quarantine;
that would need a "which alert types get which response tier" policy
framework that doesn't exist yet and is real scope beyond this item's
"give the admin a middle-ground tool" framing.

**Frontend**: `DeviceHeader.jsx`/device list — new "QUARANTINE"/
"UNQUARANTINE" button next to the existing Block/Unblock button
(mirroring `BlockButton.jsx`'s pattern), badge showing quarantined state
distinctly from fully-blocked (e.g. amber "QUARANTINED" vs. red "BLOCKED").

**Tests**: `tests/test_adapter/test_xmo_adapter.py` — this is a real gap
closer (confirmed zero existing coverage for `block_device`/
`_set_blacklist_schedule` either): new tests for `quarantine_device`'s
`addChild` payload shape, the `DefaultPolicy` read-and-warn path, and
`unquarantine_device`'s `deleteObject` call. New route tests mirroring
whatever pattern `tests/test_api/test_devices.py` already uses for
`/block`/`/unblock`.

---

## #15 — Cross-alert correlation

**New file `sentinel/detection/correlation.py`** — a small, curated pattern
list rather than an open-ended engine (matches this codebase's existing
"data-driven curated set" style, e.g. `HIGH_RISK_PORTS`,
`_ACCESS_POINT_ALIASES`):

```python
CORRELATION_PATTERNS = [
    {
        'name': 'NEW_DEVICE_THEN_SPOOFING',
        'trigger_types': {'NEW_DEVICE'},
        'follow_types': {'ARP_SPOOF', 'FINGERPRINT_MISMATCH', 'OS_FINGERPRINT_CONFLICT'},
        'window_minutes': 60,
    },
    {
        'name': 'EXPOSURE_THEN_COMPROMISE',
        'trigger_types': {'VULNERABILITY_DETECTED', 'CREDENTIAL_EXPOSURE_DETECTED', 'HIGH_RISK_PORT_OPENED'},
        'follow_types': {'MALWARE_DETECTED', 'C2_BEACONING'},
        'window_minutes': 1440,  # 24h
    },
]
```

A `CrossAlertCorrelator` class (constructed once, like other
scheduler-owned components) with a `find_new_incidents(session) ->
list[Alert]` method: for each pattern, query `Alert` rows of
`trigger_types` created within a bounded lookback (e.g. last 48h, to keep
the query cheap), then for each trigger, look for a `follow_types` alert
on the *same `device_mac`* with `created_at` between the trigger's
`created_at` and `created_at + window_minutes`. **Dedup**: before creating
a new incident, check for an existing `Alert` with
`alert_type='COMPROMISE_CHAIN_DETECTED'` whose `raw_data['follow_alert_id']`
already equals this follow-alert's id (`Alert.raw_data['follow_alert_id'].astext
== str(follow.id)`, standard SQLAlchemy JSONB indexing) — so the same
trigger→follow pair never re-fires on a later job run, while a *different*
later follow-alert of the same device can still produce a new incident.

**Scheduler wiring**: new interval job `_correlation_job` (every ~5 min,
cheap bounded query), constructed via `self._correlator =
CrossAlertCorrelator()` in `_run_loop`. For each new incident found,
routes through the existing `_raise_threat_alert(mac,
'COMPROMISE_CHAIN_DETECTED', 'CRITICAL', description, raw_data={'pattern':
name, 'trigger_alert_id':, 'follow_alert_id':})` — reuses the existing
auto-block-if-armed path (a confirmed chain is at least as
actionable as any single alert already routed there), reuses `emit_alert`
for the websocket broadcast (confirmed generic over `alert_type`, zero
websocket-layer changes needed), and reuses the `alerts` table (new
`alert_type` string, `String(50)` unconstrained — no schema change beyond
`raw_data`'s existing JSONB column). New
`correlation_scan_interval_s` constructor param, same threading pattern
as `block_expiry_check_interval_s`.

**Tests**: `tests/test_detection/test_correlation.py` (pure, seeds
in-memory `Alert`-shaped test doubles or a real DB session depending on
whether the query needs to run against Postgres JSONB — likely the
latter, following `test_rules_engine.py`'s real-Postgres integration
style) — covers: a matching pair produces exactly one incident; a pair
outside the time window doesn't; a second job run doesn't duplicate the
same pair; a different device's alerts don't cross-contaminate.

---

## #16 — Daily/weekly security digest notification

**`sentinel/db/models.py`**: `AppSettings.last_digest_sent_at: Mapped[datetime
| None]` (nullable, mirrors `baseline_established_at`'s exact shape/
semantics — `NULL` means "never sent yet"). New migration chained after
the others above (final head after this section).
**`SettingsRepository`**: `get_last_digest_sent_at`/`set_last_digest_sent_at`.

**`sentinel/config.py`**: new `SECURITY_DIGEST_CRON: str = '0 7 * * *'`
(daily 07:00 — admin can edit `.env` for weekly, e.g. `'0 7 * * 1'` for
Monday; follows the confirmed **env-only** convention every other cron
setting uses — none of the four existing cron jobs are
`SettingsRepository`-backed, so this doesn't break precedent).

**New cron job `_security_digest_job`** (`scheduler.py`, mirrors the
`add_job(self._x_job, CronTrigger.from_crontab(self._x_cron), id='x',
replace_existing=True)` shape used by all four existing cron jobs
verbatim): `cutoff = last_digest_sent_at or (now - one cron period,
approximated as 1 day)`; query mirrors `/api/alerts/grouped`'s aggregation
shape (`sentinel/api/routes/alerts.py:83-97` — `func.count()`/
`func.max(_SEVERITY_RANK)`/`group_by(Alert.severity, Alert.alert_type)`,
filtered `Alert.created_at >= cutoff`) to build: total count, counts by
severity, top alert types by count. Formats a flat multi-line summary
string (`NotificationService.notify()`'s contract is plain `title`+
`message` strings, no rich body) — sent **unconditionally** on every cron
fire, including a calmer "0 alerts, all clear" framing when the window is
empty (a home security tool's periodic "still watching, nothing to
report" is itself reassurance, not noise). Calls `self._notifier.notify(...)`
directly (confirmed already accessible, no `RuleEngine` indirection
needed — also confirmed this is the *first* mechanism that notifies for
every alert type uniformly, since today's live pings are `Rule`-gated).
Writes `last_digest_sent_at = now` via `SettingsRepository` after a
successful send.

**Tests**: `tests/test_scheduler/test_security_digest.py`, combining
`test_data_retention.py`'s real-`SentinelScheduler` construction with
`test_notifications/test_service.py`'s `_FakeAsyncClient`/`_FakeSMTP`
monkeypatch pattern (since the digest ultimately calls through
`notify()` → `_send_ntfy`/`_send_email`) — seeds `Alert` rows spanning
before/after a fake `last_digest_sent_at`, calls the job directly, asserts
the fake channel received a message with the expected counts and that
`last_digest_sent_at` advanced in the DB.

---

## Verification

- `python3 -m py_compile` on every new/changed file.
- New Alembic migrations (4: device block-expiry, device quarantine,
  app_settings auto_block_expiry, app_settings last_digest) applied in
  order against `sentinel_test`, `alembic upgrade head` then staged
  `downgrade`/`upgrade` to confirm reversibility, same as Section B's
  verification.
- Targeted test run: `pytest tests/test_scheduler/test_block_expiry.py
  tests/test_scheduler/test_security_digest.py
  tests/test_detection/test_correlation.py tests/test_adapter/test_xmo_adapter.py
  tests/test_scheduler/test_threat_auto_block.py tests/test_api/test_devices.py
  -q` against `sentinel_test` (`DATABASE_URL` + `JWT_SECRET_FILE` exported
  explicitly, per this session's established gotchas).
- Full `pytest tests/ -q` — expect only the same 5 pre-existing
  `test_data_retention.py` failures (unrelated `drop_chunks()` typing
  issue, present on `main`).
- Frontend `npm run lint && npm run build`.
- Manual, once live: confirm a quarantine rule's `Status` field and
  whether `DefaultPolicy` needs a one-time manual change in the router's
  own admin UI for quarantine to actually enforce (this item's real open
  question, deliberately left as a read-and-warn rather than an
  auto-write, same posture as Section B's unverified-xpath items).
