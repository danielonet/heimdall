# Section C: device-type-aware thresholds, active/passive OS cross-check, credential-exposure scans

*Saved from the plan-mode scratch file before starting Section B, whose
plan now occupies that same path. See `docs/zeek-clamav-implementation-plan.md`
for the note on why this file exists — same reason.*

## Context

`docs/capability-review.md` (this session) proposed three detector
improvements grouped as "new detection logic using data you already
collect (no new libraries)":

- **#10 Device-type-aware thresholds** — `HighUploadDetector`/
  `AnomalousVolumeDetector` use one flat threshold for every device, but
  `Device.device_type` (shipped a previous session) already tells us a lot:
  a NAS or IP camera legitimately sustains high upload; a printer or
  smartphone doing the same is much more suspicious.
- **#11 Active/passive OS-fingerprint cross-check** — nmap's active `-O`
  scan and `PassiveFingerprinter`'s passive TCP fingerprint both write to
  the *same* `Device.os_fingerprint` column today, silently clobbering each
  other with zero comparison. Comparing them is a free additional
  MAC-spoofing/misclassification signal from data already gathered nightly.
- **#12 Credential-exposure NSE scripts** — `NetworkScanner.vuln_scan()`
  already runs `--script vuln`; adding a curated default/blank-credential
  script set is a same-shape addition using infrastructure that already
  exists.

User confirmed: proceed with all three. Full research (subagent survey +
direct file reads) is already done; this plan captures the concrete design.

**Important correction from initial research**: `device_type` is *not* a
closed Python enum anywhere in the codebase — it's an open-ended string
straight from the router's DHCP-fingerprint database
(`sentinel/adapter/sagemcom/xmo_adapter.py:395`,
`DeviceSnapshot.device_type`, `sentinel/adapter/models.py:25`), blank when
unclassified. Any per-type table must be a dict keyed by observed strings
with a required default bucket — never an exhaustive switch.

---

## #10 — Device-type-aware thresholds

**New file `sentinel/detection/device_profiles.py`** — a plain dict lookup,
no new dependency:

```python
DEFAULT_PROFILE = {
    'high_upload_ratio_threshold': 3.0,       # HighUploadDetector.RATIO_THRESHOLD today
    'volume_sustained_polls': 3,              # AnomalousVolumeDetector.SUSTAINED_POLLS today
}

DEVICE_TYPE_PROFILES = {
    # NAS/cameras legitimately sustain high upload (backups, streaming out) —
    # raise the ratio threshold so that's not flagged as exfiltration.
    'Network Attached Storage': {'high_upload_ratio_threshold': 8.0, 'volume_sustained_polls': 5},
    'IP Camera':                {'high_upload_ratio_threshold': 10.0, 'volume_sustained_polls': 5},
    # Printers have almost no legitimate reason to sustain a high upload
    # ratio or unusual volume — tighten both.
    'Printer':                  {'high_upload_ratio_threshold': 2.0, 'volume_sustained_polls': 2},
    # Phones rarely sustain high uploads; slightly stricter than default.
    'Smartphone':                {'high_upload_ratio_threshold': 2.5},
}

def get_profile(device_type: str | None) -> dict:
    """Merges a device-type override onto DEFAULT_PROFILE — unknown/blank/
    unrecognized device_type values (an open string set, not an enum; see
    module docstring) fall back to DEFAULT_PROFILE untouched."""
    return {**DEFAULT_PROFILE, **DEVICE_TYPE_PROFILES.get(device_type or '', {})}
```

**`sentinel/detection/detectors/high_upload.py`**: replace the flat
`RATIO_THRESHOLD` read (line 54) with
`get_profile(snapshot.device_type)['high_upload_ratio_threshold']`. Keep the
module constant as `DEFAULT_PROFILE`'s source value (single source of
truth) — no other change to the streak/cooldown logic.

**`sentinel/detection/detectors/anomalous_volume.py`**: same idea — replace
the flat `SUSTAINED_POLLS` compare (line 84) with
`get_profile(snapshot.device_type)['volume_sustained_polls']`.

No constructor/pipeline changes needed — `snapshot.device_type` is already
passed into `inspect_traffic` on every call (confirmed:
`sentinel/scheduler/jobs.py`'s `_run_detection` passes the full
`DeviceSnapshot` from the same poll cycle), so this is a pure lookup, zero
new DB queries.

**Tests**: new `tests/test_detection/test_device_profiles.py` (pure
dict-merge tests). Extend `test_high_upload.py`/`test_anomalous_volume.py`
with a couple of device_type-parametrized cases (e.g. an IP Camera at 5:1
ratio does *not* fire where the default profile would; a Printer at the
same ratio *does* fire faster) — build via
`dataclasses.replace(_SNAPSHOT, device_type='...')`, existing blank-type
tests are untouched since blank device_type resolves to the same
`DEFAULT_PROFILE` values as today's constants (verified: no existing test
in either file references `device_type`, so nothing breaks).

---

## #11 — Active/passive OS-fingerprint cross-check

**New file `sentinel/security/os_classification.py`** — one pure function,
no new dependency:

```python
def os_family(os_string: str | None) -> str:
    """Coarse OS family bucket. Passive fingerprints are broad family
    strings ('Windows', 'Linux / Android', 'macOS / iOS' — see
    fingerprint.py's OS_SIGNATURES); nmap's osmatch name is much more
    specific ('Linux 3.10 - 4.11', 'Microsoft Windows 10 1607'). Comparing
    the raw strings directly would mismatch on nearly every scan; bucket
    both into the same coarse family first."""
    if not os_string:
        return 'unknown'
    s = os_string.lower()
    if 'unknown' in s:
        return 'unknown'
    if 'windows' in s:
        return 'windows'
    if 'mac' in s or 'ios' in s or 'darwin' in s:
        return 'macos_ios'
    if 'linux' in s or 'android' in s:
        return 'linux_android'
    return 'other'
```

**`sentinel/scheduler/scheduler.py`'s `_nmap_scan_job`** (currently lines
299-360): capture the device's existing (passive) `os_fingerprint` *before*
it gets overwritten by the nmap result, then compare families after the
session block closes (mirrors `_persist_fingerprint`'s existing
capture-then-alert-outside-the-session shape):

```python
async with get_session() as session:
    device = await session.get(Device, mac)
    if device is not None:
        previous_passive_os = device.os_fingerprint
        device.nmap_profile = profile
        if scan.os != 'Unknown':
            device.os_fingerprint = scan.os
    else:
        previous_passive_os = None

if scan.os != 'Unknown' and previous_passive_os:
    passive_family = os_family(previous_passive_os)
    active_family = os_family(scan.os)
    if passive_family != 'unknown' and active_family != 'unknown' and passive_family != active_family:
        await self._raise_threat_alert(
            mac, 'OS_FINGERPRINT_CONFLICT', 'WARNING',
            f'{ip} was passively fingerprinted as "{previous_passive_os}" but nmap\'s '
            f'active scan identifies it as "{scan.os}" — possible MAC spoofing or misclassification',
            raw_data={'ip': ip, 'passive_os': previous_passive_os, 'active_os': scan.os},
        )
```

New alert type `OS_FINGERPRINT_CONFLICT` (doesn't collide with the existing
`FINGERPRINT_MISMATCH`, which is passive-vs-its-own-earlier-passive-reading
only — this is active-vs-passive). Severity `WARNING` (a heuristic
family-bucket comparison, weaker confidence than a confirmed
`ARP_SPOOF`/`HIGH_RISK_PORT_OPENED`), matching this codebase's existing
severity convention. Fires every nightly scan while the conflict persists —
same precedent as `VULNERABILITY_DETECTED` (no extra dedup state); nightly
cadence keeps volume low regardless, unlike the 15s-interval flood bug
fixed earlier this session.

Note: `_raise_threat_alert` applies `auto_block_on_threat` uniformly to
every alert type that goes through it — there's no existing per-alert-type
opt-out, so this will auto-block too if the admin has that armed, same as
every other alert. Flagging this rather than silently changing that shared
method's behavior.

**Tests**: new `tests/test_security/test_os_classification.py` (pure
function). New `tests/test_scheduler/test_nmap_scan_job.py` using the
`object.__new__(SentinelScheduler)` pattern already established in
`test_threat_auto_block.py`, with a fake `_scanner` (canned `ScanResult` +
canned `credential_scan`/`vuln_scan` dicts) — covers: conflict fires when
families differ, no alert when they agree or either side is
unknown/blank, and confirms existing `HIGH_RISK_PORT_OPENED`/
`VULNERABILITY_DETECTED` behavior in this same function is untouched
(regression safety since this edits a function with no prior direct test
coverage).

---

## #12 — Credential-exposure NSE scripts

**`sentinel/security/scanner.py`**: new method pair mirroring
`vuln_scan`/`_vuln_scan_sync` exactly (same empty-dict-on-failure
contract, same `self._nm.scan(...)` + `host.get('script', {})` parsing —
confirmed this is a pure drop-in, python-nmap parses NSE output generically
regardless of which scripts ran):

```python
async def credential_scan(self, ip: str) -> dict:
    """NSE default/blank-credential scripts — kept separate from
    vuln_scan() so a CVE finding and a default-password finding aren't
    conflated under one alert type."""
    try:
        return await asyncio.to_thread(self._credential_scan_sync, ip)
    except Exception as exc:
        logger.warning('nmap credential scan failed for %s: %s', ip, exc)
        return {}

def _credential_scan_sync(self, ip: str) -> dict:
    self._nm.scan(ip, arguments='--script default-accounts,http-default-accounts,ftp-anon,mongodb-info,mysql-empty-password')
    if ip not in self._nm.all_hosts():
        return {}
    return self._nm[ip].get('script', {})
```

**`sentinel/scheduler/scheduler.py`'s `_nmap_scan_job`**: alongside the
existing `vuln_scan` call, add:

```python
credential_findings = await self._scanner.credential_scan(ip)
if credential_findings:
    await self._raise_threat_alert(
        mac, 'CREDENTIAL_EXPOSURE_DETECTED', 'CRITICAL',
        f'nmap credential scan flagged {ip}: {", ".join(credential_findings.keys())}',
        raw_data={'ip': ip, 'findings': credential_findings},
    )
```

Severity `CRITICAL` — default/blank credentials are a severe, directly
actionable exposure, matching `VULNERABILITY_DETECTED`'s precedent. This
doubles nmap's NSE-script runtime per device on the nightly job (two
`--script` invocations instead of one) — acceptable for an off-hours
cron on a home LAN, not worth the complexity of combining into one
invocation just to save nightly scan time.

**Tests**: extend `tests/test_security/test_scanner.py` with
`credential_scan`/`_credential_scan_sync` tests mirroring the existing
`vuln_scan` success/failure-path tests (`_FakePortScanner`/`_FakeHost`
pattern already established there). Extend the new
`test_nmap_scan_job.py` (from #11) to also cover
`CREDENTIAL_EXPOSURE_DETECTED` firing/not-firing.

---

## Verification

- `python3 -m py_compile` on every new/changed file.
- Full targeted test run first: `pytest tests/test_detection/ tests/test_security/test_scanner.py tests/test_security/test_os_classification.py tests/test_scheduler/test_nmap_scan_job.py -q` against `sentinel_test` (never the live `sentinel` DB — `DATABASE_URL` must be explicitly exported for `sentinel_test`, and `JWT_SECRET_FILE` must be exported too, per this session's established gotchas).
- Then full `pytest tests/ -q` to confirm no regressions elsewhere (the same 5 pre-existing `test_data_retention.py` failures from earlier this session — an unrelated asyncpg/TimescaleDB `drop_chunks()` typing issue — are expected and not something this change touches).
- No frontend changes in this plan, so no lint/build step needed.

---

**Status: fully implemented and verified this session** — see
`sentinel/detection/device_profiles.py`, `sentinel/security/os_classification.py`,
`sentinel/security/scanner.py`'s `credential_scan`, and
`sentinel/scheduler/scheduler.py`'s `_nmap_scan_job`. All items marked
done in `docs/capability-review.md`.
