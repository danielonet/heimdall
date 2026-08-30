# Detection Pipeline

> Rewritten from scratch against the actual code (2026-08-22). The previous
> version was a design-era sketch — most of the detector classes it listed
> (`off_hours.py`, `port_active.py`, `broadcast_storm.py`, `wan_outage.py`,
> `radio_error.py`, and others) were never built, and several that *were*
> built aren't shaped the way it described. Everything below is sourced
> directly from `sentinel/detection/`, `sentinel/scheduler/scheduler.py`,
> and `sentinel/security/` — file/line references throughout, not
> aspirational descriptions.

## Three shapes of detection, not one

CLAUDE.md rule 3 says every detector subclasses `BaseDetector` — that's true
for the per-device/per-traffic-sample ML and heuristic checks, but it isn't
the whole detection system. There are three genuinely different shapes here,
each used where it fits:

1. **`BaseDetector` pipeline** (`sentinel/detection/pipeline.py`) — one
   `inspect_device`/`inspect_traffic` call per detector per event, every poll
   cycle. For heuristic/probabilistic signals worth a human's judgment
   (anomalous traffic, RSSI shifts, vendor mismatches) — **never** auto-blocks.
2. **Standalone classes invoked directly from a scheduler job**, outside the
   pipeline, for checks that don't fit the per-device shape at all:
   `WanBandwidthDetector` (household-level, no device to key on),
   `CrossAlertCorrelator` (a lookback over *persisted* alert rows, not a live
   event), `DeviceIdentityLinker` (a lookback over persisted `devices` rows).
3. **Attack-signal sources routed through `SentinelScheduler._raise_threat_alert`**
   — packet/log-driven findings (ARP spoofing, rogue DHCP, port scans, DNS/
   beaconing/malware, IDS signatures, honeypot hits) that represent a
   *confirmed* attack rather than a statistical judgment call. This is the
   one path that can auto-block a device.

The rest of this doc covers each in turn, then gives the full alert-type
registry across all three.

## 1. The `BaseDetector` pipeline

### Base class — `sentinel/detection/detectors/base.py`

```python
class BaseDetector(ABC):
    enabled: bool = True
    severity: str = 'INFO'   # INFO | WARNING | CRITICAL

    @abstractmethod
    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        """Called for every DeviceSnapshot in a poll cycle."""

    @abstractmethod
    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        """Called for every per-device TrafficSample.

        Only called for TrafficGranularity.PER_DEVICE samples with a
        matching DeviceSnapshot — wired PER_PORT samples carry a port
        alias, not a device MAC, and per
        docs/router/wired-monitoring-caveat.md must not be attributed to a
        single device.
        """
```

The pipeline itself is stateless — any state a detector needs across polls
(rolling windows, last-seen baselines) is the detector's own responsibility,
kept in-memory or read back from PostgreSQL.

### Pipeline runner — `sentinel/detection/pipeline.py`

```python
class DetectionPipeline:
    def __init__(self, detectors: list[BaseDetector]) -> None:
        self._detectors = [d for d in detectors if d.enabled]

    async def process_device(self, snapshot: DeviceSnapshot) -> list[Alert]:
        # runs inspect_device() on every enabled detector, collects non-None results
        ...

    async def process_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> list[Alert]:
        # same, for inspect_traffic()
        ...
```

`create_default_pipeline(anomaly_engine)` builds the live instance and must
be given the *same* `AnomalyEngine` the scheduler uses to score
`traffic_samples.anomaly_score` — a separate engine would have empty
buffers/models and never fire.

### Registered detectors

| Class | File | Alert type(s) | Severity | Trigger |
|-------|------|---------------|----------|---------|
| `NewDeviceDetector` | `new_device.py` | `NEW_DEVICE` | CRITICAL | A device actually connects (`is_online=True`) for the first time ever (`has_connected_before` is false) and isn't in the persistent `trusted_macs` registry. Deliberately ignores devices the router's Hosts/AssociatedDevices tables merely *mention* without a real connection. |
| `HighUploadDetector` | `high_upload.py` | `HIGH_UPLOAD` | WARNING | Upload/download ratio exceeds a device-type-aware threshold (`device_profiles.get_profile()`, default 3.0×) for `volume_sustained_polls` consecutive polls (default 3). Ignores samples under `MIN_BYTES_TO_EVALUATE` (10 000 bytes) as idle noise. |
| `VendorMismatchDetector` | `vendor_mismatch.py` | `VENDOR_MISMATCH` (WARNING) / `VENDOR_UNVERIFIED` (INFO) | WARNING / INFO | Hostname strongly implies a vendor (`_HOSTNAME_VENDOR_HINTS`, e.g. `iphone`→apple) the router's OUI lookup either contradicts (`VENDOR_MISMATCH`) or can't resolve at all (`VENDOR_UNVERIFIED` — also the case for a legitimately randomized MAC, so treated as a weaker signal). |
| `SignalAnomalyDetector` | `signal_anomaly.py` | `SIGNAL_ANOMALY` | WARNING | A WiFi device's RSSI shifts more than `RSSI_DELTA_THRESHOLD_DBM` (15 dBm) from its tracked baseline and holds for `SUSTAINED_POLLS` (2) consecutive polls. Suppressed during the learning window (no baseline yet to judge against). |
| `AnomalousVolumeDetector` | `anomalous_volume.py` | `ANOMALOUS_VOLUME` | WARNING | Both the per-device IsolationForest *and* LOF models agree a PER_DEVICE traffic sample is an outlier, sustained for `volume_sustained_polls` consecutive samples (device-type-aware, same profile row `HighUploadDetector` reads). Suppressed during `ml_learning_period_hours` after a device's `first_seen`. See `docs/architecture/05-ml-anomaly-engine.md`. |
| `AccessPointCrossingDetector` | `ap_crossing.py` | `AP_TRUST_CROSSING` | WARNING (private→guest) / CRITICAL (guest→private) | A WiFi device's AP association crosses the guest/private trust boundary since its last persisted poll. Plain band-hopping within the same tier (`PRIV0`↔`VID1`, `GUEST2G`↔`GUEST5G`) does **not** fire — only a tier crossing does, since the guest→private direction implies unexplained access escalation. |

All six are wired into `create_default_pipeline()`
(`sentinel/detection/pipeline.py`) in that order. `HighUploadDetector` and
`AnomalousVolumeDetector` both read their thresholds from
`sentinel/detection/device_profiles.py`'s `DEFAULT_PROFILE` (overridable per
`device_type` via the admin-editable `device_type_profiles` table — see the
Settings page):

```python
DEFAULT_PROFILE = {
    'high_upload_ratio_threshold': 3.0,
    'volume_sustained_polls': 3,
    'contamination': 0.05,
}
```

**Dedup pattern, shared by every detector above**: rather than a cooldown
timer, a still-true condition bumps the same open alert's
`occurrence_count` via `AlertRepository.upsert()` instead of flooding a
fresh row every poll — each detector's own job is just to notice when the
condition starts and stops being true, and call `resolve()` on the latter.
This exists because the naive version was measured in production: one
device produced 1,885 near-duplicate `HIGH_UPLOAD` alerts over 4 days, and
another produced 21 `SIGNAL_ANOMALY` alerts in about an hour while its RSSI
oscillated across the threshold repeatedly.

## 2. Standalone classes, invoked directly from a scheduler job

These don't fit `BaseDetector`'s per-event shape, so — per each class's own
docstring — they're deliberately kept outside the pipeline rather than
forced into an interface that doesn't match what they actually check.

| Class | File | Alert type | Why not `BaseDetector` |
|-------|------|-------------|------------------------|
| `WanBandwidthDetector` | `wan_bandwidth.py` | `WAN_BANDWIDTH_SPIKE` (WARNING) | Household-total WAN throughput has no device to key on or auto-block — `inspect_traffic(sample, snapshot)` is inherently per-device-shaped. Called directly from `poll_cycle()` (`sentinel/scheduler/jobs.py`) alongside the pipeline; flags total up+down throughput more than `STDDEV_MULTIPLIER` (3.0) standard deviations above a rolling `WINDOW_SIZE`-poll (20, ~5 min) mean, sustained for `SUSTAINED_POLLS` (2) polls. |
| `CrossAlertCorrelator` | `correlation.py` | `COMPROMISE_CHAIN_DETECTED` (CRITICAL) | A windowed lookback over *persisted* `Alert` rows, not a live per-event check — queries the `alerts` table directly on its own schedule (`SentinelScheduler._correlation_job`, hourly-class cadence) rather than hooking any single alert-creation path, since alerts are created from several different places (see the registry below) and a correlator watching only one would miss the others. Recognizes a small, curated set of `CORRELATION_PATTERNS` (e.g. `NEW_DEVICE_THEN_SPOOFING`: a `NEW_DEVICE` followed within 60 minutes by `ARP_SPOOF`/`FINGERPRINT_MISMATCH`/`OS_FINGERPRINT_CONFLICT`) and escalates a match to one `COMPROMISE_CHAIN_DETECTED` incident, itself routed through `_raise_threat_alert` (so it's auto-block-eligible like any other confirmed finding). |
| `DeviceIdentityLinker` | `device_identity.py` | `DEVICE_IDENTITY_LINKED` (INFO) | Recognizes when several `devices` rows sharing one hostname are almost certainly the same physical device that reconnected under a fresh randomized WiFi MAC (Apple Private Wi-Fi Address / Android randomized-per-network, both on by default). Narrow, deliberately conservative match: non-blank byte-identical hostname, exactly one candidate ARP-reachable, device row under 24h old. Second, independent path (`find_ip_continuity_candidates`, confirmed live 2026-08-30) for a rotated MAC that never reported a hostname at all, so the hostname rule can never match it: proposes a link when a hostname-having device's on-file IP is also the on-file IP of a fresh, hostname-less, locally-administered MAC — bounded only by the *old* side's `_LOOKBACK_HOURS` (24h) via `last_seen`, deliberately not by the new MAC's `first_seen`/recency (an earlier version tried that and broke silently on a devices table seeded in bulk, where every row shares one ancient `first_seen` regardless of how many times it's rotated in since) — confirmed before linking by `ArpLivenessProbe.resolve_mac(ip)` (not just `is_reachable`, since both DB rows share the same on-file IP and "is it reachable" can't tell the two apart). Invoked by `SentinelScheduler._identity_link_job`; a successful link (either path) also auto-resolves the old MAC's open `NEW_DEVICE` alert and the new MAC's open `ARP_SPOOF` alert, and propagates a block via `_propagate_block_after_link` if the old MAC was blocked. |
| `SentinelScheduler._reconcile_block_enforcement` | `scheduler.py` | `BLOCK_ENFORCEMENT_DRIFT` (WARNING/INFO) | Confirmed live 2026-08-30: `devices.is_blocked` is only Heimdall's memory of what it *asked* the router to do, not a live read of what's actually enforced — and the two can drift (a blocked device's MAC rotates and the new MAC starts fresh/unblocked at the router; an admin blocks or unblocks a device directly via the router's own admin UI, outside Heimdall entirely). Every poll cycle (rate-limited to `BLOCK_ENFORCEMENT_RECONCILE_INTERVAL_S`, 5 min), compares `devices.is_blocked` against each Host's live `BlacklistStatus` (from the same `get_connected_devices()` call `poll_cycle` already makes — usually a cache hit, no extra router traffic). **The router is the source of truth in both directions** — `_correct_block_drift` only ever updates Heimdall's own record to match, never calls `block_device()`/`unblock_device()` to push Heimdall's belief back onto the router (WARNING for DB-blocked-but-router-clear, INFO for the reverse). Changed from an earlier, asymmetric version that re-issued the block on the DB-blocked-but-router-clear side — confirmed live this fought a deliberate, out-of-band admin unblock, since there is no way to tell "the block silently decayed" apart from "an admin reversed it on purpose" from in here. A MAC the router has no live Host entry for at all this cycle is skipped, not treated as confirmed either way. |

## 3. Confirmed-attack sources — `SentinelScheduler._raise_threat_alert`

Every packet- or log-driven finding below is a *confirmed* attack signal
(not a statistical judgment call), so this is the one path in the system
that can auto-block a device. All of them funnel through one method,
`SentinelScheduler._raise_threat_alert()` (`sentinel/scheduler/scheduler.py`),
regardless of which watcher produced the finding:

- If `AppSettings.auto_block_on_threat` is armed, blocks the device via the
  router adapter **before** persisting the alert, so the alert description
  can note the outcome (`— device auto-blocked` / `— AUTO-BLOCK FAILED,
  device is still on the network`). Never silently swallows a failed block.
- Always re-issues the block even if `Device.is_blocked` is already `True`
  — that flag is only a cache of the last known outcome; trusting it to
  skip re-blocking let a real attack through once already in production.
  `adapter.block_device()` is idempotent, so there's no cost to this.
- Every successful auto-block (re-)stamps `blocked_at`/`blocked_until` from
  `auto_block_expiry_hours` (0 = never expires) — a fresh threat always
  resets the expiry clock. Manual blocks never go through this method, so
  `blocked_until` stays `NULL` for them (indefinite by design).
- **Never blocks the machine Heimdall itself runs on** (`_is_own_host()`) —
  guards against a false positive (confirmed case: a Zeek beaconing
  detector once misread Heimdall's own nmap scan traffic as C2 beaconing)
  cutting the security tool off its own network. The alert still fires;
  only the block is suppressed.
- Stamps `Alert.mitigation` with canned "what to do about this" guidance
  via `build_mitigation()` (`sentinel/security/remediation.py`) for every
  alert type it recognizes (the full list below); `None` otherwise.
- Persists via `AlertRepository.upsert()` — none of these sources have a
  natural "this stopped" signal (a packet or log line, not a poll-driven
  condition), so nothing here ever calls `resolve()`; only the
  `alert_auto_resolve` sweep job (default 72h) closes them.

| Watcher / source | File | Job / method | Alert type | Severity |
|---|---|---|---|---|
| `ArpWatcher` | `sentinel/security/arp_watch.py` | `_persist_arp_alert` | `ARP_SPOOF` (untrusted MAC, and the router's own live DHCP leases don't confirm the reassignment either — see `_verify_arp_change_against_dhcp`) / `IP_CONFLICT` (INFO — the new MAC is already trusted, more likely two devices sharing a static IP than an attack) / no alert at all (untrusted MAC, but a live DHCP-leases re-poll confirms it's a legitimate reassignment) | CRITICAL / INFO / — |
| `DhcpWatcher` | `sentinel/security/dhcp_watch.py` | `_persist_dhcp_alert` | `ROGUE_DHCP_SERVER` | CRITICAL |
| `PassiveFingerprinter` | `sentinel/security/fingerprint.py` | `_persist_fingerprint` | `FINGERPRINT_MISMATCH` | CRITICAL |
| `NetworkScanner` (nmap) | `sentinel/security/scanner.py` | `_nmap_scan_job` | `HIGH_RISK_PORT_OPENED`, `OS_FINGERPRINT_CONFLICT`, `VULNERABILITY_DETECTED`, `CREDENTIAL_EXPOSURE_DETECTED` | CRITICAL / WARNING / CRITICAL / CRITICAL |
| Zeek DNS log + `ThreatIntelService` | `sentinel/security/zeek_parser.py` | `_zeek_dns_poll_job` → `_persist_dns_query` | `DNS_MALICIOUS_QUERY` (query matches the URLhaus feed) | CRITICAL |
| Zeek conn.log beaconing scan | `sentinel/security/zeek_parser.py` | `_zeek_beacon_scan_job` | `C2_BEACONING` | CRITICAL |
| Zeek conn.log + threat intel (spike enrichment) | — | `_spike_ip_enrichment_job` | `MALICIOUS_TRAFFIC_DESTINATION` — a separate finding from `C2_BEACONING`, for a device's spike-flagged destination IP matching threat intel outside the beaconing pattern itself | CRITICAL |
| Zeek file-extraction + ClamAV | `sentinel/security/clamav_scanner.py` | `_zeek_file_scan_job` | `MALWARE_DETECTED` | CRITICAL |
| Suricata EVE JSON | `sentinel/security/suricata_parser.py` | `_suricata_poll_job` → `_persist_suricata_alert` | `IDS_SIGNATURE_MATCH` | mapped from the rule's own severity |
| `OpenCanaryIngester` | `sentinel/security/canary.py` | `_canary_poll_job` → `_persist_canary_alert` | `HONEYPOT_ACCESS` | CRITICAL |

`build_mitigation()`'s dispatch table (`sentinel/security/remediation.py`)
covers exactly this set of alert types plus `COMPROMISE_CHAIN_DETECTED`.

## The rule engine — `sentinel/detection/rules_engine.py`

User-defined rules (the `rules` table) are evaluated by `RuleEngine`
alongside the `BaseDetector` pipeline — a fourth path, but one whose
conditions are admin-authored data rather than code. `HIGH_RISK_PORTS`-style
"curated data, not a UI for authoring an open-ended language" doesn't apply
here; this genuinely is a small condition/action DSL, stored as JSON:

```json
// condition_json
{
  "trigger": "TRAFFIC_SAMPLE",
  "field": "throughput_up_kbps",
  "op": "GT",
  "value": 5120,
  "window_polls": 3
}
// action_json
{
  "type": "BLOCK_DEVICE",
  "notify": true,
  "severity": "CRITICAL",
  "tag": "flagged",
  "minutes": 30
}
```

- `trigger`: `TRAFFIC_SAMPLE` or `DEVICE_SNAPSHOT` — which event this rule
  watches. Lives inside `condition_json` (there's no separate `trigger`
  column on the `rules` table).
- `op`: `GT | LT | GTE | LTE | EQ | NEQ | CONTAINS | IN`.
- `window_polls` (optional, default 1): must match this many consecutive
  polls before firing.
- `action.type`: `ALERT | BLOCK_DEVICE | NOTIFY | TAG_DEVICE | RATE_LIMIT`.
  `notify` optionally sends a push/email regardless of type; `tag`/`minutes`
  are `TAG_DEVICE`/`RATE_LIMIT`-only.

A firing rule persists `alert_type='RULE_TRIGGERED'`, deduped by
`dedup_key=f'rule:{rule.id}'` — guarded so a pair that's never seen the
condition clear doesn't get a redundant `resolve()` call.

## Reference-only: observed extremes

`sentinel/detection/observed_extremes.py` doesn't produce alerts at all —
it computes, per `device_type`, the most extreme ratio/sustained-polls/
contamination values ever actually recorded on this network, refreshed
hourly by `SentinelScheduler._observed_extremes_job`. Purely a reference
tool surfaced on the Device Type Profiles settings screen, so tuning a
profile is based on this network's real measurements rather than a guess.

## Full alert-type registry

| Alert type | Source | Severity | Auto-block eligible? |
|---|---|---|---|
| `NEW_DEVICE` | `NewDeviceDetector` | CRITICAL | No (pipeline) |
| `HIGH_UPLOAD` | `HighUploadDetector` | WARNING | No (pipeline) |
| `VENDOR_MISMATCH` / `VENDOR_UNVERIFIED` | `VendorMismatchDetector` | WARNING / INFO | No (pipeline) |
| `SIGNAL_ANOMALY` | `SignalAnomalyDetector` | WARNING | No (pipeline) |
| `ANOMALOUS_VOLUME` | `AnomalousVolumeDetector` | WARNING | No (pipeline) |
| `AP_TRUST_CROSSING` | `AccessPointCrossingDetector` | WARNING / CRITICAL | No (pipeline) |
| `WAN_BANDWIDTH_SPIKE` | `WanBandwidthDetector` | WARNING | No (`device_mac=None`, household-level) |
| `COMPROMISE_CHAIN_DETECTED` | `CrossAlertCorrelator` | CRITICAL | **Yes** (routed through `_raise_threat_alert`) |
| `DEVICE_IDENTITY_LINKED` | `DeviceIdentityLinker` | INFO | No — but if the old MAC was blocked, `_propagate_block_after_link` re-issues `block_device()` against the new MAC directly, since a link alone doesn't carry enforcement over |
| `BLOCK_ENFORCEMENT_DRIFT` | `SentinelScheduler._reconcile_block_enforcement` | WARNING / INFO | No — the router is the source of truth for this one, so Heimdall's own record is updated instead of ever re-asserting a block/unblock |
| `RULE_TRIGGERED` | `RuleEngine` | admin-configured (default WARNING) | Only if the rule's own `action.type` is `BLOCK_DEVICE` |
| `ARP_SPOOF` | `ArpWatcher` | CRITICAL | **Yes** |
| `IP_CONFLICT` | `ArpWatcher` (trusted-MAC downgrade) | INFO | No |
| `ROGUE_DHCP_SERVER` | `DhcpWatcher` | CRITICAL | **Yes** |
| `FINGERPRINT_MISMATCH` | `PassiveFingerprinter` | CRITICAL | **Yes** |
| `HIGH_RISK_PORT_OPENED` | `NetworkScanner` | CRITICAL | **Yes** |
| `OS_FINGERPRINT_CONFLICT` | `NetworkScanner` | WARNING | **Yes** |
| `VULNERABILITY_DETECTED` | `NetworkScanner` | CRITICAL | **Yes** |
| `CREDENTIAL_EXPOSURE_DETECTED` | `NetworkScanner` | CRITICAL | **Yes** |
| `DNS_MALICIOUS_QUERY` | Zeek DNS + threat intel | CRITICAL | **Yes** |
| `C2_BEACONING` | Zeek conn.log | CRITICAL | **Yes** |
| `MALICIOUS_TRAFFIC_DESTINATION` | Zeek + threat intel (spike enrichment) | CRITICAL | **Yes** |
| `MALWARE_DETECTED` | Zeek file-extraction + ClamAV | CRITICAL | **Yes** |
| `IDS_SIGNATURE_MATCH` | Suricata | rule-mapped | **Yes** |
| `HONEYPOT_ACCESS` | OpenCanary | CRITICAL | **Yes** |
| `AUTO_BLOCK_EXPIRED` | `_block_expiry_job` (informational, device unblocked) | INFO | No |

"Auto-block eligible" means routed through `_raise_threat_alert` while
`auto_block_on_threat` is armed — it's a global setting, not per-alert-type,
so every "Yes" row above shares the same on/off switch.
