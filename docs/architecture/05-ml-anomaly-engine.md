# ML Anomaly Engine

This document describes the real, current implementation — not an aspirational
design. Where a past version of this page described behavior that diverged
from the code, that's called out explicitly, because the divergence itself
(and the production incidents that caused it) explains *why* the current
design looks the way it does.

## Main principles

1. **One model per device, not global.** A camera uploading 500 KB/s might be
   normal for that camera and highly anomalous for a door intercom. Comparing
   every device against one shared threshold produces exactly that kind of
   false positive — so `AnomalyEngine` keeps a fully independent
   `IsolationForest` + `LOF` pair per MAC address, with no cross-device
   sharing at all (`sentinel/ml/anomaly_engine.py`).

2. **Two models must agree.** `IsolationForest` and PyOD's `LOF` are AND'd
   together — a sample only counts as anomalous if *both* flag it. This alone
   isn't enough to stop noisy alerts (see "Two production incidents" below),
   but it cuts the false-positive rate a single model would have.

3. **Contamination is a rate, not a rarity cutoff — and that has a real
   consequence.** `IsolationForest(contamination=X)` calibrates its decision
   boundary so that *X proportion* of the training data scores as an outlier,
   by construction. A device with a recurring-but-infrequent legitimate
   pattern (a phone doing a video call most evenings) that consistently makes
   up roughly a fixed *share* of its samples will keep tripping that boundary
   indefinitely — nightly retraining refits on fresh data, but doesn't fix
   this, because the *proportion* the pattern occupies doesn't shrink over
   time. This is why contamination is now configurable per device type (see
   "Layer 3" below) instead of one number for every device.

4. **A confirmed detection needs to be sustained, not momentary.** Even a
   correctly-calibrated model with `contamination=0.05` is *designed* to flag
   ~5% of samples. At a 15s poll interval that's roughly one flagged sample
   every 5 minutes per device from statistical noise alone. `AnomalousVolumeDetector`
   (not the ML engine itself — see "Where the ML engine's output is
   consumed" below) requires several consecutive flagged polls plus a cooldown
   before it actually raises an alert.

5. **Detectors, not the engine, decide what to do with a score.** `AnomalyEngine`
   only answers "is this sample anomalous" (and, separately, "how anomalous").
   It never raises alerts, applies cooldowns, or knows about device types —
   that logic lives entirely in `sentinel/detection/detectors/anomalous_volume.py`.

## Two production incidents that shaped this design

Both are referenced directly in code comments — they're not hypothetical:

- **68,000 alerts in 4 days.** An earlier version compared IsolationForest's
  raw, uncalibrated `score_samples()` against a fixed constant (`-0.1`) shared
  across every device. `score_samples()`'s scale is specific to each fitted
  model's own training distribution and isn't comparable across devices or to
  a fixed threshold — a low-variance/idle device's typical, repeated samples
  scored well past that arbitrary cutoff, so it was flagged anomalous on
  almost every poll. Fixed by switching to `decision_function()` (which *is*
  calibrated to the contamination rate, `decision_function() == score_samples() - offset_`)
  compared against `ANOMALY_THRESHOLD = 0.0`, the boundary that calibration
  actually means.
- **A flat/idle device flooding identical alerts forever.** A model fit on
  constant throughput (a data source that always reads 0, or a genuinely idle
  device) has no real signal to learn from — IsolationForest/LOF trained on
  it end up flagging every future sample, including exact repeats, as an
  outlier. `AnomalyEngine._fit_and_save()` now detects near-zero variance in
  the throughput features before fitting and skips training entirely,
  retrying once traffic actually varies, rather than persisting a model that
  would flood alerts.

## Feature vector — `sentinel/ml/feature_builder.py`

Each `TrafficSample` becomes a 6-dimensional vector:

```python
FEATURE_NAMES = [
    'throughput_up_kbps',      # upload speed
    'throughput_dn_kbps',      # download speed
    'upload_download_ratio',   # up/down — high sustained ratio = possible exfil
    'hour_of_day',              # 0-23 — catches off-hours activity
    'day_of_week',               # 0-6 (Mon=0)
    'is_night',                  # 1 if 22:00-06:00, else 0
]
```

Absolute throughput values are only meaningful relative to that one device's
own history — this is why per-device models matter (principle 1). The
hour/day/is_night features give the model *some* diurnal awareness within a
single flat model; there's no separate model per time-of-day (see "Not
pursued" below).

## Anomaly engine — `sentinel/ml/anomaly_engine.py`

```python
class AnomalyEngine:
    def __init__(self, model_store, min_samples, contamination, magnitude_multiplier=0.5):
        ...

    def score(self, sample) -> float:
        """decision_function() value once trained; 0.0 during bootstrap."""

    def is_anomalous(self, sample) -> bool:
        """Both models agree AND the score clears the magnitude bar (see below)."""

    def train(self, mac) -> None:
        """Bootstrap fit, from the in-memory buffer, at the global default contamination."""

    def retrain_from_history(self, mac, feature_vectors, contamination=None) -> None:
        """Nightly refit; contamination overridable per call — see Layer 3."""
```

| Constant/param | Value | Configurable? |
|---|---|---|
| `ANOMALY_THRESHOLD` | `0.0` (on `decision_function()`, not `score_samples()`) | No — tied to calibration, see incident #1 above |
| `min_samples` (`ML_MIN_SAMPLES_TO_TRAIN`) | 100 (~25 min at the default poll interval) | Env var |
| `contamination` (`ML_CONTAMINATION`) | 0.05 global default | Env var globally; **per-device-type on nightly retrain**, see Layer 3 |
| `magnitude_multiplier` (`ML_ANOMALY_MAGNITUDE_MULTIPLIER`) | 0.5 | Env var, see Layer 2 |
| LOF `n_neighbors` | `min(20, max(len(X)//5, 1))` | No — derived from sample count |
| `IsolationForest(n_estimators=100, random_state=42)` | fixed | No |

## Where the ML engine's output is consumed

`AnomalyEngine` itself never raises an alert. Two callers consume its output,
each owning its own alerting policy:

- **`sentinel/scheduler/jobs.py`'s `_score_traffic_samples`** calls
  `engine.score()` for every `PER_DEVICE` traffic sample each poll (PER_PORT
  samples are skipped — port-level counters are too noisy to attribute to one
  device) and persists the result to `traffic_samples.anomaly_score` — purely
  informational, drives the device-detail traffic chart.
- **`sentinel/detection/detectors/anomalous_volume.py`'s `AnomalousVolumeDetector`**
  calls `engine.is_anomalous()` and is the only thing that turns a
  flagged sample into an `ANOMALOUS_VOLUME` alert. It:
  1. Suppresses everything for `SettingsRepository.get_ml_learning_period_hours()`
     (default 72h) after a device's `first_seen` — a model trained on as few
     as `ML_MIN_SAMPLES_TO_TRAIN` samples has only seen a narrow slice of a
     device's real behavior and would flood alerts for normal variation it
     hasn't learned yet.
  2. Requires a streak of consecutive flagged polls (`volume_sustained_polls`,
     device-type-aware — see Layer 1) before alerting, resetting on any
     non-flagged poll in between.
  3. Applies a fixed 30-minute per-device cooldown after firing.

`HighUploadDetector` (`sentinel/detection/detectors/high_upload.py`) is a
**separate, non-ML** detector — a plain upload:download ratio check with its
own device-type-aware threshold and its own (non-device-type-aware) 3-poll
sustain + 30-minute cooldown. It shares the device-type profile table with
`AnomalousVolumeDetector` (see Layer 1) but doesn't touch `AnomalyEngine` at
all.

## Model persistence — `sentinel/ml/model_store.py`

`ModelStore` is a thin `joblib.dump`/`load` wrapper, one file per MAC
(`{mac}.joblib` under `Settings.ML_MODEL_DIR`, a Docker volume so models
survive container restarts). It persists whatever dict `AnomalyEngine` hands
it — currently `{'iso': ..., 'lof': ..., 'score_std': ...}` — with no fixed
schema, which is exactly what let Layer 2 add a new key without a migration
of existing on-disk models (see below).

## Model lifecycle

| Stage | Trigger | Contamination used |
|---|---|---|
| Bootstrap (< `min_samples`) | Every poll, in-memory buffer | n/a |
| Initial (bootstrap) training | `min_samples`th sample, inline in the poll loop | Engine's global default — see Layer 3 for why |
| Scoring | Every poll, `PER_DEVICE` samples only | n/a |
| Nightly retraining | `ML_RETRAIN_CRON` (default 03:00), `ModelTrainer.retrain_all()` | Device-type-specific — see Layer 3 |
| Container restart | Startup | Models loaded from `ML_MODEL_DIR` — no retraining needed |

## Reducing alert noise: three layers on top of the base engine

These were added specifically to address a phone (or similar bursty device)
that's normally idle and then briefly does something data-heavy, reliably
tripping `ANOMALOUS_VOLUME` every single time.

### Layer 1 — admin-editable per-device-type profiles

`sentinel/db/models.py:DeviceTypeProfile` (table `device_type_profiles`) +
`sentinel/db/repositories.py:DeviceTypeProfileRepository` replaced what used
to be a hardcoded dict in `sentinel/detection/device_profiles.py`. Each row
has `high_upload_ratio_threshold`, `volume_sustained_polls`, and
`contamination`; `device_profiles.get_profile(device_type)` (now `async`,
DB-backed) merges a matching row over `DEFAULT_PROFILE`, falling back to the
default untouched for any blank/unrecognized `device_type` — the router's own
DHCP-fingerprint classification, not a closed enum. Editable from Rules →
Device Type Profiles (`frontend/src/components/rules/DeviceTypeProfilesSection.jsx`);
`GET/PUT/DELETE /api/device-type-profiles`. A device type with no row simply
uses `DEFAULT_PROFILE` — nothing needs a row to function.

The seed migration (`sentinel/db/migrations/versions/e91a4c7d3f28_device_type_profiles.py`)
fixed a concrete gap: `Smartphone` used to override only `high_upload_ratio_threshold`,
silently falling back to the generic 3-poll `volume_sustained_polls` — the
direct cause of the reported noise. It now has its own longer streak and
higher contamination (see Layer 3).

### Layer 2 — magnitude-aware gate

`is_anomalous()` no longer treats "just past the `0.0` boundary" the same as
"an extreme outlier." At fit time, `_fit_and_save()` computes
`score_std = iso.decision_function(X).std()` over the training set and stores
it alongside the model. At inference time, the sample must clear
`ANOMALY_THRESHOLD - (magnitude_multiplier * score_std)`, not just `0.0`.

This is deliberately **self-relative** — each device is compared only to the
spread of its own fitted training scores — unlike incident #1 above, which
compared every device's raw score to one fixed constant. A model persisted
before this change (missing `score_std`) transparently falls back to
`model.get('score_std', 0.0)`, i.e. exactly the old bare-boundary behavior,
until its next retrain recomputes the stat.

### Layer 3 — adaptive per-device-type contamination (nightly retrain only)

`ModelTrainer.retrain_all()` (`sentinel/ml/trainer.py`) resolves each device's
current `device_type` (one join against `Device`, not N+1 queries) and looks
up its `contamination` from `DeviceTypeProfileRepository` before calling
`AnomalyEngine.retrain_from_history(mac, vectors, contamination=...)`. A
device type prone to short, legitimate, recurring bursts gets a higher rate
(seeded `Smartphone`: 0.10 vs. the 0.05 default) — directly addressing
principle 3 above.

Deliberately **not** applied to the initial bootstrap fit
(`AnomalyEngine.train()`, triggered inline during the poll loop) — reaching
into an async, DB-backed repository from that synchronous, CPU-bound,
hot-path code would mix concerns for comparatively little benefit: a
device's first model is superseded by the very next nightly retrain within
at most 24 hours, so it self-corrects to the right contamination quickly
regardless.

## Observed extremes — measured, not guessed, reference numbers

Rules → Device Type Profiles shows each editable RATIO/POLLS/CONTAM. field
with a small "max" figure underneath it — the highest value **for that
specific device type** ever actually measured on the network, linking to the
device that produced it (`sentinel/detection/observed_extremes.py`, grouped
`PER device_type`, not one global figure — a device type with real traffic
but no saved override still gets a row, defaulted to `DEFAULT_PROFILE`, so
its measurements are visible before anyone has tuned it). These are
full-history scans of `traffic_samples` (gaps-and-islands SQL for the POLLS
streak), too expensive to run per request, so
`SentinelScheduler._observed_extremes_job` recomputes them hourly and caches
the result in memory (`observed_extremes_snapshot()`); `GET
/api/device-type-profiles` serves the cached value alongside the profile
list. The point isn't to auto-tune anything — CONTAM. in particular is a
target rate, not the same thing as the worst empirical share of samples ever
flagged — it's so an admin picking a threshold can see what a real device of
that type actually did, instead of guessing at a number in a vacuum.

## Tuning guidance

| Knob | Where | When to change |
|---|---|---|
| `ML_ANOMALY_MAGNITUDE_MULTIPLIER` | env var, global | Raise to require more extreme outliers before alerting (fewer, higher-confidence alerts); lower toward 0 to approach pre-Layer-2 behavior |
| Per-device-type `contamination` | Rules → Device Type Profiles | Raise for a type prone to short, legitimate, recurring bursts; keep near the global default for types that should stay strict |
| Per-device-type `volume_sustained_polls` | Rules → Device Type Profiles | Raise for a type with naturally bursty/variable traffic; lower for a type that should alert fast (e.g. a printer) |
| `ML_MIN_SAMPLES_TO_TRAIN` | env var | Lower for faster bootstrap; raise for more reliable initial models |
| `ML_LEARNING_PERIOD_HOURS` | Settings tab (runtime, not just env) | How long a new device is exempt from `ANOMALOUS_VOLUME` entirely, regardless of its model |
| Retrain window (`RETRAIN_WINDOW_DAYS`, `sentinel/ml/trainer.py`) | code constant, 7 days | Not currently runtime-configurable |

## What the ML engine does NOT do

- It does not replace the rule-based/ratio-based detectors (`HighUploadDetector`,
  the user-defined `RuleEngine`) — all run independently in the same pipeline.
- It does not explain *why* a specific sample is anomalous (no SHAP values or
  similar attribution) — a real gap for a user trying to understand an alert,
  not yet addressed.
- It does not work on `PER_PORT` granularity — wired-port counters aggregate
  multiple devices and are too noisy to attribute to one; those samples are
  skipped entirely (`sample.granularity != TrafficGranularity.PER_DEVICE`).
- It does not maintain separate models per time-of-day/day-part — one flat
  model per device, with hour/day features baked in (see "Not pursued" below).

## Considered but not pursued (yet)

Surveyed while designing the three layers above; not built because the
complexity outweighed the marginal benefit over what's here:

- **Seasonal/time-bucketed models** (separate models per day-part instead of
  one flat model with hour-of-day as a feature) — meaningfully more complex
  (multiplies model count and storage per device, worsens cold-start), and
  the existing feature vector already encodes some diurnal signal.
- **Per-individual-device overrides** (on top of per-device-type) — `device_type`
  is reliably populated for the devices this was built to fix, so type-level
  tuning covers the reported case. Would need a new `Device` column, a
  `PATCH /devices/<mac>` extension, and a new settings section on the device
  detail page (which has none today) — worth it only if a specific device's
  type turns out unreliable in practice.
- **Feedback loop from alert resolution** (resolving an alert as "not a
  problem" auto-loosens that device's profile) — the biggest net-new surface
  of everything considered, and depends on per-device overrides existing
  first.
