import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  useDeviceTypeProfiles, useUpsertDeviceTypeProfile, useDeleteDeviceTypeProfile,
  useObservedThresholdExtremes,
} from '../../hooks/useDeviceTypeProfiles'
import { useDevices } from '../../hooks/useDevices'
import { TimeAgo } from '../TimeAgo'

// Must match sentinel/api/routes/device_type_profiles.py's MIN_*/MAX_* constants.
const RATIO_MIN = 0.1, RATIO_MAX = 1000
const POLLS_MIN = 1, POLLS_MAX = 100
const CONTAMINATION_MIN = 0.001, CONTAMINATION_MAX = 0.5

// One shared column template drives the header, every row, and the add
// form — previously each of those three pieces set its own fixed w-40/w-24
// widths independently and just had to coincidentally agree, which is
// exactly the kind of thing that quietly drifts out of alignment. The name
// column flexes with available width; the three threshold columns and the
// action column stay fixed.
const GRID_COLS = 'grid-cols-[minmax(9rem,1fr)_repeat(3,6.5rem)_6.5rem]'

// format() renders the read-only "measured" reference value under each
// input — same field keys the profile itself uses, so a configured number
// and its real-world counterpart sit directly on top of one another.
const FIELDS = [
  {
    key: 'high_upload_ratio_threshold', label: 'RATIO', min: RATIO_MIN, max: RATIO_MAX,
    format: (v) => v.toFixed(1),
  },
  {
    key: 'volume_sustained_polls', label: 'POLLS', min: POLLS_MIN, max: POLLS_MAX, integer: true,
    format: (v) => String(Math.round(v)),
  },
  {
    key: 'contamination', label: 'CONTAM.', min: CONTAMINATION_MIN, max: CONTAMINATION_MAX,
    format: (v) => `${(v * 100).toFixed(1)}%`,
  },
]

// Code-side fallback a device_type with no saved override uses — must match
// sentinel/detection/device_profiles.py's DEFAULT_PROFILE.
const DEFAULT_PROFILE = { high_upload_ratio_threshold: 3.0, volume_sustained_polls: 3, contamination: 0.05 }

const DEVICE_TYPE_DATALIST_ID = 'known-device-types'

function isValid(values) {
  return FIELDS.every(({ key, min, max }) => {
    const n = Number(values[key])
    return values[key] !== '' && !Number.isNaN(n) && n >= min && n <= max
  })
}

/** Strips a typed string down to digits and (for non-integer fields) a
 * single decimal point. Plain <input type="number"> was demonstrably
 * unreliable for this: e.g. on a comma-decimal locale, typing "7,7" doesn't
 * get rejected or converted — the browser silently drops the comma,
 * producing "77", a valid but completely wrong number, with no error and no
 * way to tell from the input alone that anything went wrong. Doing our own
 * parsing on a plain text field sidesteps every native-number-input quirk
 * like this, at the cost of losing the native up/down spinner buttons. */
function sanitizeNumericInput(raw, integer) {
  if (integer) return raw.replace(/[^0-9]/g, '')
  // "," treated as an alternate decimal point, not stripped — a comma-locale
  // keyboard (see the module-level comment above) types "7,7" meaning 7.7,
  // not "77".
  let cleaned = raw.replace(',', '.').replace(/[^0-9.]/g, '')
  const firstDot = cleaned.indexOf('.')
  if (firstDot !== -1) {
    cleaned = cleaned.slice(0, firstDot + 1) + cleaned.slice(firstDot + 1).replaceAll('.', '')
  }
  return cleaned
}

/** One editable threshold input, with the real-world measured extreme for
 * this device_type (if any) shown directly beneath it — "what I've set"
 * and "what actually happened" line up as one visual unit instead of two
 * unrelated lists. isDirty rings the specific field that changed (not just
 * the row as a whole), so editing one of three numbers doesn't leave it
 * ambiguous which one is actually pending a save. */
function NumCell({ field, value, onChange, measured, isDirty }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <input
        type="text"
        inputMode={field.integer ? 'numeric' : 'decimal'}
        value={value}
        onChange={(e) => onChange(field.key, sanitizeNumericInput(e.target.value, field.integer))}
        className={`w-full border bg-bg px-2 py-1.5 text-[11px] tabular-nums text-text-primary outline-none transition-colors focus:border-border-active ${
          isDirty ? 'border-accent-green/50' : 'border-border'
        }`}
      />
      <div className="truncate text-[8px] leading-tight tracking-wide text-text-muted">
        {measured ? (
          <Link
            to={`/devices/${measured.device_mac}`}
            title={measured.hostname || measured.device_mac}
            className="text-accent-amber/80 tabular-nums hover:text-accent-amber hover:underline"
          >
            max {field.format(measured.value)}
          </Link>
        ) : (
          <span className="opacity-50">no data yet</span>
        )}
      </div>
    </div>
  )
}

function ProfileRow({ deviceType, profile, measured, hasOverride, onSave, onDelete, isSaving, isDeleting }) {
  const [values, setValues] = useState(() =>
    Object.fromEntries(FIELDS.map(({ key }) => [key, String(profile[key])]))
  )
  const dirtyKeys = new Set(FIELDS.filter(({ key }) => String(profile[key]) !== values[key]).map((f) => f.key))
  const isDirty = dirtyKeys.size > 0
  const canSave = isDirty && isValid(values) && !isSaving

  return (
    <div className={`grid ${GRID_COLS} items-center gap-3 border-b border-border/40 px-1 py-2.5 text-[10px] transition-colors last:border-none hover:bg-border/10`}>
      <div className="flex min-w-0 items-baseline gap-1.5">
        <span className="truncate text-[11px] text-text-primary" title={deviceType}>
          {deviceType}
        </span>
        {!hasOverride && (
          <span className="flex-shrink-0 text-[8px] tracking-wide text-text-muted/70">default</span>
        )}
      </div>
      {FIELDS.map((field) => (
        <NumCell
          key={field.key}
          field={field}
          value={values[field.key]}
          onChange={(k, v) => setValues((prev) => ({ ...prev, [k]: v }))}
          measured={measured?.[field.key]}
          isDirty={dirtyKeys.has(field.key)}
        />
      ))}
      <div className="flex justify-end gap-1.5 self-start pt-0.5">
        <button
          type="button"
          disabled={!canSave}
          onClick={() => onSave(Object.fromEntries(FIELDS.map(({ key }) => [key, Number(values[key])])))}
          title="Save"
          className={`border px-2 py-1.5 text-[9px] tracking-wider transition-colors ${
            canSave
              ? 'border-accent-green/40 bg-accent-green/10 text-accent-green hover:bg-accent-green/20'
              : 'border-border/30 text-text-muted/30'
          }`}
        >
          {isSaving ? '···' : 'SAVE'}
        </button>
        <button
          type="button"
          disabled={!hasOverride || isDeleting}
          onClick={onDelete}
          title={hasOverride ? 'Revert this device type to the built-in default' : 'No override to revert — already using the default'}
          className={`border px-2 py-1.5 text-[9px] tracking-wider transition-colors ${
            hasOverride
              ? 'border-border text-text-muted hover:border-accent-red/40 hover:text-accent-red'
              : 'border-border/30 text-text-muted/30'
          }`}
        >
          {isDeleting ? '···' : 'RESET'}
        </button>
      </div>
    </div>
  )
}

function AddProfileForm({ onAdd, isSaving, existingTypes, onDone }) {
  const [deviceType, setDeviceType] = useState('')
  const [values, setValues] = useState({
    high_upload_ratio_threshold: '3.0', volume_sustained_polls: '3', contamination: '0.05',
  })

  const trimmed = deviceType.trim()
  const canAdd = trimmed !== '' && !existingTypes.includes(trimmed) && isValid(values)

  function handleAdd() {
    onAdd(trimmed, Object.fromEntries(FIELDS.map(({ key }) => [key, Number(values[key])])))
    setDeviceType('')
  }

  return (
    <div className={`grid ${GRID_COLS} items-center gap-3 border border-dashed border-border-active/50 bg-bg/50 px-1 py-2.5 text-[10px]`}>
      <input
        type="text"
        autoFocus
        list={DEVICE_TYPE_DATALIST_ID}
        placeholder="e.g. Smart TV"
        value={deviceType}
        onChange={(e) => setDeviceType(e.target.value)}
        onKeyDown={(e) => e.key === 'Escape' && onDone()}
        className="min-w-0 border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
      />
      {FIELDS.map((field) => (
        <input
          key={field.key}
          type="text"
          inputMode={field.integer ? 'numeric' : 'decimal'}
          value={values[field.key]}
          onChange={(e) =>
            setValues((prev) => ({ ...prev, [field.key]: sanitizeNumericInput(e.target.value, field.integer) }))
          }
          className="min-w-0 border border-border bg-bg px-2 py-1.5 text-[11px] tabular-nums text-text-primary outline-none focus:border-border-active"
        />
      ))}
      <div className="flex justify-end gap-1.5">
        <button
          type="button"
          disabled={!canAdd || isSaving}
          onClick={handleAdd}
          className="border border-accent-green/40 bg-accent-green/10 px-2 py-1.5 text-[9px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:border-border/30 disabled:bg-transparent disabled:text-text-muted/30"
        >
          {isSaving ? '···' : 'ADD'}
        </button>
        <button
          type="button"
          onClick={onDone}
          title="Cancel"
          className="border border-border px-2 py-1.5 text-[9px] tracking-wider text-text-muted transition-colors hover:text-text-primary"
        >
          ✕
        </button>
      </div>
    </div>
  )
}

export function DeviceTypeProfilesSection() {
  const { data: profiles, isLoading: profilesLoading } = useDeviceTypeProfiles()
  const { data: extremesData, isLoading: extremesLoading } = useObservedThresholdExtremes()
  const { data: devices } = useDevices()
  const upsertMutation = useUpsertDeviceTypeProfile()
  const deleteMutation = useDeleteDeviceTypeProfile()
  const [pendingType, setPendingType] = useState(null)
  const [showAdd, setShowAdd] = useState(false)
  const [showHelp, setShowHelp] = useState(false)

  const isLoading = profilesLoading || extremesLoading
  // Stable {} fallback (not a fresh object literal on every render) so the
  // `rows` useMemo below doesn't invalidate on every render while extremes
  // data hasn't actually loaded yet.
  const measuredByType = useMemo(() => extremesData?.extremes || {}, [extremesData])

  // One row per device_type that either has a saved override OR has real
  // measured traffic — a type with data but no override yet still gets a
  // row (defaulted to DEFAULT_PROFILE) so its measurements are visible
  // without first having to add an override just to see them.
  const profilesByType = useMemo(
    () => Object.fromEntries((profiles || []).map((p) => [p.device_type, p])),
    [profiles]
  )
  const rows = useMemo(() => {
    const types = new Set([...Object.keys(profilesByType), ...Object.keys(measuredByType)])
    return [...types].sort().map((deviceType) => ({
      deviceType,
      profile: profilesByType[deviceType] || DEFAULT_PROFILE,
      hasOverride: deviceType in profilesByType,
      measured: measuredByType[deviceType] || null,
    }))
  }, [profilesByType, measuredByType])

  // Suggestions for the "add profile" field: every distinct device_type the
  // router has actually reported across current devices — not just the ones
  // already shown as a row — so an admin can autocomplete straight to
  // "Smartphone" or whatever string their own hardware reports.
  const knownDeviceTypes = useMemo(() => {
    const types = new Set((devices || []).map((d) => d.device_type).filter(Boolean))
    return [...types].sort()
  }, [devices])

  function save(deviceType, fields) {
    setPendingType(deviceType)
    upsertMutation.mutate({ deviceType, ...fields }, {
      onSettled: () => setPendingType(null),
      onSuccess: () => setShowAdd(false),
    })
  }

  function remove(deviceType) {
    setPendingType(deviceType)
    deleteMutation.mutate(deviceType, { onSettled: () => setPendingType(null) })
  }

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1.5">
          <div className="text-[8px] tracking-[3px] text-text-muted">DEVICE TYPE PROFILES</div>
          <button
            type="button"
            onClick={() => setShowHelp((v) => !v)}
            title="What do these mean?"
            aria-expanded={showHelp}
            className={`flex h-3.5 w-3.5 flex-shrink-0 items-center justify-center rounded-full border text-[8px] leading-none transition-colors ${
              showHelp
                ? 'border-accent-blue/50 text-accent-blue'
                : 'border-border text-text-muted hover:border-border-active hover:text-text-secondary'
            }`}
          >
            ?
          </button>
        </div>
        <div className="text-[9px] text-text-muted">
          {extremesData?.computed_at ? (
            <>measured as of <TimeAgo iso={extremesData.computed_at} /> · refreshes hourly</>
          ) : (
            'measured column not computed yet — refreshes hourly'
          )}
        </div>
      </div>

      {showHelp && (
        <p className="mb-3 border-l-2 border-border-active/60 py-0.5 pl-2.5 text-[10px] leading-relaxed text-text-secondary">
          Per-device-type overrides for how easily HIGH_UPLOAD/ANOMALOUS_VOLUME fire. RATIO = upload:download
          ratio that counts as suspicious; POLLS = consecutive flagged polls needed before alerting; CONTAM.
          = the anomaly model's expected outlier rate for this type's nightly retrain — raise it for a type
          prone to short, legitimate, recurring bursts (e.g. a phone during a video call) so that pattern
          stops being flagged as an outlier indefinitely. The amber number under each field is the highest
          value ever actually measured for that device type — <em>use it to judge a threshold, not as a
          preset to copy blindly</em> (e.g. CONTAM. is a target rate, not the same thing as the worst share
          of samples that were ever flagged).
        </p>
      )}

      <datalist id={DEVICE_TYPE_DATALIST_ID}>
        {knownDeviceTypes.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && (
        <>
          <div className={`grid ${GRID_COLS} gap-3 px-1 pb-1.5 text-[9px] tracking-wider text-text-muted`}>
            <div>DEVICE TYPE</div>
            {FIELDS.map((f) => (
              <div key={f.key}>{f.label}</div>
            ))}
            <div />
          </div>

          {rows.length === 0 && !showAdd && (
            <div className="py-3 text-center text-[10px] text-text-muted">
              No overrides and no measured traffic yet — every device type uses the default.
            </div>
          )}

          {rows.map(({ deviceType, profile, measured, hasOverride }) => (
            <ProfileRow
              key={deviceType}
              deviceType={deviceType}
              profile={profile}
              measured={measured}
              hasOverride={hasOverride}
              onSave={(fields) => save(deviceType, fields)}
              onDelete={() => remove(deviceType)}
              isSaving={upsertMutation.isPending && pendingType === deviceType}
              isDeleting={deleteMutation.isPending && pendingType === deviceType}
            />
          ))}

          <div className="pt-2.5">
            {showAdd ? (
              <AddProfileForm
                onAdd={(deviceType, fields) => save(deviceType, fields)}
                onDone={() => setShowAdd(false)}
                isSaving={upsertMutation.isPending && pendingType !== null && !rows.some((r) => r.deviceType === pendingType)}
                existingTypes={rows.map((r) => r.deviceType)}
              />
            ) : (
              <button
                type="button"
                onClick={() => setShowAdd(true)}
                className="w-full border border-dashed border-border py-1.5 text-[9px] tracking-wider text-text-muted transition-colors hover:border-border-active hover:text-text-secondary"
              >
                + ADD DEVICE TYPE OVERRIDE
              </button>
            )}
          </div>
        </>
      )}

      {upsertMutation.isError && <div className="mt-2 text-[9px] text-accent-red">{upsertMutation.error.message}</div>}
      {deleteMutation.isError && <div className="mt-2 text-[9px] text-accent-red">{deleteMutation.error.message}</div>}
    </div>
  )
}
