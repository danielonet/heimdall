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
 * this device_type (if any) shown directly beneath it — same width as the
 * input above it, so "what I've set" and "what actually happened" line up
 * as one visual unit instead of two unrelated lists. */
function NumCell({ field, value, onChange, measured }) {
  return (
    <div className="w-24 flex-shrink-0">
      <input
        type="text"
        inputMode={field.integer ? 'numeric' : 'decimal'}
        value={value}
        onChange={(e) => onChange(field.key, sanitizeNumericInput(e.target.value, field.integer))}
        className="w-full border border-border bg-bg px-2 py-1 text-[10px] text-text-primary outline-none focus:border-border-active"
      />
      <div className="mt-0.5 truncate text-[8px] leading-tight text-text-muted">
        {measured ? (
          <>
            max{' '}
            <Link
              to={`/devices/${measured.device_mac}`}
              title={measured.hostname || measured.device_mac}
              className="text-accent-amber hover:underline"
            >
              {field.format(measured.value)}
            </Link>
          </>
        ) : (
          '—'
        )}
      </div>
    </div>
  )
}

function ProfileRow({ deviceType, profile, measured, hasOverride, onSave, onDelete, isSaving, isDeleting }) {
  const [values, setValues] = useState(() =>
    Object.fromEntries(FIELDS.map(({ key }) => [key, String(profile[key])]))
  )
  const isDirty = FIELDS.some(({ key }) => String(profile[key]) !== values[key])

  return (
    <div className="flex items-start gap-2 border-b border-border/50 py-1.5 text-[10px]">
      <div className="w-40 flex-shrink-0 truncate pt-1.5 text-text-primary" title={deviceType}>
        {deviceType}
      </div>
      {FIELDS.map((field) => (
        <NumCell
          key={field.key}
          field={field}
          value={values[field.key]}
          onChange={(k, v) => setValues((prev) => ({ ...prev, [k]: v }))}
          measured={measured?.[field.key]}
        />
      ))}
      <div className="flex flex-shrink-0 gap-2 pt-1.5">
        <button
          type="button"
          disabled={!isDirty || !isValid(values) || isSaving}
          onClick={() => onSave(Object.fromEntries(FIELDS.map(({ key }) => [key, Number(values[key])])))}
          className="border border-accent-green/30 bg-accent-green/5 px-2 py-1 text-[9px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
        >
          {isSaving ? '···' : 'SAVE'}
        </button>
        <button
          type="button"
          disabled={!hasOverride || isDeleting}
          onClick={onDelete}
          title={hasOverride ? 'Revert this device type to the built-in default' : 'No override to revert — already using the default'}
          className="border border-border px-2 py-1 text-[9px] tracking-wider text-text-muted transition-colors hover:text-accent-red disabled:opacity-40"
        >
          {isDeleting ? '···' : 'RESET'}
        </button>
      </div>
    </div>
  )
}

function AddProfileForm({ onAdd, isSaving, existingTypes }) {
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
    <div className="flex items-center gap-2 border-t border-border pt-2 text-[10px]">
      <input
        type="text"
        list={DEVICE_TYPE_DATALIST_ID}
        placeholder="new device type (e.g. Smart TV)"
        value={deviceType}
        onChange={(e) => setDeviceType(e.target.value)}
        className="w-40 flex-shrink-0 border border-border bg-bg px-2 py-1 text-[10px] text-text-primary outline-none focus:border-border-active"
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
          className="w-24 flex-shrink-0 border border-border bg-bg px-2 py-1 text-[10px] text-text-primary outline-none focus:border-border-active"
        />
      ))}
      <button
        type="button"
        disabled={!canAdd || isSaving}
        onClick={handleAdd}
        className="border border-accent-green/30 bg-accent-green/5 px-2 py-1 text-[9px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
      >
        {isSaving ? '···' : 'ADD'}
      </button>
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
    upsertMutation.mutate({ deviceType, ...fields }, { onSettled: () => setPendingType(null) })
  }

  function remove(deviceType) {
    setPendingType(deviceType)
    deleteMutation.mutate(deviceType, { onSettled: () => setPendingType(null) })
  }

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
        <div className="text-[8px] tracking-[3px] text-text-muted">DEVICE TYPE PROFILES</div>
        <div className="text-[9px] text-text-muted">
          {extremesData?.computed_at ? (
            <>measured column as of <TimeAgo iso={extremesData.computed_at} /> · refreshes hourly</>
          ) : (
            'measured column not computed yet — refreshes hourly'
          )}
        </div>
      </div>
      <p className="mb-3 text-[10px] leading-relaxed text-text-secondary">
        Per-device-type overrides for how easily HIGH_UPLOAD/ANOMALOUS_VOLUME fire. RATIO = upload:download
        ratio that counts as suspicious; POLLS = consecutive flagged polls needed before alerting; CONTAM.
        = the anomaly model's expected outlier rate for this type's nightly retrain — raise it for a type
        prone to short, legitimate, recurring bursts (e.g. a phone during a video call) so that pattern
        stops being flagged as an outlier indefinitely. The small amber number under each field is the
        highest value ever actually measured for that device type — <em>use it to judge a threshold, not
        as a preset to copy blindly</em> (e.g. CONTAM. is a target rate, not the same thing as the worst
        share of samples that were ever flagged).
      </p>

      <datalist id={DEVICE_TYPE_DATALIST_ID}>
        {knownDeviceTypes.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && (
        <>
          <div className="flex items-center gap-2 pb-1 text-[9px] tracking-wider text-text-muted">
            <div className="w-40 flex-shrink-0">DEVICE TYPE</div>
            {FIELDS.map((f) => (
              <div key={f.key} className="w-24 flex-shrink-0">{f.label}</div>
            ))}
          </div>

          {rows.length === 0 && (
            <div className="py-2 text-[10px] text-text-muted">
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

          <AddProfileForm
            onAdd={(deviceType, fields) => save(deviceType, fields)}
            isSaving={upsertMutation.isPending && pendingType !== null && !rows.some((r) => r.deviceType === pendingType)}
            existingTypes={rows.map((r) => r.deviceType)}
          />
        </>
      )}

      {upsertMutation.isError && <div className="mt-2 text-[9px] text-accent-red">{upsertMutation.error.message}</div>}
      {deleteMutation.isError && <div className="mt-2 text-[9px] text-accent-red">{deleteMutation.error.message}</div>}
    </div>
  )
}
