import { useSettings, useUpdateSettings } from '../../hooks/useSettings'
import { SettingNumberField } from './SettingNumberField'

const MIN_HOURS = 1
const MAX_HOURS = 24 * 90 // 90 days — must match sentinel/api/routes/settings.py

export function AlertStalenessSection() {
  const { data, isLoading } = useSettings()
  const mutation = useUpdateSettings()

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">ALERT STALENESS</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        An unresolved alert older than this is dropped from the Dashboard's OPEN ALERTS feed/threat score
        and stops pulling its device toward the Network Map's center — but nothing is deleted. It still
        shows up on the full Alerts page, marked STALE instead of OPEN.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && data && (
        <SettingNumberField
          label="STALE AFTER"
          unit="hours"
          value={data.alert_stale_hours}
          min={MIN_HOURS}
          max={MAX_HOURS}
          pending={mutation.isPending}
          onSave={(hours) => mutation.mutate({ alert_stale_hours: hours })}
        />
      )}

      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
