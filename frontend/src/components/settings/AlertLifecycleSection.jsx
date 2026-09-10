import { useSettings, useUpdateSettings } from '../../hooks/useSettings'
import { SettingNumberField } from './SettingNumberField'

const MIN_HOURS = 1
const MAX_HOURS = 24 * 90 // 90 days — must match sentinel/api/routes/settings.py

/** Merged AlertStalenessSection + AlertAutoResolveSection — both are a
 * single hours field governing what happens to an inactive alert, so they
 * read as one "alert lifecycle" setting rather than two unrelated tiles.
 * See docs/frontend/... — this is the compact-settings-page consolidation. */
export function AlertLifecycleSection() {
  const { data, isLoading } = useSettings()
  const mutation = useUpdateSettings()

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">ALERT LIFECYCLE</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        STALE AFTER hides an inactive unresolved alert from the Dashboard feed and Network Map pull —
        still OPEN on the Alerts page. AUTO-RESOLVE AFTER actually closes it once inactive that long
        (alerts with no natural "this stopped" signal: ARP spoof, rogue DHCP, honeypot, IDS, nmap) —
        reversible via REOPEN on the Alerts page.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && data && (
        <div className="flex flex-wrap gap-4">
          <SettingNumberField
            label="STALE AFTER"
            unit="hours"
            value={data.alert_stale_hours}
            min={MIN_HOURS}
            max={MAX_HOURS}
            pending={mutation.isPending}
            onSave={(hours) => mutation.mutate({ alert_stale_hours: hours })}
          />
          <SettingNumberField
            label="AUTO-RESOLVE AFTER"
            unit="hours"
            value={data.alert_auto_resolve_hours}
            min={MIN_HOURS}
            max={MAX_HOURS}
            pending={mutation.isPending}
            onSave={(hours) => mutation.mutate({ alert_auto_resolve_hours: hours })}
          />
        </div>
      )}

      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
