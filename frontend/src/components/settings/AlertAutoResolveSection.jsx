import { useSettings, useUpdateSettings } from '../../hooks/useSettings'
import { SettingNumberField } from './SettingNumberField'

const MIN_HOURS = 1
const MAX_HOURS = 24 * 90 // 90 days — must match sentinel/api/routes/settings.py

export function AlertAutoResolveSection() {
  const { data, isLoading } = useSettings()
  const mutation = useUpdateSettings()

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">ALERT AUTO-RESOLVE</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        Alerts with no natural "this stopped" signal of their own (ARP spoof, rogue DHCP, honeypot
        hits, IDS matches, nmap findings) are auto-resolved after this many hours with no recurrence.
        Unlike ALERT STALENESS above, this actually closes the alert — REOPEN it from the Alerts page
        if it was closed too early.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && data && (
        <SettingNumberField
          label="AUTO-RESOLVE AFTER"
          unit="hours"
          value={data.alert_auto_resolve_hours}
          min={MIN_HOURS}
          max={MAX_HOURS}
          pending={mutation.isPending}
          onSave={(hours) => mutation.mutate({ alert_auto_resolve_hours: hours })}
        />
      )}

      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
