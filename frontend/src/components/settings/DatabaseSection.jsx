import { useSettings, useUpdateSettings } from '../../hooks/useSettings'
import { SettingNumberField } from './SettingNumberField'

const MIN_DAYS = 1
const MAX_DAYS = 3650 // 10 years — must match sentinel/api/routes/settings.py

function formatSize(mb) {
  if (mb == null) return '—'
  if (mb >= 1024) return `${(mb / 1024).toFixed(2)} GB`
  return `${mb.toFixed(1)} MB`
}

export function DatabaseSection() {
  const { data, isLoading } = useSettings()
  const mutation = useUpdateSettings()

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">DATABASE</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        Traffic, port stats, WAN changes, and alerts older than the retention window are purged nightly.
        Known devices and trust decisions are never affected.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && data && (
        <div className="flex flex-wrap items-end gap-6">
          <SettingNumberField
            label="RETENTION WINDOW"
            unit="days"
            value={data.data_retention_days}
            min={MIN_DAYS}
            max={MAX_DAYS}
            pending={mutation.isPending}
            onSave={(days) => mutation.mutate({ data_retention_days: days })}
          />
          <div>
            <div className="mb-1 text-[9px] tracking-wider text-text-muted">DATABASE SIZE</div>
            <div className="py-1.5 text-[11px] text-text-primary">{formatSize(data.db_size_mb)}</div>
          </div>
        </div>
      )}

      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
