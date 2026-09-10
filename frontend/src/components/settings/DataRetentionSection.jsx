import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'
import { useArchivedDevices } from '../../hooks/useDevices'
import { apiJson } from '../../lib/api'
import { MacAddress } from '../MacAddress'
import { TimeAgo } from '../TimeAgo'
import { SettingNumberField } from './SettingNumberField'

const MIN_DAYS = 1
const MAX_DAYS = 3650 // 10 years — must match sentinel/api/routes/settings.py
const MIN_ARCHIVE_DAYS = 7
const MAX_ARCHIVE_DAYS = 730 // 2 years — must match sentinel/api/routes/settings.py

function formatSize(mb) {
  if (mb == null) return '—'
  if (mb >= 1024) return `${(mb / 1024).toFixed(2)} GB`
  return `${mb.toFixed(1)} MB`
}

/** Merged DatabaseSection + DeviceArchiveSection — both are "how long do we
 * keep things" retention windows (rows vs. devices), so one tile covers
 * both plus the archived-devices review list underneath. Compact-settings-
 * page consolidation. */
export function DataRetentionSection() {
  const { data, isLoading } = useSettings()
  const mutation = useUpdateSettings()
  const { data: archived, isLoading: archivedLoading } = useArchivedDevices()
  const qc = useQueryClient()

  const unarchive = useMutation({
    mutationFn: (mac) => apiJson(`/devices/${mac}/unarchive`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['devices'] }),
  })

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">DATA RETENTION</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        Traffic, port stats, WAN changes, and alerts older than the retention window are purged nightly.
        A device idle past ARCHIVE AFTER is hidden from counts/lists (trusted/blocked/quarantined are
        exempt) — restore any below. An archived device idle for THEN DELETE AFTER more days is{' '}
        <strong>permanently deleted</strong> (record, alerts, history, trained model).{' '}
        <strong>Cannot be undone.</strong>
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && data && (
        <div className="flex flex-wrap gap-4">
          <SettingNumberField
            label="RETENTION WINDOW"
            unit="days"
            value={data.data_retention_days}
            min={MIN_DAYS}
            max={MAX_DAYS}
            pending={mutation.isPending}
            onSave={(days) => mutation.mutate({ data_retention_days: days })}
          />
          <SettingNumberField
            label="ARCHIVE AFTER"
            unit="days"
            value={data.device_archive_after_days}
            min={MIN_ARCHIVE_DAYS}
            max={MAX_ARCHIVE_DAYS}
            pending={mutation.isPending}
            onSave={(days) => mutation.mutate({ device_archive_after_days: days })}
          />
          <SettingNumberField
            label="THEN DELETE AFTER"
            unit="more days"
            value={data.device_purge_after_days}
            min={MIN_ARCHIVE_DAYS}
            max={MAX_ARCHIVE_DAYS}
            pending={mutation.isPending}
            onSave={(days) => mutation.mutate({ device_purge_after_days: days })}
          />
          <div>
            <div className="mb-1 text-[9px] tracking-wider text-text-muted">DATABASE SIZE</div>
            <div className="py-1.5 text-[11px] text-text-primary">{formatSize(data.db_size_mb)}</div>
          </div>
        </div>
      )}

      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}

      <div className="mt-3 border-t border-border/50 pt-2">
        <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">
          ARCHIVED DEVICES {archived?.length > 0 && `(${archived.length})`}
        </div>
        {archivedLoading && <div className="text-[10px] text-text-muted">Loading…</div>}
        {!archivedLoading && (!archived || archived.length === 0) && (
          <div className="text-[10px] text-text-muted">No archived devices.</div>
        )}
        {archived?.map((d) => (
          <div
            key={d.mac_address}
            className="flex items-center justify-between gap-2 border-b border-border/50 py-1.5 text-[10px] last:border-none"
          >
            <div className="min-w-0 flex-1">
              <div className="truncate text-text-primary">
                {d.hostname || <MacAddress mac={d.mac_address} vendor={d.vendor_name} />}
              </div>
              <div className="text-[9px] text-text-muted">
                Archived <TimeAgo iso={d.archived_at} /> — {d.archive_reason}
              </div>
            </div>
            <button
              type="button"
              disabled={unarchive.isPending}
              onClick={() => unarchive.mutate(d.mac_address)}
              className="whitespace-nowrap border border-accent-amber/30 bg-accent-amber/5 px-2 py-0.5 text-[9px] tracking-wider text-accent-amber transition-colors hover:bg-accent-amber/20 disabled:opacity-50"
            >
              UNARCHIVE
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
