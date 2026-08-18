import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'
import { useArchivedDevices } from '../../hooks/useDevices'
import { apiJson } from '../../lib/api'
import { MacAddress } from '../MacAddress'
import { TimeAgo } from '../TimeAgo'
import { SettingNumberField } from './SettingNumberField'

const MIN_DAYS = 7
const MAX_DAYS = 730 // 2 years — must match sentinel/api/routes/settings.py

export function DeviceArchiveSection() {
  const { data, isLoading } = useSettings()
  const mutation = useUpdateSettings()
  const { data: archived, isLoading: archivedLoading } = useArchivedDevices()
  const qc = useQueryClient()

  const unarchive = useMutation({
    mutationFn: (mac) => apiJson(`/devices/${mac}/unarchive`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
    },
  })

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">DEVICE ARCHIVE</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        A device with no activity for this many days is automatically hidden from device counts/lists
        as stale — a guest's phone, a discarded gadget. Trusted, blocked, and quarantined devices are
        never touched. Nothing is deleted — restore any device below.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && data && (
        <SettingNumberField
          label="ARCHIVE AFTER"
          unit="days"
          value={data.device_archive_after_days}
          min={MIN_DAYS}
          max={MAX_DAYS}
          pending={mutation.isPending}
          onSave={(days) => mutation.mutate({ device_archive_after_days: days })}
        />
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
