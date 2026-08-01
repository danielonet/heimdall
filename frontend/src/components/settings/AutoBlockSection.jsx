import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'

export function AutoBlockSection() {
  const { data, isLoading } = useSettings()
  const mutation = useUpdateSettings()
  const [enabled, setEnabled] = useState(true)

  useEffect(() => {
    if (data) setEnabled(data.auto_block_on_threat)
  }, [data])

  const isDirty = data && enabled !== data.auto_block_on_threat

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">AUTO-BLOCK ON THREAT</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        When armed, ARP Watch, Passive Fingerprint, and Nmap Scanner block the offending MAC the instant
        they detect an attack (spoofing, fingerprint mismatch, a new high-risk port, a vulnerability) —
        instead of only alerting.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && (
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex items-center gap-2 text-[10px] text-text-secondary">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="accent-accent-green"
            />
            Auto-block offending devices
          </label>
          <button
            type="button"
            disabled={!isDirty || mutation.isPending}
            onClick={() => mutation.mutate({ auto_block_on_threat: enabled })}
            className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
          >
            {mutation.isPending ? 'SAVING…' : 'SAVE'}
          </button>
        </div>
      )}

      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
