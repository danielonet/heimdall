import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../../lib/api'

// Same order-of-magnitude durations as the settings-page hour bounds
// (sentinel/api/routes/devices.py: MIN/MAX_SNOOZE_HOURS), just a curated
// short list rather than a free-text field — snoozing is a quick "get this
// out of my face for a while" action, not a precision setting.
const DURATION_OPTIONS = [
  { label: '1H', hours: 1 },
  { label: '24H', hours: 24 },
  { label: '7D', hours: 24 * 7 },
]

function formatUntil(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

/** Snooze/un-snooze control for one (device, alert_type) pair — sits on an
 * AlertHistoryTable row. `snooze` is that pair's active snooze object from
 * useSnoozes(mac), or undefined if none is active. Suppresses new
 * occurrences of this alert_type on this device for a chosen duration —
 * see AlertRepository.upsert()'s snooze check. */
export function SnoozeControls({ mac, alertType, snooze }) {
  const [picking, setPicking] = useState(false)
  const qc = useQueryClient()

  function invalidate() {
    qc.invalidateQueries({ queryKey: ['snoozes', mac] })
    qc.invalidateQueries({ queryKey: ['device', mac] })
  }

  const snoozeMutation = useMutation({
    mutationFn: (hours) =>
      apiJson(`/devices/${mac}/alerts/${alertType}/snooze`, {
        method: 'POST',
        body: JSON.stringify({ hours }),
      }),
    onSuccess: () => {
      setPicking(false)
      invalidate()
    },
  })

  const unsnoozeMutation = useMutation({
    mutationFn: () => apiJson(`/devices/${mac}/alerts/${alertType}/snooze`, { method: 'DELETE' }),
    onSuccess: invalidate,
  })

  const error = snoozeMutation.error?.message || unsnoozeMutation.error?.message

  if (snooze) {
    return (
      <div className="flex flex-col items-end gap-0.5" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-1">
          <span className="text-[9px] text-text-muted" title={`Snoozed until ${formatUntil(snooze.snoozed_until)}`}>
            SNOOZED · {formatUntil(snooze.snoozed_until)}
          </span>
          <button
            type="button"
            disabled={unsnoozeMutation.isPending}
            onClick={() => unsnoozeMutation.mutate()}
            className="border border-accent-amber/30 bg-accent-amber/5 px-2 py-0.5 text-[9px] tracking-wider text-accent-amber transition-colors hover:bg-accent-amber/20 disabled:opacity-40"
          >
            CANCEL
          </button>
        </div>
        {error && <span className="text-[9px] text-accent-red">{error}</span>}
      </div>
    )
  }

  if (picking) {
    return (
      <div className="flex flex-col items-end gap-0.5" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-1">
          {DURATION_OPTIONS.map((opt) => (
            <button
              key={opt.hours}
              type="button"
              disabled={snoozeMutation.isPending}
              onClick={() => snoozeMutation.mutate(opt.hours)}
              className="border border-accent-blue/30 bg-accent-blue/5 px-2 py-0.5 text-[9px] tracking-wider text-accent-blue transition-colors hover:bg-accent-blue/20 disabled:opacity-40"
            >
              {opt.label}
            </button>
          ))}
          <button
            type="button"
            onClick={() => setPicking(false)}
            className="px-1 text-[9px] text-text-muted hover:text-text-secondary"
          >
            ×
          </button>
        </div>
        {error && <span className="text-[9px] text-accent-red">{error}</span>}
      </div>
    )
  }

  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation()
        setPicking(true)
      }}
      className="border border-border bg-surface px-2 py-0.5 text-[9px] tracking-wider text-text-muted transition-colors hover:bg-border/20"
    >
      SNOOZE
    </button>
  )
}
