import { useEffect, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../../lib/api'

const TRIGGER_CLASS =
  'flex-shrink-0 border border-border bg-surface px-2 py-1 text-[9px] tracking-wider text-text-muted outline-none transition-colors hover:bg-border/20 disabled:opacity-40'

/** One dropdown replacing what used to be a row of individually-conditional
 * buttons (ACK, RESOLVE/REOPEN, SNOOZE + its duration picker, and now ADD
 * EXCEPTION) — a single alert row was accumulating up to four buttons at
 * once. Every option here is exactly one of those old buttons; picking one
 * fires the same request the button used to, then the menu closes. Current
 * status (acknowledged/resolved/snoozed) is still shown as a badge next to
 * this, same as before — this only replaced the *actions*, not the status
 * display.
 *
 * A hand-built popup, deliberately not a native <select> — confirmed a real
 * mismatch, not a style-tuning nitpick: a native select's *open* option
 * list is rendered by the OS/browser itself once expanded, so it ignores
 * almost all CSS and shows up as a stock system menu no matter how the
 * closed trigger is styled, breaking from the app's own dark/bordered look
 * right at the moment a user opens it. This is styled the same way
 * Modal.jsx's popup surface is (bg-surface-elevated, border-border-active,
 * a real drop shadow) so it reads as part of the same UI, not a native
 * control bolted on.
 *
 * `isSnoozed` is opt-in (default false, no "Cancel snooze" option) rather
 * than derived here — knowing it requires a per-device useSnoozes() fetch,
 * which is cheap on the device detail page (one device) but would mean one
 * extra query per distinct device_mac on a mixed-device alerts list. Pass
 * it explicitly only where that state is already being fetched anyway. */
export function AlertActionsMenu({ alert, isSnoozed = false }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const rootRef = useRef(null)

  useEffect(() => {
    if (!open) return
    function onOutside(e) {
      if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false)
    }
    function onEscape(e) {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onOutside)
    document.addEventListener('keydown', onEscape)
    return () => {
      document.removeEventListener('mousedown', onOutside)
      document.removeEventListener('keydown', onEscape)
    }
  }, [open])

  function invalidate() {
    qc.invalidateQueries({ queryKey: ['alerts'] })
    qc.invalidateQueries({ queryKey: ['alertGroups'] })
    qc.invalidateQueries({ queryKey: ['device'] })
    qc.invalidateQueries({ queryKey: ['snoozes'] })
    qc.invalidateQueries({ queryKey: ['portAllowlist'] })
  }

  const statusMutation = useMutation({
    mutationFn: (body) => apiJson(`/alerts/${alert.id}`, { method: 'PATCH', body: JSON.stringify(body) }),
    onSuccess: invalidate,
  })

  const snoozeMutation = useMutation({
    mutationFn: (hours) =>
      apiJson(`/devices/${alert.device_mac}/alerts/${alert.alert_type}/snooze`, {
        method: 'POST',
        body: JSON.stringify({ hours }),
      }),
    onSuccess: invalidate,
  })

  const unsnoozeMutation = useMutation({
    mutationFn: () =>
      apiJson(`/devices/${alert.device_mac}/alerts/${alert.alert_type}/snooze`, { method: 'DELETE' }),
    onSuccess: invalidate,
  })

  const exceptionMutation = useMutation({
    mutationFn: () =>
      apiJson(`/port-allowlist/${alert.device_mac}/${alert.raw_data.port}`, {
        method: 'PUT',
        body: JSON.stringify({ note: null }),
      }),
    onSuccess: invalidate,
  })

  const isPending =
    statusMutation.isPending || snoozeMutation.isPending || unsnoozeMutation.isPending || exceptionMutation.isPending
  const error =
    statusMutation.error?.message || snoozeMutation.error?.message ||
    unsnoozeMutation.error?.message || exceptionMutation.error?.message

  const canException = alert.alert_type === 'HIGH_RISK_PORT_OPENED' && alert.device_mac && alert.raw_data?.port
  const canSnooze = !alert.resolved && alert.device_mac

  const options = [
    !alert.acknowledged && { value: 'acknowledge', label: 'Acknowledge' },
    !alert.resolved && { value: 'resolve', label: 'Resolve' },
    alert.resolved && { value: 'reopen', label: 'Reopen' },
    canSnooze && { value: 'snooze_1h', label: 'Snooze 1h' },
    canSnooze && { value: 'snooze_24h', label: 'Snooze 24h' },
    canSnooze && { value: 'snooze_7d', label: 'Snooze 7d' },
    isSnoozed && { value: 'unsnooze', label: 'Cancel snooze' },
    canException && { value: 'exception', label: 'Add exception (allow this port)' },
  ].filter(Boolean)

  function runAction(action) {
    setOpen(false)
    if (action === 'acknowledge') statusMutation.mutate({ acknowledged: true })
    else if (action === 'resolve') statusMutation.mutate({ resolved: true })
    else if (action === 'reopen') statusMutation.mutate({ resolved: false })
    else if (action === 'snooze_1h') snoozeMutation.mutate(1)
    else if (action === 'snooze_24h') snoozeMutation.mutate(24)
    else if (action === 'snooze_7d') snoozeMutation.mutate(24 * 7)
    else if (action === 'unsnooze') unsnoozeMutation.mutate()
    else if (action === 'exception') exceptionMutation.mutate()
  }

  return (
    <div ref={rootRef} className="relative flex-shrink-0" onClick={(e) => e.stopPropagation()}>
      <button
        type="button"
        disabled={isPending || options.length === 0}
        onClick={() => setOpen((o) => !o)}
        className={TRIGGER_CLASS}
      >
        {isPending ? '···' : 'ACTIONS ▾'}
      </button>

      {open && options.length > 0 && (
        <div className="absolute right-0 top-full z-10 mt-1 min-w-[11rem] border border-border-active bg-surface-elevated py-1 shadow-[0_4px_16px_rgba(0,0,0,0.4)]">
          {options.map((opt) => (
            <button
              key={opt.value}
              type="button"
              onClick={() => runAction(opt.value)}
              className="block w-full whitespace-nowrap px-3 py-1.5 text-left text-[9px] tracking-wide text-text-secondary transition-colors hover:bg-border/30 hover:text-text-primary"
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}

      {error && <div className="mt-1 whitespace-nowrap text-[9px] text-accent-red">{error}</div>}
    </div>
  )
}
