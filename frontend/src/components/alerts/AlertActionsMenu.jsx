import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../../lib/api'

const SELECT_CLASS =
  'flex-shrink-0 border border-border bg-surface px-2 py-1 text-[9px] tracking-wider text-text-muted outline-none transition-colors hover:bg-border/20 disabled:opacity-40'

/** One dropdown replacing what used to be a row of individually-conditional
 * buttons (ACK, RESOLVE/REOPEN, SNOOZE + its duration picker, and now ADD
 * EXCEPTION) — a single alert row was accumulating up to four buttons at
 * once. Every option here is exactly one of those old buttons; picking one
 * fires the same request the button used to, then the select resets back
 * to its placeholder (this is a menu, not a persistent form control — there
 * is no "current selection" to hold onto between actions). Current status
 * (acknowledged/resolved/snoozed) is still shown as a badge next to this,
 * same as before — this only replaced the *actions*, not the status display.
 *
 * `isSnoozed` is opt-in (default false, no "Cancel snooze" option) rather
 * than derived here — knowing it requires a per-device useSnoozes() fetch,
 * which is cheap on the device detail page (one device) but would mean one
 * extra query per distinct device_mac on a mixed-device alerts list. Pass
 * it explicitly only where that state is already being fetched anyway. */
export function AlertActionsMenu({ alert, isSnoozed = false }) {
  const qc = useQueryClient()
  const [value, setValue] = useState('')

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

  function handleChange(action) {
    setValue('')
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
    <div className="flex flex-col items-end gap-0.5" onClick={(e) => e.stopPropagation()}>
      <select
        value={value}
        disabled={isPending}
        onChange={(e) => handleChange(e.target.value)}
        className={SELECT_CLASS}
      >
        <option value="" disabled>
          {isPending ? '···' : 'ACTIONS ▾'}
        </option>
        {!alert.acknowledged && <option value="acknowledge">Acknowledge</option>}
        {!alert.resolved && <option value="resolve">Resolve</option>}
        {alert.resolved && <option value="reopen">Reopen</option>}
        {canSnooze && <option value="snooze_1h">Snooze 1h</option>}
        {canSnooze && <option value="snooze_24h">Snooze 24h</option>}
        {canSnooze && <option value="snooze_7d">Snooze 7d</option>}
        {isSnoozed && <option value="unsnooze">Cancel snooze</option>}
        {canException && <option value="exception">Add exception (allow this port)</option>}
      </select>
      {error && <span className="text-[9px] text-accent-red">{error}</span>}
    </div>
  )
}
