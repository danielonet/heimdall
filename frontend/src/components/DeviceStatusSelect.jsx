import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

// One dropdown instead of the old TRUSTED/SUSPECT toggle plus QUARANTINE and
// BLOCK buttons. The four values are what an admin actually decides about a
// device: block wins over quarantine, quarantine over the trust flag.
const OPTIONS = [
  ['trusted', 'TRUSTED'],
  ['suspect', 'SUSPECT'],
  ['quarantined', 'QUARANTINED'],
  ['blocked', 'BLOCKED'],
]

const TONE = {
  trusted: 'border-accent-green/30 bg-accent-green/5 text-accent-green',
  suspect: 'border-accent-amber/30 bg-accent-amber/5 text-accent-amber',
  quarantined: 'border-accent-amber/30 bg-accent-amber/5 text-accent-amber',
  blocked: 'border-accent-red/30 bg-accent-red/5 text-accent-red',
}

const TITLE = {
  trusted: 'Trusted: known device, no action taken',
  suspect: 'Suspect: not yet trusted, watched like any unknown device',
  quarantined: 'Quarantined: internet access cut, still reachable on the LAN',
  blocked: 'Blocked: cut off the network at the router',
}

/** The single state a device is in: blocked > quarantined > trusted/suspect. */
export function deviceStatus(d) {
  if (d.is_blocked) return 'blocked'
  if (d.is_quarantined) return 'quarantined'
  return d.is_trusted ? 'trusted' : 'suspect'
}

/** Moves a device to `target` with the existing per-action endpoints, undoing
 * whatever block or quarantine is in the way first. Trusting or marking a
 * device suspect also lifts a block or quarantine, since those are the
 * stronger states. Choosing quarantine or block leaves the trust flag alone. */
async function applyStatus(d, target) {
  const mac = d.mac_address
  const post = (action) => apiJson(`/devices/${mac}/${action}`, { method: 'POST' })
  const wantsRelease = target === 'trusted' || target === 'suspect'

  if (d.is_blocked && target !== 'blocked') await post('unblock')
  if (d.is_quarantined && (wantsRelease || target === 'blocked')) await post('unquarantine')

  if (wantsRelease) {
    const isTrusted = target === 'trusted'
    if (isTrusted !== Boolean(d.is_trusted)) {
      await apiJson(`/devices/${mac}`, { method: 'PATCH', body: JSON.stringify({ is_trusted: isTrusted }) })
    }
  } else if (target === 'quarantined') {
    await post('quarantine')
  } else if (target === 'blocked') {
    await post('block')
  }
}

export function DeviceStatusSelect({ device }) {
  const qc = useQueryClient()
  const current = deviceStatus(device)
  const mutation = useMutation({
    mutationFn: (target) => applyStatus(device, target),
    // A half-applied change (block lifted, quarantine refused) must show the
    // real state, so refresh whether the chain finished or failed midway.
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      qc.invalidateQueries({ queryKey: ['device', device.mac_address] })
    },
  })

  function onChange(e) {
    const target = e.target.value
    if (target === 'blocked' && !window.confirm('Block this device from the network?')) return
    mutation.mutate(target)
  }

  return (
    <span className="inline-flex flex-col items-start" onClick={(e) => e.stopPropagation()}>
      <select
        value={current}
        disabled={mutation.isPending}
        onChange={onChange}
        title={TITLE[current]}
        aria-label="Device status"
        className={`cursor-pointer border px-1.5 py-0.5 text-[9px] tracking-wider outline-none disabled:opacity-50 ${TONE[current]}`}
      >
        {OPTIONS.map(([value, label]) => (
          <option key={value} value={value} className="bg-bg text-text-primary">
            {label}
          </option>
        ))}
      </select>
      {mutation.isError && <span className="mt-0.5 text-[8px] text-accent-red">{mutation.error.message}</span>}
    </span>
  )
}
