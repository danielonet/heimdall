import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function QuarantineButton({ mac, disabled }) {
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: () => apiJson(`/devices/${mac}/quarantine`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      qc.invalidateQueries({ queryKey: ['device', mac] })
    },
  })

  return (
    <button
      type="button"
      disabled={disabled || mutation.isPending}
      onClick={() => mutation.mutate()}
      title="Cut internet access but keep this device on the LAN — a softer response than a full block"
      className="border border-accent-amber/30 bg-accent-amber/5 px-2 py-0.5 text-[9px] tracking-wider text-accent-amber transition-colors hover:bg-accent-amber/20 disabled:opacity-40"
    >
      {mutation.isPending ? '···' : '◐ QUARANTINE'}
    </button>
  )
}
