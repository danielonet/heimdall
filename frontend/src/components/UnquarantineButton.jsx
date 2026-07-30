import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function UnquarantineButton({ mac, disabled }) {
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: () => apiJson(`/devices/${mac}/unquarantine`, { method: 'POST' }),
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
      className="border border-accent-green/30 bg-accent-green/5 px-2 py-0.5 text-[9px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
    >
      {mutation.isPending ? '···' : '✓ UNQUARANTINE'}
    </button>
  )
}
