import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function BlockButton({ mac, disabled }) {
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: () => apiJson(`/devices/${mac}/block`, { method: 'POST' }),
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
      className="border border-accent-red/30 bg-accent-red/5 px-2 py-0.5 text-[9px] tracking-wider text-accent-red transition-colors hover:bg-accent-red/20 disabled:opacity-40"
    >
      {mutation.isPending ? '···' : '⊘ BLOCK'}
    </button>
  )
}
