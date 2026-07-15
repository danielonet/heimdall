import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../../lib/api'

export function AckResolveButtons({ alert }) {
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (body) => apiJson(`/alerts/${alert.id}`, { method: 'PATCH', body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['device'] })
    },
  })

  return (
    <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
      {!alert.acknowledged && (
        <button
          type="button"
          disabled={mutation.isPending}
          onClick={() => mutation.mutate({ acknowledged: true })}
          className="border border-accent-blue/30 bg-accent-blue/5 px-2 py-0.5 text-[9px] tracking-wider text-accent-blue transition-colors hover:bg-accent-blue/20 disabled:opacity-40"
        >
          ACK
        </button>
      )}
      {!alert.resolved && (
        <button
          type="button"
          disabled={mutation.isPending}
          onClick={() => mutation.mutate({ resolved: true })}
          className="border border-accent-green/30 bg-accent-green/5 px-2 py-0.5 text-[9px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
        >
          RESOLVE
        </button>
      )}
    </div>
  )
}
