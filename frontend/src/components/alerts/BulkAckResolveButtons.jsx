import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../../lib/api'

export function BulkAckResolveButtons({ deviceMac, alertType, unacknowledgedCount, unresolvedCount }) {
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (body) =>
      apiJson('/alerts/bulk', {
        method: 'PATCH',
        body: JSON.stringify({ device_mac: deviceMac, alert_type: alertType, ...body }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['alertGroups'] })
      qc.invalidateQueries({ queryKey: ['device'] })
    },
  })

  return (
    <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
      {unacknowledgedCount > 0 && (
        <button
          type="button"
          disabled={mutation.isPending}
          onClick={() => mutation.mutate({ acknowledged: true })}
          className="whitespace-nowrap border border-accent-blue/30 bg-accent-blue/5 px-2 py-0.5 text-[9px] tracking-wider text-accent-blue transition-colors hover:bg-accent-blue/20 disabled:opacity-40"
        >
          ACK ALL ({unacknowledgedCount})
        </button>
      )}
      {unresolvedCount > 0 && (
        <button
          type="button"
          disabled={mutation.isPending}
          onClick={() => mutation.mutate({ resolved: true })}
          className="whitespace-nowrap border border-accent-green/30 bg-accent-green/5 px-2 py-0.5 text-[9px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
        >
          RESOLVE ALL ({unresolvedCount})
        </button>
      )}
    </div>
  )
}
