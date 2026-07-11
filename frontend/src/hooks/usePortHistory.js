import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function usePortHistory(alias, { enabled = true } = {}) {
  return useQuery({
    queryKey: ['port-history', alias],
    queryFn: () => apiJson(`/ports/${alias}?limit=100`),
    select: (data) => data.history,
    enabled: enabled && !!alias,
  })
}
