import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useAlerts(params = {}) {
  const search = new URLSearchParams(params).toString()
  return useQuery({
    queryKey: ['alerts', params],
    queryFn: () => apiJson(`/alerts${search ? `?${search}` : ''}`),
    refetchInterval: 15000,
  })
}
