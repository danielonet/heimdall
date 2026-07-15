import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useAlertGroups(params = {}, options = {}) {
  const search = new URLSearchParams(params).toString()
  return useQuery({
    queryKey: ['alertGroups', params],
    queryFn: () => apiJson(`/alerts/grouped${search ? `?${search}` : ''}`),
    select: (data) => data.groups,
    refetchInterval: 15000,
    ...options,
  })
}
