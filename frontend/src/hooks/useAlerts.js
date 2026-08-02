import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useAlerts(params = {}, options = {}) {
  const search = new URLSearchParams(params).toString()
  return useQuery({
    queryKey: ['alerts', params],
    queryFn: () => apiJson(`/alerts${search ? `?${search}` : ''}`),
    refetchInterval: 15000,
    ...options,
  })
}

export function useClearAllAlerts() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiJson('/alerts', { method: 'DELETE' }),
    onSuccess: () => {
      // Every open view of the alert feed must reflect the clear immediately,
      // not just on the next 15s poll — same reasoning as usePurgeDatabase.
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['alertGroups'] })
    },
  })
}
