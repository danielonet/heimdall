import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useSettings() {
  return useQuery({
    queryKey: ['settings'],
    queryFn: () => apiJson('/settings'),
    refetchInterval: 15000,
  })
}

export function useUpdateSettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body) => apiJson('/settings', { method: 'PATCH', body: JSON.stringify(body) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings'] }),
  })
}

export function usePurgeDatabase() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (password) => apiJson('/settings/purge', { method: 'POST', body: JSON.stringify({ password }) }),
    onSuccess: () => {
      // Every view of learned state must reflect the wipe immediately, not
      // just on the next 15s poll — a stale "92 devices" on screen right
      // after a purge would look like the purge silently failed.
      qc.invalidateQueries({ queryKey: ['devices'] })
      qc.invalidateQueries({ queryKey: ['device'] })
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['alertGroups'] })
      qc.invalidateQueries({ queryKey: ['ports'] })
      qc.invalidateQueries({ queryKey: ['settings'] })
    },
  })
}
