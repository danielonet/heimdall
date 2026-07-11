import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../lib/api'

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    // /api/health returns 503 for a meaningful "degraded" state, not a
    // transient failure — read the body regardless of status code.
    queryFn: async () => (await apiFetch('/health')).json(),
    refetchInterval: 15000,
  })
}
