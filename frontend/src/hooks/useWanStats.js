import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useWanStats() {
  return useQuery({
    queryKey: ['wan-stats'],
    queryFn: () => apiJson('/wan-stats'),
    retry: false, // a 404 here means "not recorded yet" (unverified router xpath), not a transient hiccup
    refetchInterval: 15000,
  })
}
