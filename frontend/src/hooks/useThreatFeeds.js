import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useThreatFeeds() {
  return useQuery({
    queryKey: ['threat-feeds'],
    queryFn: () => apiJson('/threats/feeds'),
    select: (data) => data.feeds,
    refetchInterval: 60000,
  })
}
