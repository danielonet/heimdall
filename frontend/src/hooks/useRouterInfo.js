import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useRouterInfo() {
  return useQuery({
    queryKey: ['router-info'],
    queryFn: () => apiJson('/router'),
    retry: false, // 503/504/502 are real "adapter unreachable" states, not transient hiccups
    refetchInterval: 30000,
  })
}
