import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function usePorts() {
  return useQuery({
    queryKey: ['ports'],
    queryFn: () => apiJson('/ports'),
    select: (data) => data.ports,
    refetchInterval: 15000,
  })
}
