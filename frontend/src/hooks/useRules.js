import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useRules() {
  return useQuery({
    queryKey: ['rules'],
    queryFn: () => apiJson('/rules'),
    select: (data) => data.rules,
  })
}
