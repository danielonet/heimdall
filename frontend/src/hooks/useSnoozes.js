import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useSnoozes(mac) {
  return useQuery({
    queryKey: ['snoozes', mac],
    queryFn: () => apiJson(`/devices/${mac}/snoozes`),
    select: (data) => data.snoozes,
    enabled: !!mac,
  })
}
