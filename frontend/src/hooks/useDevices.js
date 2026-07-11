import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useDevices() {
  return useQuery({
    queryKey: ['devices'],
    queryFn: () => apiJson('/devices'),
    select: (data) => data.devices,
    refetchInterval: 15000,
  })
}

export function useDevice(mac) {
  return useQuery({
    queryKey: ['device', mac],
    queryFn: () => apiJson(`/devices/${mac}`),
    enabled: !!mac,
  })
}
