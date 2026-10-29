import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useWifiSightings() {
  return useQuery({
    queryKey: ['wifi', 'sightings'],
    queryFn: () => apiJson('/wifi/sightings'),
    select: (data) => data.sightings,
    refetchInterval: 15000,
  })
}

export function useMonitorInterfaces() {
  return useQuery({
    queryKey: ['wifi', 'monitor-interfaces'],
    queryFn: () => apiJson('/wifi/monitor-interfaces'),
    select: (data) => data.interfaces,
  })
}

export function useWifiNetworks() {
  return useQuery({
    queryKey: ['wifi', 'networks'],
    queryFn: () => apiJson('/wifi/networks'),
    select: (data) => data.networks,
    refetchInterval: 15000,
  })
}

export function useMarkSightingMine() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ mac, isMine }) =>
      apiJson(`/wifi/sightings/${mac}`, { method: 'PATCH', body: JSON.stringify({ is_mine: isMine }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['wifi', 'sightings'] }),
  })
}

// Reads the router's SSIDs and the access points the monitor adapter hears with those names. Nothing is saved;
// it is a mutation (not a query) because the admin asks for it and the router call is slow.
export function useWifiSuggestions() {
  return useMutation({ mutationFn: () => apiJson('/wifi/suggestions') })
}
