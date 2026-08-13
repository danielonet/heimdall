import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useDeviceTypeProfiles() {
  return useQuery({
    queryKey: ['deviceTypeProfiles'],
    queryFn: () => apiJson('/device-type-profiles'),
    select: (data) => data.profiles,
    refetchInterval: 15000,
  })
}

/** Same underlying request/cache as useDeviceTypeProfiles (identical
 * queryKey — react-query dedupes, so this doesn't cost a second fetch) —
 * just a different `select` onto the same response. The backend only
 * recomputes this hourly (SentinelScheduler._observed_extremes_job), but
 * polling alongside the profiles list is cheap since it's the same request. */
export function useObservedThresholdExtremes() {
  return useQuery({
    queryKey: ['deviceTypeProfiles'],
    queryFn: () => apiJson('/device-type-profiles'),
    select: (data) => data.observed_extremes,
    refetchInterval: 15000,
  })
}

export function useUpsertDeviceTypeProfile() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ deviceType, ...fields }) =>
      apiJson(`/device-type-profiles/${encodeURIComponent(deviceType)}`, {
        method: 'PUT',
        body: JSON.stringify(fields),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deviceTypeProfiles'] }),
  })
}

export function useDeleteDeviceTypeProfile() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (deviceType) =>
      apiJson(`/device-type-profiles/${encodeURIComponent(deviceType)}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deviceTypeProfiles'] }),
  })
}
