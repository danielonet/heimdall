import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

// { switches: [catalog entries], max_switches } — what the form offers.
export function useSwitchCatalog() {
  return useQuery({
    queryKey: ['switches', 'catalog'],
    queryFn: () => apiJson('/switches/catalog'),
    staleTime: Infinity,
  })
}

export function useSwitches() {
  return useQuery({
    queryKey: ['switches', 'list'],
    queryFn: () => apiJson('/switches'),
    select: (data) => data.switches,
    refetchInterval: 15000,
  })
}

// The latest reading of each port. Only fetched while its panel is open.
export function useSwitchPorts(id, enabled) {
  return useQuery({
    queryKey: ['switches', 'ports', id],
    queryFn: () => apiJson(`/switches/${id}/ports`),
    select: (data) => data.ports,
    enabled,
    refetchInterval: 15000,
  })
}

function useInvalidate() {
  const qc = useQueryClient()
  return () => {
    qc.invalidateQueries({ queryKey: ['switches', 'list'] })
    qc.invalidateQueries({ queryKey: ['devices'] })
  }
}

// Create (no id) or update (with id). A blank password keeps the stored one.
export function useSaveSwitch() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ id, ...body }) =>
      id
        ? apiJson(`/switches/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
        : apiJson('/switches', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: invalidate,
  })
}

export function useRemoveSwitch() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ id }) => apiJson(`/switches/${id}`, { method: 'DELETE' }),
    onSuccess: invalidate,
  })
}

// Logs in for real: { ok, model, firmware, ports, ports_up, macs, single_device_ports } or { ok: false, error }.
export function useTestSwitch() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ id }) => apiJson(`/switches/${id}/test`, { method: 'POST' }),
    onSettled: invalidate,
  })
}
