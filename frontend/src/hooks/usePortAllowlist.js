import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function usePortAllowlist() {
  return useQuery({
    queryKey: ['portAllowlist'],
    queryFn: () => apiJson('/port-allowlist'),
    refetchInterval: 15000,
  })
}

export function useAllowPort() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ mac, port, note }) =>
      apiJson(`/port-allowlist/${mac}/${port}`, { method: 'PUT', body: JSON.stringify({ note: note || null }) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['portAllowlist'] })
      // Allowlisting may have auto-unblocked the device and/or resolved its
      // HIGH_RISK_PORT_OPENED alert — both are visible elsewhere in the app.
      qc.invalidateQueries({ queryKey: ['devices'] })
      // Partial match (no mac given) — invalidates every open device-detail
      // query, not just one, since the mutation doesn't know which page a
      // user might currently have open.
      qc.invalidateQueries({ queryKey: ['device'] })
      qc.invalidateQueries({ queryKey: ['alerts'] })
    },
  })
}

export function useDisallowPort() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ mac, port }) => apiJson(`/port-allowlist/${mac}/${port}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['portAllowlist'] }),
  })
}
