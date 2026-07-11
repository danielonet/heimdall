import { useMutation } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

export function useIpLookup() {
  return useMutation({
    mutationFn: (ip) => apiJson(`/threats/lookup/${encodeURIComponent(ip)}`),
  })
}
