import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

/** GET /api/reports — the on-demand equivalent of the daily digest email,
 * scoped to [start, end) x optional deviceMac. start/end are ISO strings
 * (toISOString() output — always UTC/'Z'-suffixed, matches sentinel/api/
 * routes/reports.py:_parse_timestamp's fromisoformat parse). Not on the
 * app's usual 15s refetchInterval — this is an ad-hoc report the user
 * pulls up, not live-updating dashboard data. */
export function useReport({ start, end, deviceMac }) {
  const params = new URLSearchParams()
  if (start) params.set('start', start)
  if (end) params.set('end', end)
  if (deviceMac) params.set('device_mac', deviceMac)

  return useQuery({
    queryKey: ['reports', start, end, deviceMac || null],
    queryFn: () => apiJson(`/reports?${params.toString()}`),
    enabled: Boolean(start && end),
  })
}
