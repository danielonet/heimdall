import { useQuery } from '@tanstack/react-query'
import { apiJson } from '../lib/api'

/** Backs the Services panel's hover card — description/version/size/last-
 * alert per service (see GET /api/service-details). Much slower cadence
 * than useHealth's 15s poll: a Postgres size query, a Redis INFO call, and
 * a clamd version probe are cheap once a minute, not worth paying on every
 * health tick when this is only ever looked at on hover. */
export function useServiceDetails() {
  return useQuery({
    queryKey: ['service-details'],
    queryFn: () => apiJson('/service-details'),
    staleTime: 60000,
    refetchInterval: 60000,
  })
}
