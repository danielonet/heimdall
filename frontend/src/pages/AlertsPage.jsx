import { useMemo, useState } from 'react'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { useAlerts } from '../hooks/useAlerts'
import { DesktopAlertsList } from './alerts/DesktopAlertsList'
import { MobileAlertsList } from './alerts/MobileAlertsList'

const PER_PAGE = 25

function rangeStartIso(range) {
  if (range === '24h') return new Date(Date.now() - 24 * 3600_000).toISOString()
  if (range === '7d') return new Date(Date.now() - 7 * 24 * 3600_000).toISOString()
  return null // 'all'
}

export function AlertsPage() {
  const mode = useLayoutMode()
  const [severity, setSeverityState] = useState('all')
  const [ackFilter, setAckFilterState] = useState('all')
  const [range, setRangeState] = useState('7d')
  const [page, setPage] = useState(1)

  // Any filter change resets to page 1 — a stale page number past the new result count would look like a bug.
  const setSeverity = (v) => { setSeverityState(v); setPage(1) }
  const setAckFilter = (v) => { setAckFilterState(v); setPage(1) }
  const setRange = (v) => { setRangeState(v); setPage(1) }

  // rangeStartIso() is millisecond-precision — computing it directly in the
  // render body would produce a new string (and thus a new useAlerts
  // queryKey) on every render, refetching forever. Memoize so it's stable
  // until the range filter itself actually changes.
  const from = useMemo(() => rangeStartIso(range), [range])
  const params = { page: String(page), per_page: String(PER_PAGE) }
  if (severity !== 'all') params.severity = severity
  if (ackFilter === 'open') params.acknowledged = 'false'
  if (ackFilter === 'acked') params.acknowledged = 'true'
  if (from) params.from = from

  const { data, isLoading } = useAlerts(params)
  // Independent of the table's active filters — the histogram always reflects
  // the last 24h overall, same as the Dashboard's metrics do. Computed once
  // per mount for the same reason as `from` above.
  const histogramFrom = useMemo(() => rangeStartIso('24h'), [])
  const { data: histogramPage } = useAlerts({ per_page: '200', from: histogramFrom })

  const sharedProps = {
    alerts: data?.alerts || [],
    total: data?.total || 0,
    perPage: PER_PAGE,
    isLoading,
    filters: { severity, ackFilter, range, page },
    setSeverity,
    setAckFilter,
    setRange,
    setPage,
    histogramAlerts: histogramPage?.alerts || [],
  }

  return mode === 'mobile' ? <MobileAlertsList {...sharedProps} /> : <DesktopAlertsList {...sharedProps} />
}
