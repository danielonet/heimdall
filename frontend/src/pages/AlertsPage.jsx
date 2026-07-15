import { useMemo, useState } from 'react'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { useAlerts } from '../hooks/useAlerts'
import { useAlertGroups } from '../hooks/useAlertGroups'
import { DesktopAlertsList } from './alerts/DesktopAlertsList'
import { MobileAlertsList } from './alerts/MobileAlertsList'
import { DesktopAlertGroupsList } from './alerts/DesktopAlertGroupsList'
import { MobileAlertGroupsList } from './alerts/MobileAlertGroupsList'

const PER_PAGE = 25

function rangeStartIso(range) {
  if (range === '24h') return new Date(Date.now() - 24 * 3600_000).toISOString()
  if (range === '7d') return new Date(Date.now() - 7 * 24 * 3600_000).toISOString()
  return null // 'all'
}

export function AlertsPage() {
  const mode = useLayoutMode()
  // Grouped is the default view — a large detector flood (hundreds/thousands
  // of rows for the same device+type) is unusable as a flat paginated list.
  const [view, setViewState] = useState('grouped')
  const [severity, setSeverityState] = useState('all')
  const [ackFilter, setAckFilterState] = useState('all')
  const [range, setRangeState] = useState('7d')
  const [page, setPage] = useState(1)

  // Any filter change resets to page 1 — a stale page number past the new result count would look like a bug.
  const setView = (v) => { setViewState(v); setPage(1) }
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

  const groupParams = { ...params }
  delete groupParams.page
  delete groupParams.per_page

  // Only the active view's query needs to run — no point paginating a flat
  // list of thousands of rows in the background while the user is grouped.
  const { data, isLoading } = useAlerts(params, { enabled: view === 'list' })
  const { data: groups, isLoading: isGroupsLoading } = useAlertGroups(groupParams, { enabled: view === 'grouped' })
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

  const ViewToggle = (
    <div className="flex gap-1.5">
      {[['grouped', 'GROUPED'], ['list', 'LIST']].map(([val, text]) => (
        <button
          key={val}
          type="button"
          onClick={() => setView(val)}
          className={`border px-2 py-1 text-[9px] tracking-wider transition-colors ${
            view === val
              ? 'border-accent-green/40 bg-accent-green/10 text-accent-green'
              : 'border-border text-text-muted hover:text-text-secondary'
          }`}
        >
          {text}
        </button>
      ))}
    </div>
  )

  if (view === 'grouped') {
    const GroupsList = mode === 'mobile' ? MobileAlertGroupsList : DesktopAlertGroupsList
    return (
      <div className={mode === 'mobile' ? 'space-y-3' : 'space-y-4 p-4'}>
        {ViewToggle}
        <GroupsList groups={groups || []} isLoading={isGroupsLoading} />
      </div>
    )
  }

  return (
    <div>
      <div className={mode === 'mobile' ? 'px-0 pt-0' : 'p-4 pb-0'}>{ViewToggle}</div>
      {mode === 'mobile' ? <MobileAlertsList {...sharedProps} /> : <DesktopAlertsList {...sharedProps} />}
    </div>
  )
}
