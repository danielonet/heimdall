import { useMemo, useState } from 'react'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { useAlerts } from '../hooks/useAlerts'
import { useAlertGroups } from '../hooks/useAlertGroups'
import { useSettings } from '../hooks/useSettings'
import { DesktopAlertsList } from './alerts/DesktopAlertsList'
import { MobileAlertsList } from './alerts/MobileAlertsList'
import { DesktopAlertGroupsList } from './alerts/DesktopAlertGroupsList'
import { MobileAlertGroupsList } from './alerts/MobileAlertGroupsList'
import { ClearAlertsButton } from '../components/alerts/ClearAlertsButton'

const PER_PAGE = 25

function rangeStartIso(range) {
  if (range === '24h') return new Date(Date.now() - 24 * 3600_000).toISOString()
  if (range === '7d') return new Date(Date.now() - 7 * 24 * 3600_000).toISOString()
  return null // 'all'
}

// Mirrors the currently-active severity/ack/range filters into a CSV export
// URL — the export always grabs every matching row (no pagination), so page
// isn't part of this. GET /api/alerts/export isn't JWT-protected (same
// posture as the other alert GET routes), so a plain navigation triggers the
// download without needing to attach an auth header.
function buildExportUrl({ severity, ackFilter, range }) {
  const params = new URLSearchParams()
  if (severity !== 'all') params.set('severity', severity)
  if (ackFilter === 'open') params.set('acknowledged', 'false')
  if (ackFilter === 'acked') params.set('acknowledged', 'true')
  const from = rangeStartIso(range)
  if (from) params.set('from', from)
  const qs = params.toString()
  return `/api/alerts/export${qs ? `?${qs}` : ''}`
}

export function AlertsPage() {
  const mode = useLayoutMode()
  const { data: appSettings } = useSettings()
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
    staleHours: appSettings?.alert_stale_hours,
  }

  const ViewToggle = (
    <div className="flex flex-wrap items-center gap-1.5">
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
      <a
        href={buildExportUrl({ severity, ackFilter, range })}
        title="Download the alerts matching the current filters as CSV"
        className="border border-border px-2 py-1 text-[9px] tracking-wider text-text-muted transition-colors hover:text-text-secondary"
      >
        EXPORT CSV
      </a>
      <ClearAlertsButton
        label="CLEAR ALERTS…"
        className="ml-auto border border-accent-red/30 bg-accent-red/5 px-2 py-1 text-[9px] tracking-wider text-accent-red transition-colors hover:bg-accent-red/20"
      />
    </div>
  )

  if (view === 'grouped') {
    const GroupsList = mode === 'mobile' ? MobileAlertGroupsList : DesktopAlertGroupsList
    return (
      <div className={mode === 'mobile' ? 'space-y-3' : 'space-y-4 p-4'}>
        {ViewToggle}
        <GroupsList groups={groups || []} isLoading={isGroupsLoading} staleHours={appSettings?.alert_stale_hours} />
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
