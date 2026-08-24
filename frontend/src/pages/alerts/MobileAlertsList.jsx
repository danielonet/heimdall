import { Link } from 'react-router-dom'
import { SeverityBar } from '../../components/SeverityBar'
import { Badge } from '../../components/Badge'
import { MacAddress } from '../../components/MacAddress'
import { TimeAgo } from '../../components/TimeAgo'
import { AlertActionsMenu } from '../../components/alerts/AlertActionsMenu'
import { MitigationNote } from '../../components/alerts/MitigationNote'
import { RemoteIpNote } from '../../components/alerts/RemoteIpNote'
import { isStale } from '../../lib/alertStaleness'

const FILTER_GROUPS = [
  ['SEVERITY', [['all', 'ALL'], ['CRITICAL', 'CRIT'], ['WARNING', 'WARN'], ['INFO', 'INFO']], 'severity', 'setSeverity'],
  ['STATUS', [['all', 'ALL'], ['open', 'OPEN'], ['acked', 'ACKED']], 'ackFilter', 'setAckFilter'],
  ['RANGE', [['24h', '24H'], ['7d', '7D'], ['all', 'ALL']], 'range', 'setRange'],
]

export function MobileAlertsList({ alerts, total, perPage, isLoading, filters, setSeverity, setAckFilter, setRange, setPage, staleHours }) {
  const totalPages = Math.max(1, Math.ceil(total / perPage))
  const setters = { setSeverity, setAckFilter, setRange }

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-1.5">
        {FILTER_GROUPS.map(([label, options, filterKey, setterKey]) => (
          <div key={label} className="flex gap-1.5 overflow-x-auto">
            {options.map(([val, text]) => (
              <button
                key={val}
                type="button"
                onClick={() => setters[setterKey](val)}
                className={`flex-shrink-0 whitespace-nowrap border px-2 py-1 text-[9px] tracking-wider ${
                  filters[filterKey] === val
                    ? 'border-accent-green/40 bg-accent-green/10 text-accent-green'
                    : 'border-border text-text-muted'
                }`}
              >
                {text}
              </button>
            ))}
          </div>
        ))}
      </div>

      <div className="text-[9px] tracking-wide text-text-muted">{total} ALERTS</div>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}
      {!isLoading && alerts.length === 0 && (
        <div className="text-[10px] text-text-muted">No alerts match these filters.</div>
      )}

      <div>
        {alerts.map((a) => (
          <div key={a.id} className="flex gap-2 border-b border-border/50 py-2.5 last:border-none">
            <SeverityBar severity={a.severity} />
            <div className="min-w-0 flex-1">
              <div className="text-[11px] text-text-primary">
                {a.alert_type.replaceAll('_', ' ')}
                {a.occurrence_count > 1 && (
                  <span className="ml-2 text-[9px] text-text-muted">×{a.occurrence_count}</span>
                )}
              </div>
              <div className="text-[9px] text-text-secondary">{a.description}</div>
              <MitigationNote text={a.mitigation} />
              <RemoteIpNote rawData={a.raw_data} />
              <div className="mt-1 flex items-center gap-2 text-[9px] text-text-muted">
                {a.device_mac && (
                  <Link to={`/devices/${a.device_mac}`} className="text-accent-blue">
                    <MacAddress mac={a.device_mac} />
                  </Link>
                )}
                <TimeAgo iso={a.created_at} />
              </div>
            </div>
            <div className="flex flex-shrink-0 flex-col items-end gap-1">
              {a.resolved ? (
                <Badge variant="success">DONE</Badge>
              ) : a.acknowledged ? (
                <Badge variant="info">ACKED</Badge>
              ) : isStale(a.last_seen ?? a.created_at, staleHours) ? (
                <Badge variant="muted">STALE</Badge>
              ) : (
                <Badge variant="danger">OPEN</Badge>
              )}
              <AlertActionsMenu alert={a} />
            </div>
          </div>
        ))}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 pb-2 text-[10px] text-text-muted">
          <button
            type="button"
            disabled={filters.page <= 1}
            onClick={() => setPage(filters.page - 1)}
            className="border border-border px-2 py-1 disabled:opacity-30"
          >
            PREV
          </button>
          <span>
            {filters.page}/{totalPages}
          </span>
          <button
            type="button"
            disabled={filters.page >= totalPages}
            onClick={() => setPage(filters.page + 1)}
            className="border border-border px-2 py-1 disabled:opacity-30"
          >
            NEXT
          </button>
        </div>
      )}
    </div>
  )
}
