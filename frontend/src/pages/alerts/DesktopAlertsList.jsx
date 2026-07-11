import { Link } from 'react-router-dom'
import { SeverityBar } from '../../components/SeverityBar'
import { Badge } from '../../components/Badge'
import { MacAddress } from '../../components/MacAddress'
import { TimeAgo } from '../../components/TimeAgo'
import { AlertHistogram } from '../../components/alerts/AlertHistogram'
import { AckResolveButtons } from '../../components/alerts/AckResolveButtons'

const SEVERITY_OPTIONS = [['all', 'ALL'], ['CRITICAL', 'CRITICAL'], ['WARNING', 'WARNING'], ['INFO', 'INFO']]
const ACK_OPTIONS = [['all', 'ALL'], ['open', 'OPEN'], ['acked', 'ACKED']]
const RANGE_OPTIONS = [['24h', '24H'], ['7d', '7D'], ['all', 'ALL TIME']]

function FilterGroup({ label, options, value, onChange }) {
  return (
    <div className="flex items-center gap-1">
      <span className="mr-1 text-[9px] tracking-wider text-text-muted">{label}</span>
      {options.map(([val, text]) => (
        <button
          key={val}
          type="button"
          onClick={() => onChange(val)}
          className={`border px-2 py-1 text-[9px] tracking-wider transition-colors ${
            value === val
              ? 'border-accent-green/40 bg-accent-green/10 text-accent-green'
              : 'border-border text-text-muted hover:text-text-secondary'
          }`}
        >
          {text}
        </button>
      ))}
    </div>
  )
}

export function DesktopAlertsList({
  alerts,
  total,
  perPage,
  isLoading,
  filters,
  setSeverity,
  setAckFilter,
  setRange,
  setPage,
  histogramAlerts,
}) {
  const totalPages = Math.max(1, Math.ceil(total / perPage))

  return (
    <div className="space-y-4 p-4">
      <div className="border border-border bg-surface p-4">
        <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">ALERT FREQUENCY (24H)</div>
        <AlertHistogram alerts={histogramAlerts} />
      </div>

      <div className="flex flex-wrap items-center gap-4 border border-border bg-surface p-3">
        <FilterGroup label="SEVERITY" options={SEVERITY_OPTIONS} value={filters.severity} onChange={setSeverity} />
        <FilterGroup label="STATUS" options={ACK_OPTIONS} value={filters.ackFilter} onChange={setAckFilter} />
        <FilterGroup label="RANGE" options={RANGE_OPTIONS} value={filters.range} onChange={setRange} />
        <span className="ml-auto text-[9px] tracking-wide text-text-muted">{total} ALERTS</span>
      </div>

      <div className="border border-border bg-surface">
        {isLoading && <div className="p-4 text-center text-[10px] text-text-muted">Loading…</div>}
        {!isLoading && alerts.length === 0 && (
          <div className="p-4 text-center text-[10px] text-text-muted">No alerts match these filters.</div>
        )}
        {alerts.map((a) => (
          <div key={a.id} className="flex items-center gap-3 border-b border-border/50 p-3 last:border-none">
            <SeverityBar severity={a.severity} />
            <div className="min-w-0 flex-1">
              <div className="text-[11px] text-text-primary">{a.alert_type.replaceAll('_', ' ')}</div>
              <div className="truncate text-[10px] text-text-secondary">{a.description}</div>
            </div>
            <div className="w-36 flex-shrink-0 text-[10px]">
              {a.device_mac ? (
                <Link to={`/devices/${a.device_mac}`} className="text-accent-blue hover:underline">
                  <MacAddress mac={a.device_mac} />
                </Link>
              ) : (
                <span className="text-text-muted">—</span>
              )}
            </div>
            <div className="w-16 flex-shrink-0 text-[9px] text-text-muted">
              <TimeAgo iso={a.created_at} />
            </div>
            <div className="w-20 flex-shrink-0">
              {a.resolved ? (
                <Badge variant="success">RESOLVED</Badge>
              ) : a.acknowledged ? (
                <Badge variant="info">ACKED</Badge>
              ) : (
                <Badge variant="danger">OPEN</Badge>
              )}
            </div>
            <AckResolveButtons alert={a} />
          </div>
        ))}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 text-[10px] text-text-muted">
          <button
            type="button"
            disabled={filters.page <= 1}
            onClick={() => setPage(filters.page - 1)}
            className="border border-border px-2 py-1 disabled:opacity-30"
          >
            PREV
          </button>
          <span>
            PAGE {filters.page} / {totalPages}
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
