import { Link } from 'react-router-dom'
import { SeverityBar } from '../../components/SeverityBar'
import { Badge } from '../../components/Badge'
import { MacAddress } from '../../components/MacAddress'
import { TimeAgo } from '../../components/TimeAgo'
import { BulkAckResolveButtons } from '../../components/alerts/BulkAckResolveButtons'
import { isStale } from '../../lib/alertStaleness'

export function DesktopAlertGroupsList({ groups, isLoading, staleHours }) {
  return (
    <div className="border border-border bg-surface">
      {isLoading && <div className="p-4 text-center text-[10px] text-text-muted">Loading…</div>}
      {!isLoading && groups.length === 0 && (
        <div className="p-4 text-center text-[10px] text-text-muted">No alerts match these filters.</div>
      )}
      {groups.map((g) => (
        <div
          key={`${g.device_mac}:${g.alert_type}`}
          className="flex items-center gap-3 border-b border-border/50 p-3 last:border-none"
        >
          <SeverityBar severity={g.severity} />
          <div className="w-40 flex-shrink-0 text-[10px]">
            {g.device_mac ? (
              <Link to={`/devices/${g.device_mac}`} className="text-accent-blue hover:underline">
                {g.hostname || <MacAddress mac={g.device_mac} />}
              </Link>
            ) : (
              <span className="text-text-muted">Unknown device</span>
            )}
          </div>
          <div className="min-w-0 flex-1 text-[11px] text-text-primary">
            {g.alert_type.replaceAll('_', ' ')}
          </div>
          <div className="w-16 flex-shrink-0 text-center text-[11px] text-text-secondary">{g.count}×</div>
          <div className="w-28 flex-shrink-0 text-[9px] text-text-muted">
            first <TimeAgo iso={g.first_seen} />
          </div>
          <div className="w-28 flex-shrink-0 text-[9px] text-text-muted">
            last <TimeAgo iso={g.last_seen} />
          </div>
          <div className="w-20 flex-shrink-0">
            {g.unresolved_count === 0 ? (
              <Badge variant="success">RESOLVED</Badge>
            ) : g.unacknowledged_count === 0 ? (
              <Badge variant="info">ACKED</Badge>
            ) : isStale(g.last_seen, staleHours) ? (
              <Badge variant="muted" title={`No new occurrence in over ${staleHours}h`}>STALE</Badge>
            ) : (
              <Badge variant="danger">OPEN</Badge>
            )}
          </div>
          <BulkAckResolveButtons
            deviceMac={g.device_mac}
            alertType={g.alert_type}
            unacknowledgedCount={g.unacknowledged_count}
            unresolvedCount={g.unresolved_count}
          />
        </div>
      ))}
    </div>
  )
}
