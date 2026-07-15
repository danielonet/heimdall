import { Link } from 'react-router-dom'
import { SeverityBar } from '../../components/SeverityBar'
import { Badge } from '../../components/Badge'
import { MacAddress } from '../../components/MacAddress'
import { TimeAgo } from '../../components/TimeAgo'
import { BulkAckResolveButtons } from '../../components/alerts/BulkAckResolveButtons'

export function MobileAlertGroupsList({ groups, isLoading }) {
  return (
    <div>
      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}
      {!isLoading && groups.length === 0 && (
        <div className="text-[10px] text-text-muted">No alerts match these filters.</div>
      )}
      {groups.map((g) => (
        <div key={`${g.device_mac}:${g.alert_type}`} className="flex gap-2 border-b border-border/50 py-2.5 last:border-none">
          <SeverityBar severity={g.severity} />
          <div className="min-w-0 flex-1">
            <div className="text-[11px] text-text-primary">
              {g.alert_type.replaceAll('_', ' ')} <span className="text-text-muted">× {g.count}</span>
            </div>
            <div className="mt-0.5 text-[9px] text-text-muted">
              {g.device_mac ? (
                <Link to={`/devices/${g.device_mac}`} className="text-accent-blue">
                  {g.hostname || <MacAddress mac={g.device_mac} />}
                </Link>
              ) : (
                'Unknown device'
              )}
            </div>
            <div className="mt-0.5 text-[9px] text-text-muted">
              last <TimeAgo iso={g.last_seen} />
            </div>
            <div className="mt-1.5">
              <BulkAckResolveButtons
                deviceMac={g.device_mac}
                alertType={g.alert_type}
                unacknowledgedCount={g.unacknowledged_count}
                unresolvedCount={g.unresolved_count}
              />
            </div>
          </div>
          <div className="flex-shrink-0">
            {g.unresolved_count === 0 ? (
              <Badge variant="success">RESOLVED</Badge>
            ) : g.unacknowledged_count === 0 ? (
              <Badge variant="info">ACKED</Badge>
            ) : (
              <Badge variant="danger">OPEN</Badge>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}
