import { SeverityBar } from '../SeverityBar'
import { TimeAgo } from '../TimeAgo'
import { Badge } from '../Badge'
import { AckResolveButtons } from '../alerts/AckResolveButtons'
import { MitigationNote } from '../alerts/MitigationNote'

export function AlertHistoryTable({ alerts }) {
  if (!alerts?.length) {
    return <div className="text-[10px] text-text-muted">No alerts for this device.</div>
  }

  return (
    <div>
      {alerts.map((a) => (
        <div key={a.id} className="flex items-center gap-2 border-b border-border/50 py-2 last:border-none">
          <SeverityBar severity={a.severity} />
          <div className="min-w-0 flex-1">
            <div className="text-[10px] text-text-primary">{a.alert_type.replaceAll('_', ' ')}</div>
            <div className="text-[9px] text-text-secondary">{a.description}</div>
            <MitigationNote text={a.mitigation} />
          </div>
          <div className="flex flex-shrink-0 flex-col items-end gap-1">
            <span className="text-[9px] text-text-muted">
              <TimeAgo iso={a.created_at} />
            </span>
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
  )
}
