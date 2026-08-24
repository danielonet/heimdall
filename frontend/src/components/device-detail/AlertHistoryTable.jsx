import { SeverityBar } from '../SeverityBar'
import { TimeAgo } from '../TimeAgo'
import { Badge } from '../Badge'
import { AlertActionsMenu } from '../alerts/AlertActionsMenu'
import { MitigationNote } from '../alerts/MitigationNote'
import { RemoteIpNote } from '../alerts/RemoteIpNote'
import { useSnoozes } from '../../hooks/useSnoozes'

function formatUntil(iso) {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

export function AlertHistoryTable({ mac, alerts }) {
  const { data: snoozes } = useSnoozes(mac)
  const snoozeByType = new Map((snoozes || []).map((s) => [s.alert_type, s]))

  if (!alerts?.length) {
    return <div className="text-[10px] text-text-muted">No alerts for this device.</div>
  }

  return (
    <div>
      {alerts.map((a) => {
        const snooze = snoozeByType.get(a.alert_type)
        return (
          <div key={a.id} className="flex items-center gap-2 border-b border-border/50 py-2 last:border-none">
            <SeverityBar severity={a.severity} />
            <div className="min-w-0 flex-1">
              <div className="text-[10px] text-text-primary">{a.alert_type.replaceAll('_', ' ')}</div>
              <div className="text-[9px] text-text-secondary">{a.description}</div>
              <MitigationNote text={a.mitigation} />
              <RemoteIpNote rawData={a.raw_data} />
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
              {snooze && (
                <span className="text-[9px] text-text-muted" title={`Snoozed until ${formatUntil(snooze.snoozed_until)}`}>
                  snoozed · {formatUntil(snooze.snoozed_until)}
                </span>
              )}
            </div>
            <AlertActionsMenu alert={a} isSnoozed={!!snooze} />
          </div>
        )
      })}
    </div>
  )
}
