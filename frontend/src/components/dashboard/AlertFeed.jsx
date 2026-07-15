import { useNavigate } from 'react-router-dom'
import { SeverityBar } from '../SeverityBar'
import { TimeAgo } from '../TimeAgo'

export function AlertFeed({ alerts, limit = 6 }) {
  const navigate = useNavigate()
  const items = (alerts || []).slice(0, limit)

  if (items.length === 0) {
    return <div className="text-[10px] text-text-muted">No open alerts.</div>
  }

  return (
    <div>
      {items.map((a) => (
        <div
          key={a.id}
          onClick={() => a.device_mac && navigate(`/devices/${a.device_mac}`)}
          className={`flex gap-2 border-b border-border/50 py-1.5 last:border-none ${
            a.device_mac ? 'cursor-pointer hover:bg-border/20' : ''
          }`}
        >
          <SeverityBar severity={a.severity} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-[10px] text-text-primary">{a.alert_type.replaceAll('_', ' ')}</div>
            <div className="truncate text-[9px] text-text-secondary">{a.description}</div>
          </div>
          <div className="flex-shrink-0 text-[9px] text-text-muted">
            <TimeAgo iso={a.created_at} />
          </div>
        </div>
      ))}
    </div>
  )
}
