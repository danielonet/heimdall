import { Link } from 'react-router-dom'
import { SeverityBar } from '../SeverityBar'
import { TimeAgo } from '../TimeAgo'

// Whole row selects by default (loads this alert into the dashboard's
// SelectedAlertPanel via onSelect, without leaving the page) — a quick
// "what is this" glance shouldn't cost a navigation, and a big
// title+description click zone made "accidentally navigate instead of
// select" the common case rather than the exception (nearly the entire row
// used to be the "go to device" zone). Jumping to the device is now a
// small, deliberate target instead: the ">> DEVICE" link, only rendered
// when there's a device_mac to go to, with its own stopPropagation so
// clicking it doesn't also fire onSelect first.
export function AlertFeed({ alerts, limit = 6, onSelect }) {
  const items = (alerts || []).slice(0, limit)

  if (items.length === 0) {
    return <div className="text-[10px] text-text-muted">No open alerts.</div>
  }

  return (
    <div>
      {items.map((a) => (
        <div
          key={a.id}
          onClick={() => onSelect?.(a.id)}
          className="flex cursor-pointer items-center gap-2 border-b border-border/50 py-1.5 last:border-none hover:bg-border/20"
        >
          <SeverityBar severity={a.severity} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-[10px] text-text-primary">{a.alert_type.replaceAll('_', ' ')}</div>
            <div className="truncate text-[9px] text-text-secondary">{a.description}</div>
          </div>
          <div className="flex flex-shrink-0 flex-col items-end gap-0.5 text-[9px] text-text-muted">
            <TimeAgo iso={a.created_at} />
            {a.device_mac && (
              <Link
                to={`/devices/${a.device_mac}`}
                onClick={(e) => e.stopPropagation()}
                className="text-accent-blue hover:underline"
              >
                DEVICE →
              </Link>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}
