import { Link } from 'react-router-dom'
import { Badge } from '../Badge'

const SEVERITY_VARIANT = { CRITICAL: 'danger', WARNING: 'warning', INFO: 'info' }

/** One row per alert_type — same shape as the digest email's own grouping
 * (see sentinel/notifications/digest.py:DigestTypeGroup and its own
 * docstring for why: a burst of one repeating type must cost one row, not
 * flood the list). Unlike the email this isn't capped — a scrollable page
 * has no MAX_ALERT_TYPES-style space limit to respect. */
export function ReportAlertGroups({ groups, total, severityCounts }) {
  if (total === 0) {
    return (
      <div className="p-4 text-center text-[10px] tracking-wider text-text-muted">
        ALL CLEAR — no alerts in this window.
      </div>
    )
  }

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-border/50 p-3">
        {Object.entries(severityCounts)
          .sort(([, a], [, b]) => b - a)
          .map(([severity, count]) => (
            <Badge key={severity} variant={SEVERITY_VARIANT[severity] || 'muted'}>
              {count} {severity}
            </Badge>
          ))}
      </div>
      <div className="overflow-x-auto">
      <table className="w-full text-left text-[10px]">
        <thead>
          <tr className="text-[9px] tracking-wider text-text-muted">
            <th className="px-3 py-2 font-normal">SEVERITY</th>
            <th className="px-3 py-2 font-normal">TYPE</th>
            <th className="px-3 py-2 font-normal">COUNT</th>
            <th className="px-3 py-2 font-normal">DESCRIPTION</th>
            <th className="px-3 py-2 text-right font-normal">LATEST</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((g) => (
            <tr key={g.alert_type} className="border-t border-border/50">
              <td className="px-3 py-2 align-top">
                <Badge variant={SEVERITY_VARIANT[g.severity] || 'muted'}>{g.severity}</Badge>
              </td>
              <td className="px-3 py-2 align-top font-mono whitespace-nowrap text-text-primary">{g.alert_type}</td>
              <td className="px-3 py-2 align-top whitespace-nowrap text-text-secondary">
                {g.count} across {g.device_count} device{g.device_count === 1 ? '' : 's'}
              </td>
              <td className="px-3 py-2 align-top leading-relaxed text-text-secondary">
                {g.latest_description || g.alert_type}
              </td>
              <td className="px-3 py-2 align-top whitespace-nowrap text-right text-text-muted">
                {g.latest_created_at ? new Date(g.latest_created_at).toLocaleString() : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
      <div className="border-t border-border/50 p-2 text-right">
        <Link to="/alerts" className="text-[9px] tracking-wider text-accent-blue hover:underline">
          VIEW ALL IN ALERTS →
        </Link>
      </div>
    </div>
  )
}
