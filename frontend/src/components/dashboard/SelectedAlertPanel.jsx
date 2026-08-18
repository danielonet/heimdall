import { Link } from 'react-router-dom'
import { BlockButton } from '../BlockButton'
import { MitigationNote } from '../alerts/MitigationNote'
import { RemoteIpNote } from '../alerts/RemoteIpNote'

// Severity-keyed styling — this panel shows whichever alert is "current":
// the single open CRITICAL alert by default (see DashboardPage), or
// whatever the user just clicked in AlertFeed, which can be any severity.
// Was CRITICAL-only styling (fixed red "CRITICAL ACTION REQUIRED" label)
// back when this only ever showed the one auto-picked critical alert.
const SEVERITY_STYLE = {
  CRITICAL: { border: 'border-accent-red/30', bg: 'bg-accent-red/5', text: 'text-accent-red', label: 'CRITICAL — ACTION REQUIRED' },
  WARNING: { border: 'border-accent-amber/30', bg: 'bg-accent-amber/5', text: 'text-accent-amber', label: 'WARNING — REVIEW RECOMMENDED' },
  INFO: { border: 'border-accent-blue/30', bg: 'bg-accent-blue/5', text: 'text-accent-blue', label: 'INFO' },
}

export function SelectedAlertPanel({ alert }) {
  if (!alert) return null

  const style = SEVERITY_STYLE[alert.severity] || SEVERITY_STYLE.INFO

  return (
    <div className={`border ${style.border} ${style.bg} p-4`}>
      <div className={`mb-2 text-[9px] tracking-[2px] ${style.text}`}>{style.label}</div>
      <div className="mb-1 text-sm text-text-primary">{alert.description}</div>
      <MitigationNote text={alert.mitigation} />
      <RemoteIpNote rawData={alert.raw_data} />
      <div className="mb-3 mt-2 text-[9px] text-text-muted">
        {alert.device_mac ? (
          <Link to={`/devices/${alert.device_mac}`} className="underline hover:text-text-secondary">
            {alert.device_mac}
          </Link>
        ) : (
          'Unknown device'
        )}{' '}
        · {alert.alert_type.replaceAll('_', ' ')}
      </div>
      {alert.device_mac && <BlockButton mac={alert.device_mac} />}
    </div>
  )
}
