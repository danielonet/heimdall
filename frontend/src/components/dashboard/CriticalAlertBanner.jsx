import { Link } from 'react-router-dom'
import { BlockButton } from '../BlockButton'

export function CriticalAlertBanner({ alert }) {
  if (!alert) return null

  return (
    <div className="border border-accent-red/30 bg-accent-red/5 p-4">
      <div className="mb-2 text-[9px] tracking-[2px] text-accent-red">CRITICAL ACTION REQUIRED</div>
      <div className="mb-1 text-sm text-text-primary">{alert.description}</div>
      <div className="mb-3 text-[9px] text-text-muted">
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
