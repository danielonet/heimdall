import { useLayoutMode } from '../hooks/useLayoutMode'
import { useDevices } from '../hooks/useDevices'
import { useAlerts } from '../hooks/useAlerts'
import { useHealth } from '../hooks/useHealth'
import { usePorts } from '../hooks/usePorts'
import { computeThreatScore } from '../lib/threatScore'
import { DesktopDashboard } from './dashboard/DesktopDashboard'
import { MobileDashboard } from './dashboard/MobileDashboard'

export function DashboardPage() {
  const mode = useLayoutMode()
  const { data: devices } = useDevices()
  const { data: alertsPage } = useAlerts({ acknowledged: 'false', per_page: '20' })
  const { data: health } = useHealth()
  const { data: ports } = usePorts()

  const alerts = alertsPage?.alerts || []
  const criticalAlert = alerts.find((a) => a.severity === 'CRITICAL')

  const sharedProps = {
    devices: devices || [],
    alerts,
    criticalAlert,
    threatScore: computeThreatScore(alerts),
    health,
    ports: ports || [],
    alertsTotal: alertsPage?.total ?? 0,
  }

  return mode === 'mobile' ? <MobileDashboard {...sharedProps} /> : <DesktopDashboard {...sharedProps} />
}
