import { useState } from 'react'
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
  // id, not the alert object itself — alertsPage refetches every 15s
  // (useAlerts), so a stored object reference would go stale the moment a
  // poll returns a new array; re-finding by id off the freshest alerts
  // means the panel picture updates live and silently reverts to the
  // default critical alert if the selected one gets acknowledged/resolved
  // out of this unacknowledged-only list.
  const [selectedAlertId, setSelectedAlertId] = useState(null)

  const alerts = alertsPage?.alerts || []
  const criticalAlert = alerts.find((a) => a.severity === 'CRITICAL')
  const selectedAlert = alerts.find((a) => a.id === selectedAlertId)

  const sharedProps = {
    devices: devices || [],
    alerts,
    bannerAlert: selectedAlert || criticalAlert,
    onSelectAlert: setSelectedAlertId,
    threatScore: computeThreatScore(alerts),
    health,
    ports: ports || [],
    alertsTotal: alertsPage?.total ?? 0,
  }

  return mode === 'mobile' ? <MobileDashboard {...sharedProps} /> : <DesktopDashboard {...sharedProps} />
}
