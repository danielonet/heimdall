import { useMemo, useState } from 'react'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { useDevices } from '../hooks/useDevices'
import { useAlerts } from '../hooks/useAlerts'
import { useSettings } from '../hooks/useSettings'
import { useHealth } from '../hooks/useHealth'
import { usePorts } from '../hooks/usePorts'
import { computeThreatScore } from '../lib/threatScore'
import { staleBeforeIso } from '../lib/alertStaleness'
import { DesktopDashboard } from './dashboard/DesktopDashboard'
import { MobileDashboard } from './dashboard/MobileDashboard'

export function DashboardPage() {
  const mode = useLayoutMode()
  const { data: devices } = useDevices()
  const { data: appSettings } = useSettings()
  // Memoized like AlertsPage.jsx's rangeStartIso — staleBeforeIso() reads
  // Date.now(), so calling it inline in the query params on every render
  // would mint a new ISO string (and thus a new useAlerts queryKey) every
  // render, refetching forever. Stable until alert_stale_hours itself changes.
  const staleFrom = useMemo(() => staleBeforeIso(appSettings?.alert_stale_hours), [appSettings?.alert_stale_hours])
  const alertParams = { acknowledged: 'false', per_page: '20', ...(staleFrom ? { from: staleFrom } : {}) }
  const { data: alertsPage } = useAlerts(alertParams)
  // Deliberately broader than alertParams above (no acknowledged/staleness
  // filter) — ServiceStatusPanel's ALERT state must not clear just because
  // a human acknowledged the finding or it's older than the staleness
  // setting; only alert.resolved should silence it. See ServiceStatusPanel.jsx.
  const { data: openAlertsPage } = useAlerts({ per_page: '100' })
  const { data: health } = useHealth()
  const { data: ports } = usePorts()
  // id, not the alert object itself — alertsPage refetches every 15s
  // (useAlerts), so a stored object reference would go stale the moment a
  // poll returns a new array; re-finding by id off the freshest alerts
  // means the panel picture updates live and silently reverts to the
  // default critical alert if the selected one gets acknowledged/resolved
  // out of this unacknowledged-only list.
  const [selectedAlertId, setSelectedAlertId] = useState(null)

  // `|| []` mints a new array on every render whenever alertsPage is still
  // undefined (before the first response lands), so memoize the fallback
  // itself rather than just the reduce below — otherwise a hook depending
  // on `alerts` can never prove it's stable. Empty-array identity churn
  // before the first response is harmless either way; this just keeps the
  // dependency clean for threatScore below.
  const alerts = useMemo(() => alertsPage?.alerts || [], [alertsPage])
  const criticalAlert = alerts.find((a) => a.severity === 'CRITICAL')
  const selectedAlert = alerts.find((a) => a.id === selectedAlertId)
  // Memoized so this reduce doesn't re-run on every unrelated re-render of
  // an ancestor — see DesktopShell's Clock fix.
  const threatScore = useMemo(() => computeThreatScore(alerts), [alerts])

  const sharedProps = {
    devices: devices || [],
    alerts,
    bannerAlert: selectedAlert || criticalAlert,
    onSelectAlert: setSelectedAlertId,
    threatScore,
    health,
    ports: ports || [],
    alertsTotal: alertsPage?.total ?? 0,
    openAlerts: openAlertsPage?.alerts || [],
  }

  return mode === 'mobile' ? <MobileDashboard {...sharedProps} /> : <DesktopDashboard {...sharedProps} />
}
