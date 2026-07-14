import { MetricCard } from '../../components/MetricCard'
import { StatusDot } from '../../components/StatusDot'
import { TrafficDisplay } from '../../components/TrafficDisplay'
import { MacAddress } from '../../components/MacAddress'
import { Badge } from '../../components/Badge'
import { CriticalAlertBanner } from '../../components/dashboard/CriticalAlertBanner'
import { AlertFeed } from '../../components/dashboard/AlertFeed'
import { ServiceStatusPanel } from '../../components/dashboard/ServiceStatusPanel'
import { isDeviceOnline } from '../../lib/deviceFilters'

export function MobileDashboard({ devices, alerts, criticalAlert, threatScore, health, alertsTotal }) {
  const servicesOkCount = health
    ? Object.values(health.security_services || {}).filter((v) => v === true).length
    : null
  const onlineDevices = devices.filter(isDeviceOnline)
  const onlineCount = onlineDevices.length

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-2">
        <MetricCard label="DEVICES ONLINE" value={onlineCount} accent="green" />
        <MetricCard label="OPEN ALERTS" value={alertsTotal} accent={alertsTotal > 0 ? 'red' : 'green'} />
        <MetricCard label="THREAT SCORE" value={threatScore} accent={threatScore > 40 ? 'amber' : 'green'} />
        <MetricCard label="SERVICES ACTIVE" value={servicesOkCount ?? '—'} accent="blue" />
      </div>

      <CriticalAlertBanner alert={criticalAlert} />

      <div>
        <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">CONNECTED DEVICES</div>
        {onlineDevices.length === 0 && <div className="text-[10px] text-text-muted">No devices online.</div>}
        {onlineDevices.slice(0, 6).map((d) => (
          <div key={d.mac_address} className="flex items-center gap-2 border-b border-border/50 py-2 last:border-none">
            <StatusDot variant={d.is_blocked ? 'red' : 'green'} />
            <div className="min-w-0 flex-1">
              <div className="truncate text-[11px] text-text-primary">
                {d.hostname || <MacAddress mac={d.mac_address} vendor={d.vendor_name} />}
              </div>
              <div className="text-[9px] text-text-muted">{d.ip_address}</div>
            </div>
            <div className="flex flex-shrink-0 flex-col items-end gap-1">
              <TrafficDisplay sample={d.latest_traffic} />
              <Badge variant="info">{d.interface_name === 'Ethernet' ? 'ETH' : 'WiFi'}</Badge>
            </div>
          </div>
        ))}
      </div>

      <div>
        <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">SECURITY SERVICES</div>
        <ServiceStatusPanel health={health} />
      </div>

      <div>
        <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">EVENT LOG</div>
        <AlertFeed alerts={alerts} limit={5} />
      </div>
    </div>
  )
}
