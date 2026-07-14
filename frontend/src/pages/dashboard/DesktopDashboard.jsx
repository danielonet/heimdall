import { MetricCard } from '../../components/MetricCard'
import { StatusDot } from '../../components/StatusDot'
import { TrafficDisplay } from '../../components/TrafficDisplay'
import { MacAddress } from '../../components/MacAddress'
import { Badge } from '../../components/Badge'
import { BlockButton } from '../../components/BlockButton'
import { CriticalAlertBanner } from '../../components/dashboard/CriticalAlertBanner'
import { AlertFeed } from '../../components/dashboard/AlertFeed'
import { TrafficBarChart } from '../../components/dashboard/TrafficBarChart'
import { ServiceStatusPanel } from '../../components/dashboard/ServiceStatusPanel'
import { PortSummary } from '../../components/dashboard/PortSummary'
import { isDeviceOnline } from '../../lib/deviceFilters'

export function DesktopDashboard({ devices, alerts, criticalAlert, threatScore, health, ports, alertsTotal }) {
  const onlineDevices = devices.filter(isDeviceOnline)
  const onlineCount = onlineDevices.length

  return (
    <div className="space-y-px bg-border p-px">
      <div className="grid grid-cols-3 gap-px bg-border">
        <MetricCard label="DEVICES ONLINE" tag="LIVE" value={onlineCount} accent="green" />
        <MetricCard
          label="ACTIVE ALERTS"
          tag={alertsTotal > 0 ? 'REVIEW' : 'CLEAR'}
          value={alertsTotal}
          accent={alertsTotal > 0 ? 'red' : 'green'}
        />
        <MetricCard
          label="THREAT SCORE"
          tag={threatScore > 40 ? 'RISK' : 'OK'}
          value={threatScore}
          accent={threatScore > 40 ? 'amber' : 'green'}
        />
      </div>

      <div className="grid grid-cols-12 gap-px bg-border">
        <div className="col-span-6 border border-border bg-surface p-4">
          <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">CONNECTED HOSTS</div>
          <div>
            {onlineDevices.length === 0 && <div className="text-[10px] text-text-muted">No devices online.</div>}
            {onlineDevices.slice(0, 8).map((d) => (
              <div
                key={d.mac_address}
                className="flex items-center gap-3 border-b border-border/50 py-1.5 text-[10px] last:border-none"
              >
                <StatusDot variant={d.is_blocked ? 'red' : 'green'} />
                <div className="min-w-0 flex-1 truncate text-text-primary">
                  {d.hostname || <MacAddress mac={d.mac_address} vendor={d.vendor_name} />}
                </div>
                <TrafficDisplay sample={d.latest_traffic} />
                <Badge variant="info">{d.interface_name === 'Ethernet' ? 'ETH' : 'WiFi'}</Badge>
                {!d.is_blocked && <BlockButton mac={d.mac_address} />}
              </div>
            ))}
          </div>
        </div>

        <div className="col-span-3 border border-border bg-surface p-4">
          <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">BANDWIDTH USAGE</div>
          <TrafficBarChart devices={onlineDevices} />
        </div>

        <div className="col-span-3">
          <ServiceStatusPanel health={health} />
        </div>
      </div>

      <div className="grid grid-cols-12 gap-px bg-border">
        <div className="col-span-8 border border-border bg-surface p-4">
          <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">OPEN ALERTS</div>
          <AlertFeed alerts={alerts} />
        </div>
        <div className="col-span-4">
          <CriticalAlertBanner alert={criticalAlert} />
        </div>
      </div>

      <div className="border border-border bg-surface p-4">
        <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">PORTS</div>
        <PortSummary ports={ports} />
      </div>
    </div>
  )
}
