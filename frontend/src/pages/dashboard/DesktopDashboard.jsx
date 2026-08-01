import { Link } from 'react-router-dom'
import { MetricCard } from '../../components/MetricCard'
import { StatusDot } from '../../components/StatusDot'
import { TrafficDisplay } from '../../components/TrafficDisplay'
import { ThroughputArrows } from '../../components/ThroughputArrows'
import { MacAddress } from '../../components/MacAddress'
import { Badge } from '../../components/Badge'
import { BlockButton } from '../../components/BlockButton'
import { CriticalAlertBanner } from '../../components/dashboard/CriticalAlertBanner'
import { AlertFeed } from '../../components/dashboard/AlertFeed'
import { TrafficBarChart } from '../../components/dashboard/TrafficBarChart'
import { ServiceStatusPanel } from '../../components/dashboard/ServiceStatusPanel'
import { PortSummary } from '../../components/dashboard/PortSummary'
import { isDeviceOnline } from '../../lib/deviceFilters'
import { useWanStats } from '../../hooks/useWanStats'

const HOSTS_SHOWN = 8

// "Independent Rail": a main operational column (hosts/alerts/ports) beside
// a persistent right rail (bandwidth + service status) that scrolls on its
// own axis. Service Status has no ceiling on row count — it grows with
// every integration Heimdall wires up — so without this split, CSS Grid's
// default row-stretch behavior pulls Hosts/Bandwidth tall to match it, and
// the whole page can push Ports below the fold. See docs/
// dashboard-rail-and-palette-plan.md.
export function DesktopDashboard({ devices, alerts, criticalAlert, threatScore, health, ports, alertsTotal }) {
  const onlineDevices = devices.filter(isDeviceOnline)
  const onlineCount = onlineDevices.length
  const hiddenCount = Math.max(onlineCount - HOSTS_SHOWN, 0)
  // 404 here just means SagemcomXmoAdapter.get_wan_stats' xpath hasn't been
  // verified against a live router yet (see its docstring) — not an error
  // worth surfacing, the household total simply stays hidden until then.
  const { data: wanStats } = useWanStats()

  return (
    <div className="flex h-full flex-col gap-px overflow-hidden bg-border p-px">
      <div className="grid flex-shrink-0 grid-cols-3 gap-px bg-border">
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

      <div className="flex flex-1 gap-px overflow-hidden">
        {/* Main column */}
        <div className="flex flex-[7] flex-col gap-px overflow-hidden">
          <div className="flex-shrink-0 border border-border bg-surface p-4">
            <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">CONNECTED HOSTS</div>
            <div>
              {onlineDevices.length === 0 && <div className="text-[10px] text-text-muted">No devices online.</div>}
              {onlineDevices.slice(0, HOSTS_SHOWN).map((d) => (
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
              {hiddenCount > 0 && (
                <Link
                  to="/devices"
                  className="mt-1.5 block text-[9px] tracking-wide text-accent-blue hover:text-text-primary"
                >
                  + {hiddenCount} MORE · VIEW ALL DEVICES →
                </Link>
              )}
            </div>
          </div>

          <div className="flex flex-1 gap-px overflow-hidden">
            <div className="flex-[2] border border-border bg-surface p-4">
              <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">OPEN ALERTS</div>
              <AlertFeed alerts={alerts} />
            </div>
            <div className="flex-1">
              <CriticalAlertBanner alert={criticalAlert} />
            </div>
          </div>

          <div className="flex-shrink-0 border border-border bg-surface p-4">
            <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">PORTS</div>
            <PortSummary ports={ports} />
          </div>
        </div>

        {/* Rail — scrolls independently of the main column */}
        <div className="flex flex-[3] flex-col gap-px overflow-hidden">
          <div className="flex-shrink-0 border border-border bg-surface p-4">
            <div className="mb-2 flex items-center justify-between text-[8px] tracking-[3px] text-text-muted">
              <span>BANDWIDTH USAGE</span>
              {wanStats && (
                <span className="text-[9px] tracking-normal">
                  <ThroughputArrows upKbps={wanStats.throughput_up_kbps} downKbps={wanStats.throughput_dn_kbps} />
                </span>
              )}
            </div>
            <TrafficBarChart devices={onlineDevices} />
          </div>

          <div className="flex-1 overflow-hidden">
            <ServiceStatusPanel health={health} />
          </div>
        </div>
      </div>
    </div>
  )
}
