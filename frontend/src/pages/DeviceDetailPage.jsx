import { Link, useParams } from 'react-router-dom'
import { useDevice } from '../hooks/useDevices'
import { DeviceHeader } from '../components/device-detail/DeviceHeader'
import { TrafficTimelineChart } from '../components/device-detail/TrafficTimelineChart'
import { AnomalyScoreChart } from '../components/device-detail/AnomalyScoreChart'
import { OpenPortsPanel } from '../components/device-detail/OpenPortsPanel'
import { AlertHistoryTable } from '../components/device-detail/AlertHistoryTable'
import { WiredPortNote } from '../components/device-detail/WiredPortNote'

export function DeviceDetailPage() {
  const { mac } = useParams()
  const { data: device, isLoading, isError } = useDevice(mac)

  if (isLoading) return <div className="p-4 text-[10px] text-text-muted">Loading…</div>

  if (isError || !device) {
    return (
      <div className="p-4">
        <div className="mb-2 text-[10px] text-text-muted">Device not found.</div>
        <Link to="/devices" className="text-[10px] text-accent-green underline">
          Back to devices
        </Link>
      </div>
    )
  }

  const isWired = device.traffic_granularity === 'per_port'

  return (
    <div className="space-y-4 p-4">
      <DeviceHeader device={device} />

      {isWired && <WiredPortNote portAlias={device.port_alias} />}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="border border-border bg-surface p-4">
          <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">TRAFFIC (24H)</div>
          <TrafficTimelineChart history={device.traffic_history} />
        </div>
        <div className="border border-border bg-surface p-4">
          <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">ANOMALY SCORE</div>
          <AnomalyScoreChart history={device.traffic_history} />
        </div>
      </div>

      <div className="border border-border bg-surface p-4">
        <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">OPEN PORTS (LAST NMAP SCAN)</div>
        <OpenPortsPanel nmapProfile={device.nmap_profile} />
      </div>

      <div className="border border-border bg-surface p-4">
        <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">ALERT HISTORY</div>
        <AlertHistoryTable mac={mac} alerts={device.alerts} />
      </div>
    </div>
  )
}
