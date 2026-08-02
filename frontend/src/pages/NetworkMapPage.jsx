import { useMemo } from 'react'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { useDevices } from '../hooks/useDevices'
import { useAlertGroups } from '../hooks/useAlertGroups'
import { useHealth } from '../hooks/useHealth'
import { NetworkMap } from '../components/network-map/NetworkMap'
import { computeNodeLayout } from '../lib/networkMapLayout'

const LEGEND = [
  ['critical', 'CRITICAL / BLOCKED', 'bg-accent-red'],
  ['warning', 'WARNING / QUARANTINED', 'bg-accent-amber'],
  ['online', 'ONLINE', 'bg-accent-green'],
  ['offline', 'OFFLINE', 'bg-text-muted'],
]

export function NetworkMapPage() {
  const mode = useLayoutMode()
  const { data: devices } = useDevices()
  // resolved=false, not acknowledged=false — a device shouldn't keep getting
  // pulled toward the THREAT ring for an alert someone already resolved.
  const { data: alertGroups } = useAlertGroups({ resolved: 'false' })
  const { data: health } = useHealth()

  const layout = useMemo(() => computeNodeLayout(devices || [], alertGroups || []), [devices, alertGroups])
  const schedulerOk = health ? health.scheduler?.scheduler_running && !health.scheduler?.last_poll_error : true

  // The concept this ships was explicitly framed around "wide screen
  // display" — a phone-width polar SVG with 100+ device labels is illegible,
  // so this route intentionally has no mobile rendering (and no MobileShell
  // nav entry either). See docs/network-map-plan.md.
  if (mode === 'mobile') {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 p-8 text-center">
        <div className="text-[11px] tracking-[2px] text-text-primary">NETWORK MAP</div>
        <div className="text-[10px] text-text-muted">
          Best viewed on a wider screen — open Heimdall in a desktop browser to use the map.
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col gap-px overflow-hidden bg-border p-px">
      <div className="flex flex-shrink-0 flex-wrap items-center gap-4 border border-border bg-surface p-3">
        <div className="text-[8px] tracking-[3px] text-text-muted">NETWORK MAP</div>
        <div className="text-[9px] text-text-secondary">
          {(devices || []).length} devices · distance from center = urgency · angle = AP segment
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-3">
          {LEGEND.map(([key, label, dotClass]) => (
            <div key={key} className="flex items-center gap-1.5">
              <span className={`h-[7px] w-[7px] flex-shrink-0 rounded-full ${dotClass}`} />
              <span className="text-[9px] tracking-wide text-text-muted">{label}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-hidden border border-border bg-surface">
        <NetworkMap layout={layout} degraded={!schedulerOk} />
      </div>
    </div>
  )
}
