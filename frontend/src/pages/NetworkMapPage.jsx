import { useMemo } from 'react'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { useDevices } from '../hooks/useDevices'
import { useAlertGroups } from '../hooks/useAlertGroups'
import { useSettings } from '../hooks/useSettings'
import { useHealth } from '../hooks/useHealth'
import { useWifiSightings } from '../hooks/useWifi'
import { useNowTick } from '../hooks/useNowTick'
import { guessDeviceType } from '../lib/deviceGuess'
import { visibleSightings } from '../lib/wifiSightings'
import { NetworkMap } from '../components/network-map/NetworkMap'
import { computeNodeLayout } from '../lib/networkMapLayout'
import { staleBeforeIso } from '../lib/alertStaleness'

const LEGEND = [
  ['critical', 'CRITICAL / BLOCKED', 'bg-accent-red'],
  ['warning', 'WARNING / QUARANTINED', 'bg-accent-amber'],
  ['online', 'ONLINE', 'bg-accent-green'],
  ['offline', 'OFFLINE', 'bg-text-muted'],
  ['nearby', 'NEARBY (NEVER JOINED)', 'bg-accent-blue'],
]

export function NetworkMapPage() {
  const mode = useLayoutMode()
  const { data: devices } = useDevices()
  const { data: appSettings } = useSettings()
  // Memoized — see DashboardPage.jsx's identical comment on staleBeforeIso.
  const staleFrom = useMemo(() => staleBeforeIso(appSettings?.alert_stale_hours), [appSettings?.alert_stale_hours])
  // resolved=false, not acknowledged=false — a device shouldn't keep getting
  // pulled toward the THREAT ring for an alert someone already resolved.
  // Also excludes stale alerts (older than AppSettings.alert_stale_hours) —
  // a months-old unresolved alert shouldn't permanently anchor a device
  // near the center; see AlertsPage's STALE badge for where they still
  // show up instead of just vanishing.
  const { data: alertGroups } = useAlertGroups({ resolved: 'false', ...(staleFrom ? { from: staleFrom } : {}) })
  const { data: health } = useHealth()
  const { data: sightings } = useWifiSightings()
  const now = useNowTick()

  // WiFi Monitor sightings shaped like devices so they land in the NOT
  // ASSOCIATED sector (no ap_alias, WiFi interface), ranked by signal like
  // every other unassociated node. Filtered the same way, and with the same
  // shared logic (lib/wifiSightings.js), as the WIFI tab's own NEARBY WIFI
  // DEVICES table — requested directly, so a device that's dropped off that
  // list (out of range, or marked/matched as one of your own) doesn't keep
  // sitting on the map as a "nearby" node. `known` is a belt-and-suspenders
  // check on top of that shared logic's own exact-match test — a device
  // already on the map as itself should never also render as a sighting.
  const sightingNodes = useMemo(() => {
    const known = new Set((devices || []).map((d) => d.mac_address))
    return visibleSightings(sightings, now)
      .filter((s) => !known.has(s.mac_address))
      .map((s) => ({
        mac_address: s.mac_address,
        hostname: s.vendor_name || guessDeviceType(s.vendor_name, s.mac_address).replace('Probably a ', ''),
        interface_name: 'WiFi',
        ap_alias: null,
        signal_strength_dbm: s.strongest_signal_dbm,
        is_trusted: false,
        is_online: false,
        is_wifi_sighting: true,
      }))
  }, [devices, sightings, now])

  const layout = useMemo(() => computeNodeLayout([...(devices || []), ...sightingNodes], alertGroups || []), [devices, sightingNodes, alertGroups])
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
          {(devices || []).length} devices{sightingNodes.length ? ` + ${sightingNodes.length} nearby` : ''} · distance from center = urgency · angle = AP segment
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
