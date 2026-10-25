import { useRouterInfo } from '../hooks/useRouterInfo'
import { useHealth } from '../hooks/useHealth'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { Badge } from '../components/Badge'
import { NetworkInterfaceSection } from '../components/settings/NetworkInterfaceSection'
import { MiwifiCredentialsForm } from '../components/equipment/MiwifiCredentialsForm'
import { PrimaryRouterSelect } from '../components/equipment/PrimaryRouterSelect'
import { RouterCredentialsForm } from '../components/equipment/RouterCredentialsForm'

function formatUptime(seconds) {
  if (!seconds) return '—'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const mins = Math.floor((seconds % 3600) / 60)
  return `${days}d ${hours}h ${mins}m`
}

function Field({ label, children }) {
  return (
    <div>
      <div className="text-[9px] tracking-wider text-text-muted">{label}</div>
      <div className="mt-0.5 text-[11px] text-text-primary">{children}</div>
    </div>
  )
}

// Everything about the network equipment Heimdall talks to: the router(s)
// today, managed switches next (docs/router-and-switch-expansion-plan.md).
// Moved here from the Settings page, which keeps the Heimdall-wide options.
export function EquipmentPage() {
  const { data: router, isLoading, isError, error } = useRouterInfo()
  const { data: health } = useHealth()
  const mode = useLayoutMode()
  const deploymentTier = health?.security_services?.deployment_tier

  // Keyed off layout mode, not viewport — see PortsPage/ThreatsPage.
  const gridClass = mode === 'mobile' ? 'grid grid-cols-1 gap-2' : 'grid grid-cols-4 gap-3'

  return (
    <div className="space-y-3 p-3">
      <div className="border border-border bg-surface p-3">
        <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">ROUTER</div>
        {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}
        {isError && <div className="text-[10px] text-accent-red">{error.message}</div>}
        {router && (
          <div className={gridClass}>
            <Field label="MODEL">{router.model || '—'}</Field>
            <Field label="FIRMWARE">{router.firmware || '—'}</Field>
            <Field label="SERIAL">{router.serial || '—'}</Field>
            <Field label="WAN IP">{router.wan_ip || '—'}</Field>
            <Field label="WAN MAC">{router.wan_mac || '—'}</Field>
            <Field label="WAN STATUS">
              <Badge variant={router.wan_status === 'UP' ? 'success' : 'danger'}>{router.wan_status}</Badge>
            </Field>
            <Field label="WAN MODE">{router.wan_mode || '—'}</Field>
            <Field label="UPTIME">{formatUptime(router.uptime_seconds)}</Field>
            <Field label="DEPLOYMENT">
              {deploymentTier ? <Badge variant="info">{deploymentTier.toUpperCase()}</Badge> : '—'}
            </Field>
            <div className={mode === 'mobile' ? '' : 'col-span-2'}>
              <Field label="SSIDs">{(router.ssids || []).join(', ') || '—'}</Field>
            </div>
            <div className={mode === 'mobile' ? '' : 'col-span-2'}>
              <Field label="WIFI RADIOS">
                {(router.radios || []).length > 0
                  ? router.radios
                      .map((r) => {
                        // tx_power_percent, not dBm — this is a percentage
                        // of the radio's max transmit power; null means
                        // automatic power control (no fixed level set).
                        const power = r.tx_power_percent == null ? 'auto power' : `${r.tx_power_percent}% power`
                        return `${r.band} ch${r.channel} (${power})${r.standard ? ` · ${r.standard}` : ''}`
                      })
                      .join(', ')
                  : '—'}
              </Field>
            </div>
          </div>
        )}
        <RouterCredentialsForm />
        <MiwifiCredentialsForm />
        <PrimaryRouterSelect />
        <NetworkInterfaceSection />
      </div>

      <div className="border border-border bg-surface p-3">
        <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">SWITCHES</div>
        <p className="text-[10px] leading-relaxed text-text-secondary">
          Managed-switch monitoring is planned: add up to 5 switches by the URL of their web stats page for
          per-device wired traffic. Nothing to configure yet.
        </p>
      </div>
    </div>
  )
}
