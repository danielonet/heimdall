import { useNavigate } from 'react-router-dom'
import { useRouterInfo } from '../hooks/useRouterInfo'
import { useHealth } from '../hooks/useHealth'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { logout } from '../lib/api'
import { Badge } from '../components/Badge'
import { AlertLifecycleSection } from '../components/settings/AlertLifecycleSection'
import { AutoBlockSection } from '../components/settings/AutoBlockSection'
import { DataRetentionSection } from '../components/settings/DataRetentionSection'
import { LearningStatusSection } from '../components/settings/LearningStatusSection'
import { MiwifiCredentialsForm } from '../components/settings/MiwifiCredentialsForm'
import { NetworkInterfaceSection } from '../components/settings/NetworkInterfaceSection'
import { NotificationsSection } from '../components/settings/NotificationsSection'
import { PrimaryRouterSelect } from '../components/settings/PrimaryRouterSelect'
import { PurgeDatabaseSection } from '../components/settings/PurgeDatabaseSection'
import { RouterCredentialsForm } from '../components/settings/RouterCredentialsForm'
import heimdallLogo from '../assets/heimdall-icon.png'

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

export function SettingsPage() {
  const { data: router, isLoading, isError, error } = useRouterInfo()
  const { data: health } = useHealth()
  const mode = useLayoutMode()
  const navigate = useNavigate()
  const deploymentTier = health?.security_services?.deployment_tier

  // Keyed off layout mode, not viewport — see PortsPage/ThreatsPage.
  const gridClass = mode === 'mobile' ? 'grid grid-cols-1 gap-2' : 'grid grid-cols-4 gap-3'
  // Everything that used to be the separate NOTIFICATIONS tab now lives in
  // this one tile grid too (requested directly: consolidate the tab into
  // Settings) — and several formerly-standalone tiles were merged into
  // denser ones along the way (AlertLifecycleSection = staleness +
  // auto-resolve, DataRetentionSection = DB retention + device archive/
  // purge, NotificationsSection = ntfy + SMTP; NETWORK INTERFACE moved into
  // the ROUTER panel below as a third sub-section alongside ROUTER LOGIN)
  // specifically so the whole page reads as fewer, richer cards instead of
  // many thin ones — the actual ask, not just a relocation.
  //
  // Responsive beyond the binary mobile/desktop split this codebase
  // otherwise uses everywhere else: base desktop is 2-up, xl (>=1280px) is
  // 4-up, so this fits as one wide page on a real monitor without forcing
  // a scroll a phone-width layout wouldn't need either. The two content-
  // heavy merged tiles (DATA RETENTION, NOTIFICATIONS) span 2 columns at
  // every desktop width — full-width at 2-up, half-width side-by-side once
  // 4-up kicks in — since their own multi-field rows need more than one
  // quarter of a narrow-ish desktop window to lay out cleanly.
  const tilesClass = mode === 'mobile' ? 'space-y-3' : 'grid grid-cols-2 xl:grid-cols-4 gap-3'
  const wideTileClass = mode === 'mobile' ? '' : 'col-span-2'

  async function handleLogout() {
    await logout()
    navigate('/login', { replace: true })
  }

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

      <div className={tilesClass}>
        <LearningStatusSection />
        <AutoBlockSection />
        <AlertLifecycleSection />
        <PurgeDatabaseSection />
        <div className={wideTileClass}>
          <DataRetentionSection />
        </div>
        <div className={wideTileClass}>
          <NotificationsSection />
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 border border-border bg-surface p-3">
        <div className="flex items-center gap-3">
          <img src={heimdallLogo} alt="" className="h-6 w-6 flex-shrink-0" />
          <div className="text-[9px] text-text-muted">Sentinel — Heimdall Home Network Monitor</div>
        </div>
        <button
          type="button"
          onClick={handleLogout}
          className="border border-accent-red/30 bg-accent-red/5 px-4 py-2 text-[10px] tracking-wider text-accent-red transition-colors hover:bg-accent-red/20"
        >
          LOG OUT
        </button>
      </div>
    </div>
  )
}
