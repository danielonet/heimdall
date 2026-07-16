import { useNavigate } from 'react-router-dom'
import { useRouterInfo } from '../hooks/useRouterInfo'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { logout } from '../lib/api'
import { Badge } from '../components/Badge'
import { DatabaseSection } from '../components/settings/DatabaseSection'
import { LearningStatusSection } from '../components/settings/LearningStatusSection'
import { NetworkInterfaceSection } from '../components/settings/NetworkInterfaceSection'
import { PurgeDatabaseSection } from '../components/settings/PurgeDatabaseSection'
import { RouterCredentialsForm } from '../components/settings/RouterCredentialsForm'
import heimdallLogo from '../assets/heimdall-logo.svg'

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
  const mode = useLayoutMode()
  const navigate = useNavigate()

  // Keyed off layout mode, not viewport — see PortsPage/ThreatsPage.
  const gridClass = mode === 'mobile' ? 'grid grid-cols-1 gap-3' : 'grid grid-cols-3 gap-4'
  // items-stretch (the grid default) so paired tiles match each other's
  // height instead of each hugging its own content.
  const sectionGridClass = mode === 'mobile' ? 'space-y-4' : 'grid grid-cols-2 gap-4'

  async function handleLogout() {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="space-y-4 p-4">
      <div className="border border-border bg-surface p-4">
        <div className="mb-3 text-[8px] tracking-[3px] text-text-muted">ROUTER</div>
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
            <Field label="SSIDs">{(router.ssids || []).join(', ') || '—'}</Field>
          </div>
        )}
        <RouterCredentialsForm />
      </div>

      <div className={sectionGridClass}>
        <LearningStatusSection />
        <DatabaseSection />
      </div>

      <div className={sectionGridClass}>
        <NetworkInterfaceSection />
        <PurgeDatabaseSection />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 border border-border bg-surface p-4">
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
