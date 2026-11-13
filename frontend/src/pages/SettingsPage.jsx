import { useNavigate } from 'react-router-dom'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { logout } from '../lib/api'
import { AlertLifecycleSection } from '../components/settings/AlertLifecycleSection'
import { AutoBlockSection } from '../components/settings/AutoBlockSection'
import { DataRetentionSection } from '../components/settings/DataRetentionSection'
import { LearningStatusSection } from '../components/settings/LearningStatusSection'
import { PurgeDatabaseSection } from '../components/settings/PurgeDatabaseSection'
import heimdallLogo from '../assets/heimdall-icon.png'

export function SettingsPage() {
  const mode = useLayoutMode()
  const navigate = useNavigate()

  // Heimdall-wide options only: learning, auto-block, alert lifecycle, data
  // retention and the purge. Router, WiFi monitor and managed-switch
  // configuration live on the EQUIPMENT page and the alert channels (ntfy,
  // Telegram, email) on the NOTIFICATIONS page. Notifications was folded
  // into this page once and came out again because the page had become too
  // heavy. Several formerly-standalone tiles were merged into denser ones
  // (AlertLifecycleSection = staleness + auto-resolve, DataRetentionSection
  // = DB retention + device archive/purge), so the page reads as a few
  // richer cards instead of many thin ones.
  //
  // Responsive beyond the binary mobile/desktop split this codebase
  // otherwise uses everywhere else: base desktop is 2-up, xl (>=1280px) is
  // 3-up. The one content-heavy tile (DATA RETENTION) spans 2 columns at
  // every desktop width, since its multi-field rows need more than one
  // narrow column. DOM order is what keeps the grid gap-free under plain
  // (sparse) auto-flow: four single tiles, then the wide one. At 2-up that
  // is two full rows and the wide tile on its own row; at 3-up it is three
  // singles, then the last single beside the wide tile. grid-flow-dense
  // would let the dangerous PURGE DATABASE tile jump ahead of its DOM
  // position, so the order is tuned instead.
  const tilesClass = mode === 'mobile' ? 'space-y-3' : 'grid grid-cols-2 xl:grid-cols-3 gap-3'
  const wideTileClass = mode === 'mobile' ? '' : 'col-span-2'

  async function handleLogout() {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="space-y-3 p-3">
      <div className={tilesClass}>
        <LearningStatusSection />
        <AutoBlockSection />
        <AlertLifecycleSection />
        <PurgeDatabaseSection />
        <div className={wideTileClass}>
          <DataRetentionSection />
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
