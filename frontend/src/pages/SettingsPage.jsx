import { useNavigate } from 'react-router-dom'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { logout } from '../lib/api'
import { AlertLifecycleSection } from '../components/settings/AlertLifecycleSection'
import { AutoBlockSection } from '../components/settings/AutoBlockSection'
import { DataRetentionSection } from '../components/settings/DataRetentionSection'
import { LearningStatusSection } from '../components/settings/LearningStatusSection'
import { NotificationsSection } from '../components/settings/NotificationsSection'
import { PurgeDatabaseSection } from '../components/settings/PurgeDatabaseSection'
import { WifiMonitorSection } from '../components/settings/WifiMonitorSection'
import heimdallLogo from '../assets/heimdall-icon.png'

export function SettingsPage() {
  const mode = useLayoutMode()
  const navigate = useNavigate()

  // Everything that used to be the separate NOTIFICATIONS tab now lives in
  // this one tile grid too (requested directly: consolidate the tab into
  // Settings) — and several formerly-standalone tiles were merged into
  // denser ones along the way (AlertLifecycleSection = staleness +
  // auto-resolve, DataRetentionSection = DB retention + device archive/
  // purge, NotificationsSection = ntfy + SMTP)
  // specifically so the whole page reads as fewer, richer cards instead of
  // many thin ones — the actual ask, not just a relocation. Router and
  // (future) switch configuration lives on the EQUIPMENT page, not here.
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
        <div className={wideTileClass}>
          <WifiMonitorSection />
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
