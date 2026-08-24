import { useEffect, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { logout } from '../../lib/api'
import { useHealth } from '../../hooks/useHealth'
import { useThemeStore } from '../../store/themeStore'
import { StatusDot } from '../../components/StatusDot'
import { CreditsModal } from '../../components/CreditsModal'
import heimdallLogo from '../../assets/heimdall-icon.png'

const PALETTES = [['amber', 'AMBER'], ['slate', 'SLATE']]

function PaletteToggle() {
  const palette = useThemeStore((s) => s.palette)
  const setPalette = useThemeStore((s) => s.setPalette)
  return (
    <div className="flex items-center gap-1">
      {PALETTES.map(([value, text]) => (
        <button
          key={value}
          type="button"
          onClick={() => setPalette(value)}
          className={`border px-2 py-1 text-[9px] tracking-wider transition-colors ${
            palette === value
              ? 'border-accent-green/40 bg-accent-green/10 text-accent-green'
              : 'border-border text-text-muted hover:text-text-secondary'
          }`}
        >
          {text}
        </button>
      ))}
    </div>
  )
}

const NAV_ITEMS = [
  { to: '/', label: 'DASHBOARD', end: true },
  { to: '/map', label: 'MAP' },
  { to: '/devices', label: 'DEVICES' },
  { to: '/alerts', label: 'ALERTS' },
  { to: '/ports', label: 'PORTS' },
  { to: '/threats', label: 'THREATS' },
  { to: '/rules', label: 'RULES' },
  { to: '/notifications', label: 'NOTIFICATIONS' },
  { to: '/settings', label: 'SETTINGS' },
]

// Its own leaf component, not a hook called from DesktopShell itself —
// confirmed real: the ticking setState lived in DesktopShell before, which
// re-rendered the *entire* authenticated app (everything under <Outlet/> —
// every page, every chart, the live network map, every list) once a
// second, forever, for as long as a tab stayed open. Isolated here, only
// this one <span> re-renders each tick; DesktopShell and everything it
// wraps stays untouched by the clock.
function Clock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return (
    <div className="min-w-[90px] text-right font-heading text-xl font-semibold tracking-wide text-accent-green">
      {now.toLocaleTimeString('en-GB')}
    </div>
  )
}

export function DesktopShell() {
  const navigate = useNavigate()
  const { data: health } = useHealth()
  const schedulerOk = health?.scheduler?.scheduler_running && !health?.scheduler?.last_poll_error
  const [showCredits, setShowCredits] = useState(false)

  async function handleLogout() {
    await logout()
    navigate('/login', { replace: true })
  }

  // Easter egg: Ctrl+Shift + double-click the logo.
  function handleLogoDoubleClick(e) {
    if (e.ctrlKey && e.shiftKey) setShowCredits(true)
  }

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-bg text-[11px] text-text-secondary">
      <header className="flex h-[52px] flex-shrink-0 items-stretch border-b border-border bg-surface-elevated">
        <div className="flex min-w-[200px] items-center gap-3 border-r border-border px-6">
          <img
            src={heimdallLogo}
            alt=""
            onDoubleClick={handleLogoDoubleClick}
            className="h-9 w-9 flex-shrink-0 select-none"
          />
          <div>
            <div className="font-heading text-lg font-bold tracking-[4px] text-accent-green">SENTINEL</div>
            <div className="mt-0.5 text-[8px] tracking-wide text-text-muted">HOME NET MONITOR</div>
          </div>
        </div>

        <nav className="flex items-stretch">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `flex items-center border-r border-border px-4 text-[10px] tracking-[2px] transition-colors ${
                  isActive
                    ? 'border-b-2 border-b-accent-green text-accent-green'
                    : 'text-text-muted hover:text-text-primary'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-5 border-l border-border px-5">
          <div className="flex items-center gap-2">
            <StatusDot variant={schedulerOk ? 'green' : 'red'} pulse={schedulerOk} />
            <span className="text-[9px] tracking-wide text-text-muted">XMO</span>
          </div>
          <PaletteToggle />
          <button
            type="button"
            onClick={handleLogout}
            className="text-[9px] tracking-wide text-text-muted hover:text-accent-red"
          >
            LOGOUT
          </button>
          <Clock />
        </div>
      </header>

      <div className="flex h-9 flex-shrink-0 items-center border-b border-border bg-surface-elevated px-6">
        <div className="text-[9px] tracking-wide text-text-muted">
          SENTINEL / <em className="not-italic text-accent-green">LIVE VIEW</em>
        </div>
      </div>

      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>

      {showCredits && <CreditsModal onClose={() => setShowCredits(false)} />}
    </div>
  )
}
