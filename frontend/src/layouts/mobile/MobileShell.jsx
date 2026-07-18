import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { logout } from '../../lib/api'
import { useHealth } from '../../hooks/useHealth'
import { useAlerts } from '../../hooks/useAlerts'
import { StatusDot } from '../../components/StatusDot'
import heimdallLogo from '../../assets/heimdall-icon.png'

const TABS = [
  { to: '/', label: 'OVERVIEW', end: true },
  { to: '/devices', label: 'DEVICES' },
  { to: '/alerts', label: 'ALERTS' },
  { to: '/threats', label: 'THREATS' },
  { to: '/rules', label: 'RULES' },
  { to: '/notifications', label: 'NOTIFICATIONS' },
]

const BOTTOM_NAV = [
  { to: '/', icon: '⌂', label: 'HOME', end: true },
  { to: '/devices', icon: '▤', label: 'DEVICES' },
  { to: '/alerts', icon: '⚠', label: 'ALERTS' },
  { to: '/threats', icon: '◈', label: 'THREATS' },
  { to: '/settings', icon: '⚙', label: 'CONFIG' },
]

export function MobileShell() {
  const navigate = useNavigate()
  const { data: health } = useHealth()
  const { data: alertsPage } = useAlerts({ acknowledged: 'false', per_page: '1' })
  const unreadCount = alertsPage?.total ?? 0
  const schedulerOk = health?.scheduler?.scheduler_running && !health?.scheduler?.last_poll_error

  async function handleLogout() {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-[480px] flex-col bg-bg text-[11px] text-text-secondary">
      <div className="flex items-center justify-between px-4 pt-4">
        <div className="flex items-center gap-2">
          <img src={heimdallLogo} alt="" className="h-8 w-8 flex-shrink-0" />
          <div>
            <div className="font-heading text-lg font-bold tracking-wide text-text-primary">SENTINEL</div>
            <div className="text-[9px] tracking-wide text-text-muted">NET MONITOR · LIVE</div>
          </div>
        </div>
        <button
          type="button"
          onClick={handleLogout}
          className="border border-border px-2 py-1 text-[9px] text-text-muted"
        >
          LOGOUT
        </button>
      </div>

      <div className="flex gap-2 px-4 py-3">
        <div
          className={`flex items-center gap-1.5 border px-2 py-1 text-[9px] ${
            schedulerOk
              ? 'border-accent-green/25 bg-accent-green/5 text-accent-green'
              : 'border-accent-red/25 bg-accent-red/5 text-accent-red'
          }`}
        >
          <StatusDot variant={schedulerOk ? 'green' : 'red'} pulse={schedulerOk} />
          XMO {schedulerOk ? 'LIVE' : 'DOWN'}
        </div>
        {unreadCount > 0 && (
          <div className="flex items-center gap-1.5 border border-accent-red/25 bg-accent-red/5 px-2 py-1 text-[9px] text-accent-red">
            <StatusDot variant="red" />
            {unreadCount} ALERTS
          </div>
        )}
      </div>

      <nav className="sticky top-0 z-10 flex gap-1 overflow-x-auto border-b border-border bg-bg px-4">
        {TABS.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            end={tab.end}
            className={({ isActive }) =>
              `flex-shrink-0 whitespace-nowrap border-b-2 px-3 py-2.5 text-[9px] tracking-[2px] ${
                isActive ? 'border-accent-green text-accent-green' : 'border-transparent text-text-muted'
              }`
            }
          >
            {tab.label}
          </NavLink>
        ))}
      </nav>

      <main className="flex-1 px-4 py-3 pb-20">
        <Outlet />
      </main>

      <nav className="fixed bottom-0 left-1/2 grid w-full max-w-[480px] -translate-x-1/2 grid-cols-5 border-t border-border bg-surface-elevated">
        {BOTTOM_NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `flex flex-col items-center gap-1 py-2.5 text-[8px] tracking-wide ${
                isActive ? 'text-accent-green' : 'text-text-muted'
              }`
            }
          >
            <span className="text-lg leading-none">{item.icon}</span>
            {item.label}
          </NavLink>
        ))}
      </nav>
    </div>
  )
}
