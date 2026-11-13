import { NotificationsSection } from '../components/notifications/NotificationsSection'

// Where Heimdall reaches you when the dashboard is closed: ntfy push, Telegram and email. These were a tile
// on the Settings page until that page grew too heavy, so they have their own tab again.
export function NotificationsPage() {
  return (
    <div className="p-3">
      <NotificationsSection />
    </div>
  )
}
