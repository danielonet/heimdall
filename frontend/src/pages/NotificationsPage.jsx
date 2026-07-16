import { useLayoutMode } from '../hooks/useLayoutMode'
import { NtfyUrlSection } from '../components/notifications/NtfyUrlSection'
import { SmtpSection } from '../components/notifications/SmtpSection'

export function NotificationsPage() {
  const mode = useLayoutMode()
  const gridClass = mode === 'mobile' ? 'space-y-4' : 'grid grid-cols-2 gap-4'

  return (
    <div className="space-y-4 p-4">
      <div className={gridClass}>
        <NtfyUrlSection />
        <SmtpSection />
      </div>
    </div>
  )
}
