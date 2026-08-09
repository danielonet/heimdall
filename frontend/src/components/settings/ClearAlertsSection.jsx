import { ClearAlertsButton } from '../alerts/ClearAlertsButton'

export function ClearAlertsSection() {
  return (
    <div className="border border-accent-red/30 bg-accent-red/5 p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-accent-red">CLEAR ALERTS</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        Deletes every alert record. Devices, trust decisions, traffic history, and trained models are
        untouched — monitoring keeps running on the data already collected and raises new alerts as new
        activity happens. <strong>Cannot be undone.</strong>
      </p>

      <ClearAlertsButton label="CLEAR ALL ALERTS…" />
    </div>
  )
}
