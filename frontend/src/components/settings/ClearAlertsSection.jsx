import { useState } from 'react'
import { Modal } from '../Modal'
import { useClearAllAlerts } from '../../hooks/useAlerts'

export function ClearAlertsSection() {
  const [modalOpen, setModalOpen] = useState(false)
  const mutation = useClearAllAlerts()

  function closeModal() {
    setModalOpen(false)
    mutation.reset()
  }

  function handleConfirm() {
    mutation.mutate(undefined, { onSuccess: closeModal })
  }

  return (
    <div className="border border-accent-red/30 bg-accent-red/5 p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-accent-red">CLEAR ALERTS</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        Deletes every alert record. Devices, trust decisions, traffic history, and trained models are
        untouched — monitoring keeps running on the data already collected and raises new alerts as new
        activity happens. <strong>Cannot be undone.</strong>
      </p>

      <button
        type="button"
        onClick={() => setModalOpen(true)}
        className="border border-accent-red/30 bg-accent-red/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-red transition-colors hover:bg-accent-red/20"
      >
        CLEAR ALL ALERTS…
      </button>

      {modalOpen && (
        <Modal title="⚠ CONFIRM CLEAR ALERTS" tone="danger" onClose={closeModal}>
          <p className="mb-4 text-[11px] leading-relaxed text-text-primary">
            Are you sure? This permanently deletes every alert. Devices, trust decisions, and trained
            models are kept — this action cannot be undone.
          </p>

          {mutation.isError && <div className="mb-3 text-[10px] text-accent-red">{mutation.error.message}</div>}

          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleConfirm}
              disabled={mutation.isPending}
              className="border border-accent-red/50 bg-accent-red/10 px-3 py-1.5 text-[10px] tracking-wider text-accent-red transition-colors hover:bg-accent-red/25 disabled:opacity-40"
            >
              {mutation.isPending ? 'CLEARING…' : 'YES, CLEAR ALL ALERTS'}
            </button>
            <button
              type="button"
              onClick={closeModal}
              disabled={mutation.isPending}
              className="border border-border px-3 py-1.5 text-[10px] tracking-wider text-text-muted transition-colors hover:text-text-secondary disabled:opacity-40"
            >
              CANCEL
            </button>
          </div>
        </Modal>
      )}
    </div>
  )
}
