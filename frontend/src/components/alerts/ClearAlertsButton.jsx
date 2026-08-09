import { useState } from 'react'
import { Modal } from '../Modal'
import { useClearAllAlerts } from '../../hooks/useAlerts'

/** Button + confirm modal for permanently deleting every alert record.
 * Shared by the Alerts page toolbar (quick access while triaging) and
 * Settings' ClearAlertsSection (the explanatory, buried version) so the
 * destructive action and its confirmation copy live in exactly one place. */
export function ClearAlertsButton({ label = 'CLEAR ALERTS…', className }) {
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
    <>
      <button
        type="button"
        onClick={() => setModalOpen(true)}
        className={
          className ||
          'border border-accent-red/30 bg-accent-red/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-red transition-colors hover:bg-accent-red/20'
        }
      >
        {label}
      </button>

      {modalOpen && (
        <Modal title="⚠ CONFIRM CLEAR ALERTS" tone="danger" onClose={closeModal}>
          <p className="mb-4 text-[11px] leading-relaxed text-text-primary">
            Are you sure? This permanently deletes every alert — stale or not. Devices, trust decisions,
            and trained models are kept — this action cannot be undone.
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
    </>
  )
}
