import { useState } from 'react'
import { Modal } from '../Modal'
import { usePurgeDatabase } from '../../hooks/useSettings'

export function PurgeDatabaseSection() {
  const [modalOpen, setModalOpen] = useState(false)
  const [password, setPassword] = useState('')
  const mutation = usePurgeDatabase()

  function closeModal() {
    setModalOpen(false)
    setPassword('')
    mutation.reset()
  }

  function handleConfirm(e) {
    e.preventDefault()
    mutation.mutate(password, { onSuccess: closeModal })
  }

  return (
    <div className="border border-accent-red/30 bg-accent-red/5 p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-accent-red">RESET &amp; RELEARN</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        Deletes every known device, trust decision, traffic history, alert, and trained model. Returns to
        LEARNING — connected devices are re-trusted automatically. <strong>Cannot be undone.</strong>
      </p>

      <button
        type="button"
        onClick={() => setModalOpen(true)}
        className="border border-accent-red/30 bg-accent-red/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-red transition-colors hover:bg-accent-red/20"
      >
        PURGE DATABASE…
      </button>

      {modalOpen && (
        <Modal title="⚠ CONFIRM DATABASE PURGE" tone="danger" onClose={closeModal}>
          <p className="mb-4 text-[11px] leading-relaxed text-text-primary">
            Are you sure? This permanently deletes all recorded devices, traffic history, alerts, and
            trained ML models. The system returns to LEARNING status. This action cannot be undone.
          </p>

          <form onSubmit={handleConfirm}>
            <label htmlFor="purge-password" className="mb-1 block text-[9px] tracking-wider text-text-secondary">
              ENTER ADMIN PASSWORD TO CONFIRM
            </label>
            <input
              id="purge-password"
              type="password"
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mb-3 w-full border border-accent-red/30 bg-bg px-3 py-2 text-sm text-text-primary outline-none focus:border-accent-red"
            />

            {mutation.isError && <div className="mb-3 text-[10px] text-accent-red">{mutation.error.message}</div>}

            <div className="flex gap-2">
              <button
                type="submit"
                disabled={!password || mutation.isPending}
                className="border border-accent-red/50 bg-accent-red/10 px-3 py-1.5 text-[10px] tracking-wider text-accent-red transition-colors hover:bg-accent-red/25 disabled:opacity-40"
              >
                {mutation.isPending ? 'PURGING…' : 'YES, PURGE EVERYTHING'}
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
          </form>
        </Modal>
      )}
    </div>
  )
}
