import { useState } from 'react'
import { Modal } from '../Modal'
import { useSaveRouter } from '../../hooks/useRouters'

const FIELD_LABELS = { host: 'IP ADDRESS / HOST', username: 'USERNAME', password: 'PASSWORD' }
const INPUT_CLASS =
  'w-full border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active'

// Login popup for one router. The fields shown come from the catalog entry
// (spec.fields), so adding a router family needs no change here. The password
// is write-only: it is never sent back to the browser, only whether one is on
// file — leave it blank to keep the stored one.
export function RouterLoginModal({ spec, current, onClose }) {
  const mutation = useSaveRouter()
  const [values, setValues] = useState({
    host: current?.host || '',
    username: current?.username || spec.default_username || '',
    password: '',
  })

  const needsUsername = spec.fields.includes('username')
  const needsHost = spec.fields.includes('host')
  const hasPassword = Boolean(current?.password_configured)
  const canSave =
    (!needsUsername || values.username.trim()) &&
    (!needsHost || values.host.trim()) &&
    (hasPassword || values.password) &&
    !mutation.isPending

  function handleSubmit(e) {
    e.preventDefault()
    if (!canSave) return
    mutation.mutate({ spec, ...values }, { onSuccess: onClose })
  }

  return (
    <Modal title={`${spec.label.toUpperCase()} LOGIN`} onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-3">
        {spec.fields.map((field) => (
          <div key={field}>
            <label htmlFor={`router-${field}`} className="mb-1 block text-[9px] tracking-wider text-text-muted">
              {spec.field_labels?.[field] || FIELD_LABELS[field] || field.toUpperCase()}
            </label>
            <input
              id={`router-${field}`}
              type={field === 'password' ? 'password' : 'text'}
              autoComplete={field === 'password' ? 'new-password' : 'off'}
              value={values[field]}
              onChange={(e) => setValues((v) => ({ ...v, [field]: e.target.value }))}
              placeholder={field === 'password' ? (hasPassword ? '••••••••' : '(not set)') : ''}
              className={INPUT_CLASS}
              autoFocus={field === spec.fields[0]}
            />
          </div>
        ))}
        <p className="text-[9px] text-text-muted">
          Stored in a secret file on the Heimdall host, never in the database. Leave the password blank to keep
          the current one.
        </p>
        {!spec.implemented && (
          <p className="text-[9px] text-accent-amber">
            Heimdall can’t poll {spec.family} routers yet — the login is saved for when the adapter ships.
          </p>
        )}
        {mutation.isError && <div className="text-[9px] text-accent-red">{mutation.error.message}</div>}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="border border-border px-3 py-1.5 text-[10px] tracking-wider text-text-secondary hover:bg-surface"
          >
            CANCEL
          </button>
          <button
            type="submit"
            disabled={!canSave}
            className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
          >
            {mutation.isPending ? 'SAVING…' : 'SAVE'}
          </button>
        </div>
      </form>
    </Modal>
  )
}
