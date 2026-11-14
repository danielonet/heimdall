import { useState } from 'react'
import { Modal } from '../Modal'
import { useSaveSwitch, useTestSwitch } from '../../hooks/useSwitches'

const FIELD_LABELS = { host: 'IP ADDRESS / HOST', username: 'USERNAME', password: 'PASSWORD' }
const INPUT_CLASS =
  'w-full border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active'

// Add or edit one managed switch. The fields come from the catalog entry (spec.fields), so supporting another
// switch model needs no change here. The password is write-only: it is never sent back to the browser, only
// whether one is on file — leave it blank to keep the stored one.
export function SwitchFormModal({ catalog, current, onClose }) {
  const save = useSaveSwitch()
  const test = useTestSwitch()
  const supported = catalog.filter((s) => s.implemented)
  const [specId, setSpecId] = useState(current?.spec_id || supported[0]?.id || '')
  const spec = supported.find((s) => s.id === specId) || supported[0]
  const [values, setValues] = useState({
    name: current?.name || '',
    host: current?.host || '',
    username: current?.username ?? spec?.default_username ?? '',
    password: '',
    poll_interval_s: current?.poll_interval_s || 15,
  })
  // A new switch is created by the first submit. If the login test then fails the modal stays open for another try,
  // and that try must update the switch just created, not create a second one: remember its id.
  const [createdId, setCreatedId] = useState(null)
  const switchId = current?.id || createdId
  const hasPassword = Boolean(current?.password_configured)
  const editing = Boolean(current)
  const canSave =
    spec &&
    values.name.trim() &&
    values.host.trim() &&
    (hasPassword || values.password) &&
    !save.isPending &&
    !test.isPending

  function handleSubmit(e) {
    e.preventDefault()
    if (!canSave) return
    test.reset()
    const body = {
      id: switchId,
      spec_id: spec.id,
      name: values.name.trim(),
      host: values.host.trim(),
      username: values.username.trim(),
      poll_interval_s: Number(values.poll_interval_s),
      password: values.password || undefined,
    }
    // Save, then really try the login: closing silently on "saved" leaves people unsure whether it worked.
    save.mutate(body, {
      onSuccess: (data) => {
        const id = switchId || data.switch.id
        setCreatedId(id)
        test.mutate({ id })
      },
    })
  }

  return (
    <Modal title={editing ? 'EDIT SWITCH' : 'ADD A SWITCH'} onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <label htmlFor="switch-model" className="mb-1 block text-[9px] tracking-wider text-text-muted">
            MODEL
          </label>
          <select
            id="switch-model"
            value={spec?.id || ''}
            disabled={editing}
            onChange={(e) => setSpecId(e.target.value)}
            className={INPUT_CLASS}
          >
            {supported.map((s) => (
              <option key={s.id} value={s.id}>
                {s.label}
              </option>
            ))}
          </select>
          {spec?.notes && <p className="mt-1 text-[9px] leading-relaxed text-text-secondary">{spec.notes}</p>}
        </div>
        <div>
          <label htmlFor="switch-name" className="mb-1 block text-[9px] tracking-wider text-text-muted">
            NAME
          </label>
          <input
            id="switch-name"
            type="text"
            autoComplete="off"
            maxLength={60}
            placeholder="e.g. Rack switch"
            value={values.name}
            onChange={(e) => setValues((v) => ({ ...v, name: e.target.value }))}
            className={INPUT_CLASS}
            autoFocus
          />
        </div>
        {(spec?.fields || []).map((field) => (
          <div key={field}>
            <label htmlFor={`switch-${field}`} className="mb-1 block text-[9px] tracking-wider text-text-muted">
              {spec.field_labels?.[field] || FIELD_LABELS[field] || field.toUpperCase()}
            </label>
            <input
              id={`switch-${field}`}
              type={field === 'password' ? 'password' : 'text'}
              autoComplete={field === 'password' ? 'new-password' : 'off'}
              value={values[field]}
              onChange={(e) => setValues((v) => ({ ...v, [field]: e.target.value }))}
              placeholder={field === 'password' ? (hasPassword ? '••••••••' : '(not set)') : ''}
              className={INPUT_CLASS}
            />
          </div>
        ))}
        <div>
          <label htmlFor="switch-interval" className="mb-1 block text-[9px] tracking-wider text-text-muted">
            POLL EVERY (SECONDS)
          </label>
          <input
            id="switch-interval"
            type="number"
            min={10}
            max={3600}
            value={values.poll_interval_s}
            onChange={(e) => setValues((v) => ({ ...v, poll_interval_s: e.target.value }))}
            className={INPUT_CLASS}
          />
        </div>
        <p className="text-[9px] text-text-muted">
          The address must be on your local network. The password is stored in a secret file on the Heimdall
          host, never in the database. Leave it blank to keep the current one.
        </p>
        {save.isError && <div className="text-[9px] text-accent-red">{save.error.message}</div>}
        {test.isPending && (
          <div role="status" className="border border-border bg-bg px-3 py-2 text-[10px] text-text-secondary">
            Saved. Signing in to the switch…
          </div>
        )}
        {test.isSuccess && test.data.ok && (
          <div role="status" className="border border-accent-green/40 bg-accent-green/10 px-3 py-2 text-[10px] text-accent-green">
            ✓ Signed in to {test.data.model || 'the switch'} · {test.data.ports_up} of {test.data.ports} ports up ·{' '}
            {test.data.macs} devices seen · {test.data.single_device_ports.length} port
            {test.data.single_device_ports.length === 1 ? '' : 's'} with exactly one device (those get per-device
            traffic).
          </div>
        )}
        {((test.isSuccess && !test.data.ok) || test.isError) && (
          <div role="alert" className="border border-accent-red/40 bg-accent-red/10 px-3 py-2 text-[10px] text-accent-red">
            ✗ Saved, but the switch did not accept the login: {test.isError ? test.error.message : test.data.error}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="border border-border px-3 py-1.5 text-[10px] tracking-wider text-text-secondary hover:bg-surface"
          >
            {test.isSuccess && test.data.ok ? 'CLOSE' : 'CANCEL'}
          </button>
          <button
            type="submit"
            disabled={!canSave}
            className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
          >
            {save.isPending ? 'SAVING…' : test.isPending ? 'TESTING…' : 'SAVE & TEST'}
          </button>
        </div>
      </form>
    </Modal>
  )
}
