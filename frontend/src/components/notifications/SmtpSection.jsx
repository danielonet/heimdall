import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'

const EMPTY_FORM = {
  smtp_host: '', smtp_port: '587', smtp_from: '', smtp_to: '', smtp_username: '', smtp_use_tls: true,
}

export function SmtpSection() {
  const { data, isLoading } = useSettings()
  const mutation = useUpdateSettings()
  const [form, setForm] = useState(EMPTY_FORM)
  const [password, setPassword] = useState('')

  useEffect(() => {
    if (data) {
      setForm({
        smtp_host: data.smtp_host || '',
        smtp_port: String(data.smtp_port || 587),
        smtp_from: data.smtp_from || '',
        smtp_to: data.smtp_to || '',
        smtp_username: data.smtp_username || '',
        smtp_use_tls: data.smtp_use_tls,
      })
    }
  }, [data])

  function setField(key, value) {
    setForm((f) => ({ ...f, [key]: value }))
  }

  const port = Number(form.smtp_port)
  const isPortValid = Number.isInteger(port) && port >= 1 && port <= 65535
  const isDirty =
    data &&
    (form.smtp_host !== (data.smtp_host || '') ||
      form.smtp_port !== String(data.smtp_port || 587) ||
      form.smtp_from !== (data.smtp_from || '') ||
      form.smtp_to !== (data.smtp_to || '') ||
      form.smtp_username !== (data.smtp_username || '') ||
      form.smtp_use_tls !== data.smtp_use_tls ||
      password !== '')

  function handleSave() {
    if (!isPortValid) return
    const body = {
      smtp_host: form.smtp_host,
      smtp_port: port,
      smtp_from: form.smtp_from,
      smtp_to: form.smtp_to,
      smtp_username: form.smtp_username,
      smtp_use_tls: form.smtp_use_tls,
    }
    if (password) body.smtp_password = password
    mutation.mutate(body, { onSuccess: () => setPassword('') })
  }

  return (
    <div className="border border-border bg-surface p-4">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">EMAIL — SMTP</div>
      <p className="mb-3 text-[10px] leading-relaxed text-text-secondary">
        Email alerts for CRITICAL/WARNING events. Applies immediately, no restart needed.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && (
        <div className="space-y-3">
          <div className="flex flex-wrap gap-3">
            <div className="flex-1 min-w-[10rem]">
              <label htmlFor="smtp-host" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                SMTP SERVER
              </label>
              <input
                id="smtp-host"
                value={form.smtp_host}
                onChange={(e) => setField('smtp_host', e.target.value)}
                placeholder="smtp.example.com"
                className="w-full border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
              />
            </div>
            <div>
              <label htmlFor="smtp-port" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                PORT
              </label>
              <input
                id="smtp-port"
                type="number"
                min={1}
                max={65535}
                value={form.smtp_port}
                onChange={(e) => setField('smtp_port', e.target.value)}
                className="w-20 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            <div className="flex-1 min-w-[10rem]">
              <label htmlFor="smtp-username" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                USERNAME
              </label>
              <input
                id="smtp-username"
                value={form.smtp_username}
                onChange={(e) => setField('smtp_username', e.target.value)}
                className="w-full border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
              />
            </div>
            <div className="flex-1 min-w-[10rem]">
              <label htmlFor="smtp-password" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                PASSWORD
              </label>
              <input
                id="smtp-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={data?.smtp_password_configured ? '••••••••' : '(not set)'}
                className="w-full border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            <div className="flex-1 min-w-[10rem]">
              <label htmlFor="smtp-from" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                FROM
              </label>
              <input
                id="smtp-from"
                value={form.smtp_from}
                onChange={(e) => setField('smtp_from', e.target.value)}
                placeholder="heimdall@example.com"
                className="w-full border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
              />
            </div>
            <div className="flex-1 min-w-[10rem]">
              <label htmlFor="smtp-to" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                TO <span className="text-text-muted">(optional — defaults to FROM)</span>
              </label>
              <input
                id="smtp-to"
                value={form.smtp_to}
                onChange={(e) => setField('smtp_to', e.target.value)}
                className="w-full border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
              />
            </div>
          </div>

          <label className="flex items-center gap-2 text-[10px] text-text-secondary">
            <input
              type="checkbox"
              checked={form.smtp_use_tls}
              onChange={(e) => setField('smtp_use_tls', e.target.checked)}
              className="accent-accent-green"
            />
            Use STARTTLS
          </label>

          <button
            type="button"
            disabled={!isDirty || !isPortValid || mutation.isPending}
            onClick={handleSave}
            className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
          >
            {mutation.isPending ? 'SAVING…' : 'SAVE'}
          </button>
        </div>
      )}

      {!isPortValid && <div className="mt-2 text-[9px] text-accent-red">Port must be between 1 and 65535.</div>}
      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
