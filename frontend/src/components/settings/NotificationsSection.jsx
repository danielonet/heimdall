import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'

const MIN_SMTP_PORT = 1
const MAX_SMTP_PORT = 65535

export function NotificationsSection() {
  const { data, isLoading } = useSettings()
  const ntfyMutation = useUpdateSettings()
  const smtpMutation = useUpdateSettings()

  const [ntfyUrl, setNtfyUrl] = useState('')
  const [smtpHost, setSmtpHost] = useState('')
  const [smtpPort, setSmtpPort] = useState('')
  const [smtpFrom, setSmtpFrom] = useState('')
  const [smtpTo, setSmtpTo] = useState('')
  const [smtpUsername, setSmtpUsername] = useState('')
  const [smtpPassword, setSmtpPassword] = useState('')
  const [smtpUseTls, setSmtpUseTls] = useState(true)

  useEffect(() => {
    if (!data) return
    setNtfyUrl(data.ntfy_url || '')
    setSmtpHost(data.smtp_host || '')
    setSmtpPort(String(data.smtp_port || 587))
    setSmtpFrom(data.smtp_from || '')
    setSmtpTo(data.smtp_to || '')
    setSmtpUsername(data.smtp_username || '')
    setSmtpUseTls(data.smtp_use_tls ?? true)
  }, [data])

  const ntfyDirty = data && ntfyUrl !== (data.ntfy_url || '')

  const parsedPort = Number(smtpPort)
  const portValid =
    smtpPort !== '' && Number.isInteger(parsedPort) && parsedPort >= MIN_SMTP_PORT && parsedPort <= MAX_SMTP_PORT
  const smtpDirty =
    data &&
    (smtpHost !== (data.smtp_host || '') ||
      String(parsedPort) !== String(data.smtp_port || 587) ||
      smtpFrom !== (data.smtp_from || '') ||
      smtpTo !== (data.smtp_to || '') ||
      smtpUsername !== (data.smtp_username || '') ||
      smtpUseTls !== (data.smtp_use_tls ?? true) ||
      smtpPassword !== '')

  function saveNtfy() {
    ntfyMutation.mutate({ ntfy_url: ntfyUrl })
  }

  function saveSmtp() {
    const body = {
      smtp_host: smtpHost,
      smtp_port: parsedPort,
      smtp_from: smtpFrom,
      smtp_to: smtpTo,
      smtp_username: smtpUsername,
      smtp_use_tls: smtpUseTls,
    }
    if (smtpPassword) body.smtp_password = smtpPassword
    smtpMutation.mutate(body, { onSuccess: () => setSmtpPassword('') })
  }

  return (
    <div className="border border-border bg-surface p-4">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">NOTIFICATIONS</div>
      <p className="mb-3 text-[10px] leading-relaxed text-text-secondary">
        Push (ntfy.sh) and email channels used by rule-triggered notifications and the daily
        security digest. Applies immediately, no restart needed.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && (
        <div className="space-y-4">
          <div>
            <div className="mb-2 text-[8px] tracking-[2px] text-text-muted">NTFY</div>
            <div className="flex flex-wrap items-end gap-3">
              <div className="min-w-[220px] flex-1">
                <label htmlFor="ntfy-url" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                  TOPIC URL
                </label>
                <input
                  id="ntfy-url"
                  value={ntfyUrl}
                  onChange={(e) => setNtfyUrl(e.target.value)}
                  placeholder="https://ntfy.sh/your-topic"
                  className="w-full border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
                />
              </div>
              <button
                type="button"
                disabled={!ntfyDirty || ntfyMutation.isPending}
                onClick={saveNtfy}
                className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
              >
                {ntfyMutation.isPending ? 'SAVING…' : 'SAVE'}
              </button>
            </div>
            {ntfyMutation.isError && (
              <div className="mt-2 text-[9px] text-accent-red">{ntfyMutation.error.message}</div>
            )}
          </div>

          <div className="border-t border-border/50 pt-4">
            <div className="mb-2 text-[8px] tracking-[2px] text-text-muted">SMTP EMAIL</div>
            <div className="flex flex-wrap items-end gap-3">
              <div>
                <label htmlFor="smtp-host" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                  HOST
                </label>
                <input
                  id="smtp-host"
                  value={smtpHost}
                  onChange={(e) => setSmtpHost(e.target.value)}
                  className="w-40 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
                />
              </div>
              <div>
                <label htmlFor="smtp-port" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                  PORT
                </label>
                <input
                  id="smtp-port"
                  type="number"
                  min={MIN_SMTP_PORT}
                  max={MAX_SMTP_PORT}
                  value={smtpPort}
                  onChange={(e) => setSmtpPort(e.target.value)}
                  className="w-20 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
                />
              </div>
              <div>
                <label htmlFor="smtp-from" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                  FROM
                </label>
                <input
                  id="smtp-from"
                  value={smtpFrom}
                  onChange={(e) => setSmtpFrom(e.target.value)}
                  className="w-40 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
                />
              </div>
              <div>
                <label htmlFor="smtp-to" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                  TO
                </label>
                <input
                  id="smtp-to"
                  value={smtpTo}
                  onChange={(e) => setSmtpTo(e.target.value)}
                  placeholder={smtpFrom ? '(defaults to FROM)' : ''}
                  className="w-40 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
                />
              </div>
              <div>
                <label htmlFor="smtp-username" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                  USERNAME
                </label>
                <input
                  id="smtp-username"
                  value={smtpUsername}
                  onChange={(e) => setSmtpUsername(e.target.value)}
                  className="w-36 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
                />
              </div>
              <div>
                <label htmlFor="smtp-password" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                  PASSWORD
                </label>
                <input
                  id="smtp-password"
                  type="password"
                  value={smtpPassword}
                  onChange={(e) => setSmtpPassword(e.target.value)}
                  placeholder={data?.smtp_password_configured ? '••••••••' : '(not set)'}
                  className="w-36 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
                />
              </div>
              <label className="flex items-center gap-2 pb-2 text-[10px] text-text-secondary">
                <input
                  type="checkbox"
                  checked={smtpUseTls}
                  onChange={(e) => setSmtpUseTls(e.target.checked)}
                  className="accent-accent-green"
                />
                USE TLS
              </label>
              <button
                type="button"
                disabled={!smtpDirty || !portValid || smtpMutation.isPending}
                onClick={saveSmtp}
                className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
              >
                {smtpMutation.isPending ? 'SAVING…' : 'SAVE'}
              </button>
            </div>
            {smtpPort !== '' && !portValid && (
              <div className="mt-2 text-[9px] text-accent-red">
                Port must be a whole number between {MIN_SMTP_PORT} and {MAX_SMTP_PORT}.
              </div>
            )}
            <p className="mt-2 text-[9px] text-text-muted">Leave password blank to keep the current one.</p>
            {smtpMutation.isError && (
              <div className="mt-2 text-[9px] text-accent-red">{smtpMutation.error.message}</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
