import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'

const EMPTY_SMTP_FORM = {
  smtp_host: '', smtp_port: '587', smtp_from: '', smtp_to: '', smtp_username: '', smtp_use_tls: true,
}

/** Merged NtfyUrlSection + SmtpSection — the two outbound notification
 * channels, one card. Consolidated out of the standalone Notifications tab
 * into Settings; see SettingsPage's own note on that. Each channel keeps
 * its own independent form/save (two PATCH bodies, two dirty-trackers),
 * just under one shared intro instead of two — the "CRITICAL now, everything
 * else in the daily digest" behavior is identical for both channels
 * (NotificationService.notify() fans the same event out to whichever
 * channels are configured), so a single accurate paragraph replaces what
 * used to be two — one of which had drifted out of sync with the actual
 * severity gate (notify_new_critical_alert is CRITICAL-only, not
 * CRITICAL/WARNING as the old ntfy copy claimed). */
export function NotificationsSection() {
  const { data, isLoading } = useSettings()
  const mutation = useUpdateSettings()

  const [ntfyUrl, setNtfyUrl] = useState('')
  const [smtpForm, setSmtpForm] = useState(EMPTY_SMTP_FORM)
  const [smtpPassword, setSmtpPassword] = useState('')

  useEffect(() => {
    if (!data) return
    setNtfyUrl(data.ntfy_url || '')
    setSmtpForm({
      smtp_host: data.smtp_host || '',
      smtp_port: String(data.smtp_port || 587),
      smtp_from: data.smtp_from || '',
      smtp_to: data.smtp_to || '',
      smtp_username: data.smtp_username || '',
      smtp_use_tls: data.smtp_use_tls,
    })
  }, [data])

  function setSmtpField(key, value) {
    setSmtpForm((f) => ({ ...f, [key]: value }))
  }

  const ntfyDirty = data && ntfyUrl !== (data.ntfy_url || '')

  const smtpPort = Number(smtpForm.smtp_port)
  const isSmtpPortValid = Number.isInteger(smtpPort) && smtpPort >= 1 && smtpPort <= 65535
  const smtpDirty =
    data &&
    (smtpForm.smtp_host !== (data.smtp_host || '') ||
      smtpForm.smtp_port !== String(data.smtp_port || 587) ||
      smtpForm.smtp_from !== (data.smtp_from || '') ||
      smtpForm.smtp_to !== (data.smtp_to || '') ||
      smtpForm.smtp_username !== (data.smtp_username || '') ||
      smtpForm.smtp_use_tls !== data.smtp_use_tls ||
      smtpPassword !== '')

  function saveSmtp() {
    if (!isSmtpPortValid) return
    const body = {
      smtp_host: smtpForm.smtp_host,
      smtp_port: smtpPort,
      smtp_from: smtpForm.smtp_from,
      smtp_to: smtpForm.smtp_to,
      smtp_username: smtpForm.smtp_username,
      smtp_use_tls: smtpForm.smtp_use_tls,
    }
    if (smtpPassword) body.smtp_password = smtpPassword
    mutation.mutate(body, { onSuccess: () => setSmtpPassword('') })
  }

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">NOTIFICATIONS</div>
      <p className="mb-3 text-[10px] leading-relaxed text-text-secondary">
        Both channels below get the same events: an immediate push the moment a CRITICAL alert fires
        (confirmed attacks, new devices, unauthorized access), plus a daily 7am digest covering
        everything else. Leave a channel's fields blank to disable it. Both apply immediately, no
        restart needed.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && (
        <div className="space-y-3">
          <div>
            <div className="mb-1 text-[8px] tracking-[2px] text-text-muted">PUSH — NTFY.SH</div>
            <div className="flex flex-wrap items-end gap-3">
              <div className="flex-1 min-w-[14rem]">
                <label htmlFor="ntfy-url" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                  TOPIC URL
                </label>
                <input
                  id="ntfy-url"
                  value={ntfyUrl}
                  onChange={(e) => setNtfyUrl(e.target.value)}
                  placeholder="https://ntfy.sh/heimdall-alerts"
                  className="w-full border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
                />
              </div>
              <button
                type="button"
                disabled={!ntfyDirty || mutation.isPending}
                onClick={() => mutation.mutate({ ntfy_url: ntfyUrl })}
                className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
              >
                {mutation.isPending ? 'SAVING…' : 'SAVE'}
              </button>
            </div>
          </div>

          <div className="border-t border-border/50 pt-3">
            <div className="mb-2 text-[8px] tracking-[2px] text-text-muted">EMAIL — SMTP</div>

            <div className="space-y-2">
              <div className="flex flex-wrap gap-3">
                <div className="flex-1 min-w-[10rem]">
                  <label htmlFor="smtp-host" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                    SMTP SERVER
                  </label>
                  <input
                    id="smtp-host"
                    value={smtpForm.smtp_host}
                    onChange={(e) => setSmtpField('smtp_host', e.target.value)}
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
                    value={smtpForm.smtp_port}
                    onChange={(e) => setSmtpField('smtp_port', e.target.value)}
                    className="w-20 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
                  />
                </div>
                <label className="flex items-center gap-2 self-end pb-1.5 text-[10px] whitespace-nowrap text-text-secondary">
                  <input
                    type="checkbox"
                    checked={smtpForm.smtp_use_tls}
                    onChange={(e) => setSmtpField('smtp_use_tls', e.target.checked)}
                    className="accent-accent-green"
                  />
                  STARTTLS
                </label>
              </div>

              <div className="flex flex-wrap gap-3">
                <div className="flex-1 min-w-[10rem]">
                  <label htmlFor="smtp-username" className="mb-1 block text-[9px] tracking-wider text-text-muted">
                    USERNAME
                  </label>
                  <input
                    id="smtp-username"
                    value={smtpForm.smtp_username}
                    onChange={(e) => setSmtpField('smtp_username', e.target.value)}
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
                    value={smtpPassword}
                    onChange={(e) => setSmtpPassword(e.target.value)}
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
                    value={smtpForm.smtp_from}
                    onChange={(e) => setSmtpField('smtp_from', e.target.value)}
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
                    value={smtpForm.smtp_to}
                    onChange={(e) => setSmtpField('smtp_to', e.target.value)}
                    className="w-full border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
                  />
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  disabled={!smtpDirty || !isSmtpPortValid || mutation.isPending}
                  onClick={saveSmtp}
                  className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
                >
                  {mutation.isPending ? 'SAVING…' : 'SAVE'}
                </button>
                {!isSmtpPortValid && (
                  <div className="text-[9px] text-accent-red">Port must be between 1 and 65535.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
