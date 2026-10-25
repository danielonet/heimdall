import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'

// Second-router credentials — a Redmi/Xiaomi router on stock MiWiFi
// firmware (see sentinel/adapter/miwifi/). Entirely optional: leaving
// MIWIFI IP blank means Heimdall behaves exactly as it did with only the
// Sagemcom. Same field shape and "leave blank to keep current" convention
// as RouterCredentialsForm right above it (Equipment page) — MiWiFi login only needs a
// password, not a username, hence IP+password instead of username+password.
export function MiwifiCredentialsForm() {
  const { data } = useSettings()
  const mutation = useUpdateSettings()
  const [ip, setIp] = useState('')
  const [password, setPassword] = useState('')

  useEffect(() => {
    if (data) setIp(data.miwifi_ip || '')
  }, [data])

  const isDirty = (data && ip !== (data.miwifi_ip || '')) || password !== ''

  function handleSave() {
    const body = { miwifi_ip: ip }
    if (password) body.miwifi_password = password
    mutation.mutate(body, { onSuccess: () => setPassword('') })
  }

  return (
    <div className="mt-2 border-t border-border/50 pt-2">
      <div className="mb-1.5 text-[8px] tracking-[3px] text-text-muted">REDMI ROUTER (MIWIFI)</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        Optional second router — monitored for device/traffic visibility alongside the Sagemcom.
        Leave IP blank to disable it.
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <label htmlFor="miwifi-ip" className="mb-1 block text-[9px] tracking-wider text-text-muted">
            IP ADDRESS
          </label>
          <input
            id="miwifi-ip"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="192.168.31.1"
            className="w-36 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
          />
        </div>
        <div>
          <label htmlFor="miwifi-password" className="mb-1 block text-[9px] tracking-wider text-text-muted">
            PASSWORD
          </label>
          <input
            id="miwifi-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={data?.miwifi_password_configured ? '••••••••' : '(not set)'}
            className="w-36 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
          />
        </div>
        <button
          type="button"
          disabled={!isDirty || mutation.isPending}
          onClick={handleSave}
          className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
        >
          {mutation.isPending ? 'SAVING…' : 'SAVE'}
        </button>
      </div>
      <p className="mt-1.5 text-[9px] text-text-muted">Leave password blank to keep the current one. Applies immediately.</p>
      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
