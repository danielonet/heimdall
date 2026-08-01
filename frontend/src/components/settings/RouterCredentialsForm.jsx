import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'

export function RouterCredentialsForm() {
  const { data } = useSettings()
  const mutation = useUpdateSettings()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  useEffect(() => {
    if (data) setUsername(data.router_username)
  }, [data])

  const isDirty = (data && username !== data.router_username) || password !== ''

  function handleSave() {
    const body = { router_username: username }
    if (password) body.router_password = password
    mutation.mutate(body, { onSuccess: () => setPassword('') })
  }

  return (
    <div className="mt-2 border-t border-border/50 pt-2">
      <div className="mb-1.5 text-[8px] tracking-[3px] text-text-muted">ROUTER LOGIN</div>
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <label htmlFor="router-username" className="mb-1 block text-[9px] tracking-wider text-text-muted">
            USERNAME
          </label>
          <input
            id="router-username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-36 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
          />
        </div>
        <div>
          <label htmlFor="router-password" className="mb-1 block text-[9px] tracking-wider text-text-muted">
            PASSWORD
          </label>
          <input
            id="router-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={data?.router_password_configured ? '••••••••' : '(not set)'}
            className="w-36 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
          />
        </div>
        <button
          type="button"
          disabled={!isDirty || !username.trim() || mutation.isPending}
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
