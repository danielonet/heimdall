import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../../lib/api'

const inputClass =
  'border border-border bg-bg px-2 py-1 text-[11px] text-text-primary outline-none focus:border-border-active'

/** The admin account: who is signed in and the email a password-reset link goes to. */
export function AccountSection() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['account'], queryFn: () => apiJson('/account') })
  const [editing, setEditing] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const save = useMutation({
    mutationFn: () => apiJson('/account/email', { method: 'PUT', body: JSON.stringify({ email, password }) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['account'] })
      setEditing(false)
      setPassword('')
    },
  })

  if (!data) return null

  function startEditing() {
    setEmail(data.email)
    setPassword('')
    save.reset()
    setEditing(true)
  }

  return (
    <div className="space-y-2 text-[10px] text-text-secondary">
      <div>
        Signed in as <span className="text-text-primary">{data.username}</span>
        {' · '}reset email: <span className="text-text-primary">{data.email}</span>
        {!editing && (
          <button type="button" onClick={startEditing} className="ml-2 text-accent-green hover:underline">
            CHANGE
          </button>
        )}
      </div>

      {editing && (
        <form
          onSubmit={(e) => {
            e.preventDefault()
            save.mutate()
          }}
          className="flex flex-wrap items-center gap-2"
        >
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            autoComplete="email"
            aria-label="Reset email"
            className={`w-56 ${inputClass}`}
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="current password"
            autoComplete="current-password"
            aria-label="Current password"
            className={`w-40 ${inputClass}`}
          />
          <button
            type="submit"
            disabled={save.isPending || !email || !password}
            className="border border-accent-green/30 bg-accent-green/5 px-3 py-1 tracking-wider text-accent-green hover:bg-accent-green/20 disabled:opacity-40"
          >
            {save.isPending ? 'SAVING…' : 'SAVE'}
          </button>
          <button type="button" onClick={() => setEditing(false)} className="px-2 py-1 tracking-wider text-text-muted">
            CANCEL
          </button>
          {save.isError && <span className="w-full text-[9px] text-accent-red">{save.error.message}</span>}
        </form>
      )}
      <div className="text-[9px] text-text-muted">
        The reset link is sent through the email server set on the Notifications page.
      </div>
    </div>
  )
}
