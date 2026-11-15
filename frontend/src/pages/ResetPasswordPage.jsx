import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { resetPassword } from '../lib/api'
import heimdallLogo from '../assets/heimdall-icon.png'

const inputClass =
  'w-full border border-border bg-bg px-3 py-2 text-sm text-text-primary outline-none focus:border-border-active'
const labelClass = 'mb-1 block text-[9px] tracking-wider text-text-secondary'

/** Opened from the link in the password-reset email: choose a new password, then go straight in. */
export function ResetPasswordPage() {
  const [params] = useSearchParams()
  const token = params.get('token') || ''
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const navigate = useNavigate()
  const mismatch = confirm !== '' && confirm !== password

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (password.length < 12) return setError('Choose a password of at least 12 characters.')
    if (password !== confirm) return setError('The two passwords do not match.')
    setPending(true)
    try {
      await resetPassword(token, password)
      navigate('/', { replace: true })
    } catch (err) {
      setError(err.message)
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="flex h-screen items-center justify-center bg-bg">
      <form onSubmit={handleSubmit} className="w-80 border border-border bg-surface p-8">
        <div className="mb-6 text-center">
          <img src={heimdallLogo} alt="" className="mx-auto mb-3 h-28 w-28" />
          <div className="font-heading text-xl font-bold tracking-[4px] text-accent-green">SENTINEL</div>
          <div className="mt-1 text-[9px] tracking-widest text-text-muted">NEW PASSWORD</div>
        </div>

        {!token ? (
          <p className="mb-6 border-l-2 border-accent-red pl-3 text-[11px] leading-relaxed text-text-secondary">
            This page needs the link from the reset email. Ask for a new one from the sign-in page.
          </p>
        ) : (
          <>
            <p className="mb-6 border-l-2 border-border-active pl-3 text-[11px] leading-relaxed text-text-secondary">
              Choose a new password of at least 12 characters. Every other signed-in browser will be signed out.
            </p>
            <label htmlFor="password" className={labelClass}>
              NEW PASSWORD
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
              autoComplete="new-password"
              className={`mb-4 ${inputClass}`}
            />
            <label htmlFor="confirm" className={labelClass}>
              REPEAT PASSWORD
            </label>
            <input
              id="confirm"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              className={`mb-1 ${inputClass}`}
            />
            <div className="mb-4 h-4 text-[10px] text-accent-red">{mismatch ? 'Does not match yet.' : ''}</div>
            {error && <div className="mb-4 text-[11px] text-accent-red">{error}</div>}
            <button
              type="submit"
              disabled={pending}
              className="w-full border border-accent-green/40 bg-accent-green/10 py-2 text-[11px] tracking-[2px] text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-50"
            >
              {pending ? 'SAVING…' : 'SET PASSWORD'}
            </button>
          </>
        )}
        <div className="mt-4 text-center">
          <Link
            to="/login"
            className="text-[10px] tracking-wider text-text-muted underline-offset-2 hover:text-text-secondary hover:underline"
          >
            Back to sign in
          </Link>
        </div>
      </form>
    </div>
  )
}
