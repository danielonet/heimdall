import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { createAccount, fetchSetupRequired, login } from '../lib/api'
import { nextWisdomPhrase } from '../lib/wisdom'
import heimdallLogo from '../assets/heimdall-icon.png'

export function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [confirm, setConfirm] = useState('')
  const [pending, setPending] = useState(false)
  // null while we ask the backend whether this is a new install with no admin yet.
  const [setupRequired, setSetupRequired] = useState(null)
  // nextWisdomPhrase() has a side effect (advances localStorage), so it can't
  // be a useState lazy initializer — Strict Mode deliberately double-invokes
  // those in dev, which would silently burn two rotation slots per visit.
  // A ref guard runs it exactly once per mount instead.
  const wisdomRef = useRef(null)
  if (wisdomRef.current === null) wisdomRef.current = nextWisdomPhrase()
  const wisdom = wisdomRef.current
  const navigate = useNavigate()

  // Which form to show is decided by the backend, so neither is rendered until it answers; a failed
  // check is shown as an error with a retry rather than guessed as "sign in".
  const [setupError, setSetupError] = useState('')
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    fetchSetupRequired()
      .then((required) => !cancelled && setSetupRequired(required))
      .catch((err) => !cancelled && setSetupError(err.message))
    return () => {
      cancelled = true
    }
  }, [attempt])

  const creating = setupRequired === true
  const mismatch = creating && confirm !== '' && confirm !== password

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (creating) {
      if (password.length < 12) return setError('Choose a password of at least 12 characters.')
      if (password !== confirm) return setError('The two passwords do not match.')
    }
    setPending(true)
    try {
      await (creating ? createAccount(username, password) : login(username, password))
      navigate('/', { replace: true })
    } catch (err) {
      setError(err.message)
    } finally {
      setPending(false)
    }
  }

  if (setupRequired === null) {
    return (
      <div className="flex h-screen flex-col items-center justify-center gap-3 bg-bg text-[11px] text-text-secondary">
        <img src={heimdallLogo} alt="" className="h-20 w-20" />
        {setupError ? (
          <>
            <div className="text-accent-red">Cannot reach the dashboard backend: {setupError}</div>
            <button
              type="button"
              onClick={() => {
                setSetupError('')
                setAttempt((n) => n + 1)
              }}
              className="border border-border px-3 py-1 tracking-wider hover:border-border-active"
            >
              RETRY
            </button>
          </>
        ) : (
          <div className="text-text-muted">Loading…</div>
        )}
      </div>
    )
  }

  return (
    <div className="flex h-screen items-center justify-center bg-bg">
      <form onSubmit={handleSubmit} className="w-80 border border-border bg-surface p-8">
        <div className="mb-6 text-center">
          <img src={heimdallLogo} alt="" className="mx-auto mb-3 h-28 w-28" />
          <div className="font-heading text-xl font-bold tracking-[4px] text-accent-green">SENTINEL</div>
          <div className="mt-1 text-[9px] tracking-widest text-text-muted">HOME NET MONITOR</div>
        </div>

        {creating ? (
          <p className="mb-6 border-l-2 border-accent-amber pl-3 text-[11px] leading-relaxed text-text-secondary">
            Welcome. This is a new install, so there is no login yet. Choose the user name and password you will
            use to sign in. The password is stored only as a salted hash.
          </p>
        ) : (
          <p className="mb-6 border-l-2 border-border-active pl-3 font-nordic text-[15px] leading-relaxed tracking-wide text-text-secondary">
            {wisdom}
          </p>
        )}

        <label htmlFor="username" className="mb-1 block text-[9px] tracking-wider text-text-secondary">
          USERNAME
        </label>
        <input
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoFocus
          autoComplete="username"
          className="mb-4 w-full border border-border bg-bg px-3 py-2 text-sm text-text-primary outline-none focus:border-border-active"
        />

        <label htmlFor="password" className="mb-1 block text-[9px] tracking-wider text-text-secondary">
          PASSWORD
        </label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete={creating ? 'new-password' : 'current-password'}
          className="mb-4 w-full border border-border bg-bg px-3 py-2 text-sm text-text-primary outline-none focus:border-border-active"
        />

        {creating && (
          <>
            <label htmlFor="confirm" className="mb-1 block text-[9px] tracking-wider text-text-secondary">
              REPEAT PASSWORD
            </label>
            <input
              id="confirm"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              className="mb-1 w-full border border-border bg-bg px-3 py-2 text-sm text-text-primary outline-none focus:border-border-active"
            />
            <div className="mb-4 h-4 text-[10px] text-accent-red">{mismatch ? 'Does not match yet.' : ''}</div>
          </>
        )}

        {error && <div className="mb-4 text-[11px] text-accent-red">{error}</div>}

        <button
          type="submit"
          disabled={pending}
          className="w-full border border-accent-green/40 bg-accent-green/10 py-2 text-[11px] tracking-[2px] text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-50"
        >
          {pending ? (creating ? 'CREATING…' : 'SIGNING IN…') : creating ? 'CREATE ACCOUNT' : 'SIGN IN'}
        </button>
      </form>
    </div>
  )
}
