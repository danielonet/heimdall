import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AccountExistsError, createAccount, fetchSetupRequired, login, requestPasswordReset } from '../lib/api'
import { nextWisdomPhrase } from '../lib/wisdom'
import heimdallLogo from '../assets/heimdall-icon.png'

const inputClass =
  'w-full border border-border bg-bg px-3 py-2 text-sm text-text-primary outline-none focus:border-border-active'
const labelClass = 'mb-1 block text-[9px] tracking-wider text-text-secondary'
const submitClass =
  'w-full border border-accent-green/40 bg-accent-green/10 py-2 text-[11px] tracking-[2px] text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-50'
const linkClass = 'text-[10px] tracking-wider text-text-muted underline-offset-2 hover:text-text-secondary hover:underline'

export function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [confirm, setConfirm] = useState('')
  const [pending, setPending] = useState(false)
  // null while we ask the backend whether this is a new install with no admin yet.
  const [setupRequired, setSetupRequired] = useState(null)
  // The "forgot password" form, shown in place of sign-in.
  const [forgot, setForgot] = useState(false)
  const [resetAnswer, setResetAnswer] = useState(null)
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
    setNotice('')
    if (creating) {
      if (password.length < 12) return setError('Choose a password of at least 12 characters.')
      if (password !== confirm) return setError('The two passwords do not match.')
      if (!email.trim()) return setError('Enter the email address a password-reset link should go to.')
    }
    setPending(true)
    try {
      await (creating ? createAccount(username, password, email) : login(username, password))
      navigate('/', { replace: true })
    } catch (err) {
      if (err instanceof AccountExistsError) {
        // Someone created the admin from another browser while this page was open.
        setSetupRequired(false)
        setPassword('')
        setConfirm('')
        setNotice('An admin account already exists on this server. Sign in with it.')
      } else {
        setError(err.message)
      }
    } finally {
      setPending(false)
    }
  }

  async function handleForgot(e) {
    e.preventDefault()
    setError('')
    setPending(true)
    try {
      setResetAnswer(await requestPasswordReset(email))
    } catch (err) {
      setError(err.message)
    } finally {
      setPending(false)
    }
  }

  function showForgot(value) {
    setForgot(value)
    setError('')
    setNotice('')
    setResetAnswer(null)
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

  const header = (
    <div className="mb-6 text-center">
      <img src={heimdallLogo} alt="" className="mx-auto mb-3 h-28 w-28" />
      <div className="font-heading text-xl font-bold tracking-[4px] text-accent-green">SENTINEL</div>
      <div className="mt-1 text-[9px] tracking-widest text-text-muted">HOME NET MONITOR</div>
    </div>
  )

  if (forgot && !creating) {
    return (
      <div className="flex h-screen items-center justify-center bg-bg">
        <form onSubmit={handleForgot} className="w-80 border border-border bg-surface p-8">
          {header}
          {resetAnswer ? (
            <p className="mb-6 border-l-2 border-accent-amber pl-3 text-[11px] leading-relaxed text-text-secondary">
              {resetAnswer.email_configured
                ? 'If that is the email address of the admin account, a reset link is on its way. It works once, for 30 minutes. Check the spam folder too.'
                : 'This server cannot send email yet, so no link was sent. Sign in on a browser that is still logged in and set up email on the Notifications page, or see "I forgot the admin user name or password" under Troubleshooting in the manual to reset the account on the server.'}
            </p>
          ) : (
            <>
              <p className="mb-6 border-l-2 border-border-active pl-3 text-[11px] leading-relaxed text-text-secondary">
                Enter the email address you gave when you created the account. A link to choose a new password
                will be sent to it.
              </p>
              <label htmlFor="email" className={labelClass}>
                EMAIL
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoFocus
                autoComplete="email"
                required
                className={`mb-4 ${inputClass}`}
              />
              {error && <div className="mb-4 text-[11px] text-accent-red">{error}</div>}
              <button type="submit" disabled={pending} className={submitClass}>
                {pending ? 'SENDING…' : 'SEND RESET LINK'}
              </button>
            </>
          )}
          <div className="mt-4 text-center">
            <button type="button" onClick={() => showForgot(false)} className={linkClass}>
              Back to sign in
            </button>
          </div>
        </form>
      </div>
    )
  }

  return (
    <div className="flex h-screen items-center justify-center bg-bg">
      <form onSubmit={handleSubmit} className="w-80 border border-border bg-surface p-8">
        {header}

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

        {notice && <div className="mb-4 text-[11px] text-accent-amber">{notice}</div>}

        <label htmlFor="username" className={labelClass}>
          USERNAME
        </label>
        <input
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoFocus
          autoComplete="username"
          className={`mb-4 ${inputClass}`}
        />

        {creating && (
          <>
            <label htmlFor="email" className={labelClass}>
              EMAIL (FOR PASSWORD RESET)
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              className={`mb-4 ${inputClass}`}
            />
          </>
        )}

        <label htmlFor="password" className={labelClass}>
          PASSWORD
        </label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete={creating ? 'new-password' : 'current-password'}
          className={`mb-4 ${inputClass}`}
        />

        {creating && (
          <>
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
          </>
        )}

        {error && <div className="mb-4 text-[11px] text-accent-red">{error}</div>}

        <button type="submit" disabled={pending} className={submitClass}>
          {pending ? (creating ? 'CREATING…' : 'SIGNING IN…') : creating ? 'CREATE ACCOUNT' : 'SIGN IN'}
        </button>

        {!creating && (
          <div className="mt-4 text-center">
            <button type="button" onClick={() => showForgot(true)} className={linkClass}>
              Forgot password?
            </button>
          </div>
        )}
      </form>
    </div>
  )
}
