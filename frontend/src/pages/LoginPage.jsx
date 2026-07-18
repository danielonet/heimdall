import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '../lib/api'
import { nextWisdomPhrase } from '../lib/wisdom'
import heimdallLogo from '../assets/heimdall-icon.png'

export function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  // nextWisdomPhrase() has a side effect (advances localStorage), so it can't
  // be a useState lazy initializer — Strict Mode deliberately double-invokes
  // those in dev, which would silently burn two rotation slots per visit.
  // A ref guard runs it exactly once per mount instead.
  const wisdomRef = useRef(null)
  if (wisdomRef.current === null) wisdomRef.current = nextWisdomPhrase()
  const wisdom = wisdomRef.current
  const navigate = useNavigate()

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setPending(true)
    try {
      await login(username, password)
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
          <div className="mt-1 text-[9px] tracking-widest text-text-muted">HOME NET MONITOR</div>
        </div>

        <p className="mb-6 border-l-2 border-border-active pl-3 font-nordic text-[15px] leading-relaxed tracking-wide text-text-secondary">
          {wisdom}
        </p>

        <label htmlFor="username" className="mb-1 block text-[9px] tracking-wider text-text-secondary">
          USERNAME
        </label>
        <input
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoFocus
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
          className="mb-6 w-full border border-border bg-bg px-3 py-2 text-sm text-text-primary outline-none focus:border-border-active"
        />

        {error && <div className="mb-4 text-[11px] text-accent-red">{error}</div>}

        <button
          type="submit"
          disabled={pending}
          className="w-full border border-accent-green/40 bg-accent-green/10 py-2 text-[11px] tracking-[2px] text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-50"
        >
          {pending ? 'SIGNING IN…' : 'SIGN IN'}
        </button>
      </form>
    </div>
  )
}
