import { useAuthStore } from '../store/authStore'

const BASE = '/api'

// Coalesces concurrent 401s into one /api/refresh call instead of a stampede.
let refreshPromise = null

async function rawFetch(path, options = {}) {
  const { accessToken } = useAuthStore.getState()
  const headers = { ...(options.headers || {}) }
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`
  if (options.body && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json'
  }
  return fetch(BASE + path, { ...options, headers })
}

async function refreshAccessToken() {
  const { refreshToken } = useAuthStore.getState()
  if (!refreshToken) return false

  if (!refreshPromise) {
    refreshPromise = fetch(BASE + '/refresh', {
      method: 'POST',
      headers: { Authorization: `Bearer ${refreshToken}` },
    })
      .then(async (resp) => {
        if (!resp.ok) throw new Error('refresh failed')
        const data = await resp.json()
        useAuthStore.getState().setTokens({ accessToken: data.access_token })
        return true
      })
      .catch(() => {
        useAuthStore.getState().clear()
        return false
      })
      .finally(() => {
        refreshPromise = null
      })
  }
  return refreshPromise
}

/** Fetch wrapper: attaches the bearer token, retries exactly once through a
 * silent /api/refresh on a 401. */
export async function apiFetch(path, options = {}) {
  let resp = await rawFetch(path, options)
  if (resp.status === 401 && path !== '/login' && path !== '/refresh') {
    const refreshed = await refreshAccessToken()
    if (refreshed) resp = await rawFetch(path, options)
  }
  return resp
}

export async function apiJson(path, options = {}) {
  const resp = await apiFetch(path, options)
  if (!resp.ok) {
    let message = `Request failed: ${resp.status}`
    try {
      const body = await resp.json()
      if (body.error) message = body.error
    } catch {
      /* non-JSON error body — keep the generic message */
    }
    throw new Error(message)
  }
  if (resp.status === 204) return null
  return resp.json()
}

export async function login(username, password) {
  const resp = await rawFetch('/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  })
  if (!resp.ok) throw new Error('Invalid username or password')
  const data = await resp.json()
  useAuthStore.getState().setTokens({
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
  })
  return data
}

/** True while the dashboard has no admin yet (a new install): the login page then offers account creation. */
export async function fetchSetupRequired() {
  const resp = await rawFetch('/setup', { method: 'GET' })
  if (!resp.ok) throw new Error(`The dashboard backend answered ${resp.status}`)
  return Boolean((await resp.json()).setup_required)
}

/** Thrown by createAccount when another browser already created the admin: the page then shows sign-in. */
export class AccountExistsError extends Error {}

/** First run only: create the admin account and sign in with it. */
export async function createAccount(username, password, email) {
  const resp = await rawFetch('/setup', {
    method: 'POST',
    body: JSON.stringify({ username, password, email }),
  })
  const data = await resp.json().catch(() => ({}))
  if (resp.status === 409) throw new AccountExistsError(data.error || 'An admin account already exists. Sign in instead.')
  if (!resp.ok) throw new Error(data.error || `Could not create the account (${resp.status})`)
  useAuthStore.getState().setTokens({
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
  })
  return data
}

/** Asks for a reset link to be emailed. Resolves {sent, email_configured}; the answer is the
 * same whether or not the address matched, so it only says whether this server can send email. */
export async function requestPasswordReset(email) {
  const resp = await rawFetch('/password-reset/request', { method: 'POST', body: JSON.stringify({ email }) })
  const data = await resp.json().catch(() => ({}))
  if (!resp.ok) throw new Error(data.error || `Could not ask for a reset link (${resp.status})`)
  return data
}

/** Sets a new password with the token from the reset email, and signs in. */
export async function resetPassword(token, password) {
  const resp = await rawFetch('/password-reset', { method: 'POST', body: JSON.stringify({ token, password }) })
  const data = await resp.json().catch(() => ({}))
  if (!resp.ok) throw new Error(data.error || `Could not reset the password (${resp.status})`)
  useAuthStore.getState().setTokens({ accessToken: data.access_token, refreshToken: data.refresh_token })
  return data
}

export async function logout() {
  const { accessToken } = useAuthStore.getState()
  if (accessToken) {
    try {
      await rawFetch('/logout', { method: 'POST' })
    } catch {
      /* best-effort — clear local state regardless */
    }
  }
  useAuthStore.getState().clear()
}

/** Called once at app boot: if a refresh token survived a reload, silently
 * mint a fresh access token before anything renders past AuthGuard. */
export async function bootstrapAuth() {
  const { refreshToken } = useAuthStore.getState()
  if (refreshToken) await refreshAccessToken()
  useAuthStore.getState().markAuthReady()
}
