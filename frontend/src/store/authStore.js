import { create } from 'zustand'

const REFRESH_TOKEN_KEY = 'heimdall_refresh_token'

// Access token lives in memory only (15 min expiry) — never persisted.
// Refresh token persists in localStorage (7 day expiry) so a page reload
// doesn't force a re-login; see lib/api.js's bootstrapAuth()/refresh flow.
export const useAuthStore = create((set, get) => ({
  accessToken: null,
  refreshToken: localStorage.getItem(REFRESH_TOKEN_KEY),
  isAuthReady: false,

  setTokens({ accessToken, refreshToken }) {
    if (refreshToken !== undefined) {
      if (refreshToken) {
        localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      } else {
        localStorage.removeItem(REFRESH_TOKEN_KEY)
      }
    }
    set({
      accessToken: accessToken !== undefined ? accessToken : get().accessToken,
      refreshToken: refreshToken !== undefined ? refreshToken : get().refreshToken,
    })
  },

  clear() {
    localStorage.removeItem(REFRESH_TOKEN_KEY)
    set({ accessToken: null, refreshToken: null })
  },

  markAuthReady() {
    set({ isAuthReady: true })
  },
}))
