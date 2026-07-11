import { useEffect } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuthStore } from './store/authStore'
import { bootstrapAuth } from './lib/api'
import { connectSocket, disconnectSocket } from './lib/socket'
import { useSocketEvents } from './hooks/useSocketEvents'

export function AuthGuard({ children }) {
  const isAuthReady = useAuthStore((s) => s.isAuthReady)
  const accessToken = useAuthStore((s) => s.accessToken)
  const location = useLocation()

  useEffect(() => {
    bootstrapAuth()
  }, [])

  useEffect(() => {
    if (accessToken) connectSocket()
    else disconnectSocket()
  }, [accessToken])

  useSocketEvents()

  if (!isAuthReady) {
    return (
      <div className="flex h-screen items-center justify-center bg-bg text-[11px] tracking-widest text-text-muted">
        LOADING…
      </div>
    )
  }

  if (!accessToken && location.pathname !== '/login') {
    return <Navigate to="/login" replace />
  }

  return children
}
