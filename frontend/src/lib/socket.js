import { io } from 'socket.io-client'

// Same-origin (dev: Vite proxy, prod: nginx) — see vite.config.js /
// frontend/nginx.conf. Namespace and default Engine.IO path confirmed
// against sentinel/api/extensions.py + sentinel/api/websocket.py.
export const socket = io('/sentinel', { autoConnect: false })

export function connectSocket() {
  if (!socket.connected) socket.connect()
}

export function disconnectSocket() {
  if (socket.connected) socket.disconnect()
}
