import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Dev server only (`npm run dev`; the containerised build is served by
    // nginx on :3000). Binds to localhost unless VITE_HOST is set — use
    // VITE_HOST=0.0.0.0 (or FRONTEND_HOST via scripts/dev.sh / run.sh) to
    // reach it from another machine on the LAN.
    host: process.env.VITE_HOST || 'localhost',
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/socket.io': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        ws: true,
      },
    },
  },
})
