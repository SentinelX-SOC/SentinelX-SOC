import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
  },
  preview: {
    host: '0.0.0.0',
    allowedHosts: ['disciplined-warmth-production-393e.up.railway.app'],
  },
})