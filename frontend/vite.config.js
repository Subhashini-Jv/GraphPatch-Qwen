import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// `npm run dev` talks to the backend on :8000; `npm run build` writes dist/, which the backend serves at /
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { '/api': 'http://localhost:8000' } },
  build: { assetsDir: 'static', chunkSizeWarningLimit: 1500 },
})
