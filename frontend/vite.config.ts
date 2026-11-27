import {defineConfig} from 'vite'
import {svelte} from '@sveltejs/vite-plugin-svelte'

// In `npm run dev`, API + SSE calls are proxied to the Go server on :8081.
export default defineConfig({
  plugins: [svelte()],
  server: {
    proxy: {
      '/api': { target: 'http://127.0.0.1:8081', changeOrigin: false },
    },
  },
})
