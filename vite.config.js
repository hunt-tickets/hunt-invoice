import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: 'index.html',
        accept: 'accept.html',
        error: 'error.html'
      }
    }
  },
  preview: {
    allowedHosts: ['hunt-invoice-production.up.railway.app', 'invoice.hunt-tickets.com', 'new-invoice.hunt-tickets.com']
  }
})