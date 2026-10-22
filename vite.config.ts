import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    include: [
      '@semaphore-protocol/group',
      '@semaphore-protocol/identity',
      '@semaphore-protocol/proof',
    ],
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: { '/api': process.env.API_ORIGIN ?? 'http://127.0.0.1:3001' },
  },
  build: { outDir: 'dist/client' },
});
