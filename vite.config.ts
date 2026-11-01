import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  // The API reads PORT and APP_ORIGIN from the same .env, so the dev proxy must
  // follow it too; otherwise a changed PORT leaves the frontend calling a port
  // that nothing (or something else) is listening on.
  const env = loadEnv(mode, process.cwd(), '');
  const apiOrigin =
    process.env.API_ORIGIN ?? env.API_ORIGIN ?? `http://127.0.0.1:${env.PORT ?? '3001'}`;
  return {
    plugins: [react()],
    server: {
      port: 5173,
      strictPort: true,
      proxy: { '/api': apiOrigin },
    },
    build: { outDir: 'dist/client' },
  };
});
