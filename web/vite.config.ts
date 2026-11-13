import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Frontend only. The API key lives in the Node backend and is never bundled here.
export default defineConfig({
  root: import.meta.dirname,
  plugins: [react()],
  base: './',
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false, target: 'es2022' },
  server: { port: 5173, proxy: { '/api': 'http://127.0.0.1:8787' } },
});
