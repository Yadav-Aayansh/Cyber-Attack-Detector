import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  base: '/Cyber-Attack-Detector/',
  plugins: [react()],
  optimizeDeps: {
    exclude: ['lucide-react'],
  },
});
