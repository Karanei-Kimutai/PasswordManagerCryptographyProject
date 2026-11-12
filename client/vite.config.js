/**
 * Vite configuration.
 *
 * In development, Vite serves the React app on :5173 and forwards /api to the
 * Express server on :3001. The browser sees a single origin, exactly as in
 * production, where Express serves both the API and the built app. That
 * matters because the session cookie is SameSite=Strict and the CSRF guard
 * checks the Origin header.
 */
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:3001", changeOrigin: false },
    },
  },
  build: {
    // Source maps would publish readable source; not needed for a demo build.
    sourcemap: false,
  },
});
