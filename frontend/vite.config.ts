import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development the API runs separately (`certfabric serve`); in production FastAPI serves dist/.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8080",
      "/ws": { target: "ws://localhost:8080", ws: true },
    },
  },
});
