import { defineConfig } from "vite";

export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    // Keep assets external rather than inlining into HTML/JS so strict CSP holds.
    assetsInlineLimit: 0,
    cssCodeSplit: false,
  },
});
