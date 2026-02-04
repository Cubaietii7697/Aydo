import { defineConfig } from "electron-vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

const sharedAlias = {
  "@shared": path.resolve(__dirname, "src/shared")
};

export default defineConfig({
  main: {
    resolve: {
      alias: sharedAlias
    },
    build: {
      outDir: path.resolve(__dirname, "dist/main")
    }
  },
  preload: {
    resolve: {
      alias: sharedAlias
    },
    build: {
      outDir: path.resolve(__dirname, "dist/preload")
    }
  },
  renderer: {
    root: path.resolve(__dirname, "src/renderer"),
    build: {
      outDir: path.resolve(__dirname, "dist/renderer"),
      emptyOutDir: true
    },
    resolve: {
      alias: {
        "@renderer": path.resolve(__dirname, "src/renderer"),
        ...sharedAlias
      }
    },
    plugins: [react()]
  }
});
