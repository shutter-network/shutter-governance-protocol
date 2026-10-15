import { createRequire } from "node:module";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vitest/config";

// Tests run in Node, where the crypto SDK's ES-module build cannot load its WASM (it
// calls `require("fs")` dynamically). Its CommonJS build can, so tests resolve the
// package to that build and let Node load it natively. The apps are unaffected: Vite
// builds them from the ES-module entry as before.
const sdkCjs = createRequire(import.meta.url).resolve("@shutter-network/urban-verified-crypto");

export default defineConfig({
  resolve: {
    alias: {
      "@shutter-network/urban-verified-crypto": sdkCjs,
      // The workspace package, resolved the way the apps' Vite configs resolve it.
      "@shutter-governance-protocol/shared": fileURLToPath(new URL("./shared/src", import.meta.url)),
    },
  },
  test: { server: { deps: { external: [/urban-verified-crypto/] } } },
});
