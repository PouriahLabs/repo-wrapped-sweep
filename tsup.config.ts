import { defineConfig } from "tsup";

// The CLI bundles the pure scanner modules from the app (`@/lib/native-scan/*`,
// `@/lib/charts/palette`, `@/lib/code-quality/file-view`) — one source of truth,
// never a fork. The "@/*" alias comes from tsconfig.json `paths`.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node20",
  platform: "node",
  outDir: "dist",
  clean: true,
  sourcemap: false,
  minify: false,
  banner: { js: "#!/usr/bin/env node" },
});
