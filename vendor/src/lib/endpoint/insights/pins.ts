// Per-repo toolchain pins for Machine Insights (ENDPOINT-MACHINE-INSIGHTS § C2.3) —
// PURE: the collector reads the files, this module parses their text. No fs, no clock.
//
// A pin is "this repo wants tool X at version/range Y, and says so in file Z". Every pin file
// a repo carries yields its own Pin, so a repo whose `.nvmrc`, `engines.node` and
// `packageManager` disagree reports all three — drift.ts judges each independently.
//
// `wanted` is kept as written (minus a leading `v`): a major (`22`), an exact version, a semver
// range (`>=20 <23`), or an alias the file format allows (`lts/iron`, `stable`) that drift.ts
// reports as "can't judge" rather than guessing.

export const TOOL_IDS = [
  "node",
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "deno",
  "python",
  "pip",
  "uv",
  "java",
  "go",
  "rustc",
  "cargo",
  "dotnet",
  "git",
  "gh",
  "docker",
  "kubectl",
  "terraform",
  "aws",
  "gcloud",
  "az",
  "vercel",
  "code",
  "cursor",
] as const;
export type ToolId = (typeof TOOL_IDS)[number];

export interface Pin {
  tool: ToolId;
  wanted: string;
  /** The file (or file field) the pin came from: `.nvmrc`, `engines.node`, `packageManager`, … */
  source: string;
}

/** The files a collector should read from a repo root to find pins. */
export const PIN_FILES: readonly string[] = [
  ".nvmrc",
  ".node-version",
  "package.json",
  ".python-version",
  ".tool-versions",
  "rust-toolchain",
  "rust-toolchain.toml",
  "go.mod",
  "global.json",
];

const isTool = (s: string): s is ToolId => (TOOL_IDS as readonly string[]).includes(s);

const stripV = (s: string): string => s.trim().replace(/^v(?=\d)/i, "");

/** First line that is neither blank nor a `#` comment. */
function firstValueLine(text: string): string | null {
  for (const raw of text.replace(/^﻿/, "").split("\n")) {
    const line = raw.replace(/\r$/, "").trim();
    if (line && !line.startsWith("#")) return line;
  }
  return null;
}

function pin(tool: ToolId, wanted: string | null | undefined, source: string): Pin[] {
  const w = typeof wanted === "string" ? stripV(wanted) : "";
  return w ? [{ tool, wanted: w, source }] : [];
}

/** `.tool-versions` / mise plugin names → our tool ids. */
const TOOL_VERSIONS_PLUGINS: Record<string, ToolId> = {
  nodejs: "node",
  node: "node",
  python: "python",
  golang: "go",
  go: "go",
  rust: "rustc",
  java: "java",
  dotnet: "dotnet",
  "dotnet-core": "dotnet",
  terraform: "terraform",
  pnpm: "pnpm",
  yarn: "yarn",
  bun: "bun",
  deno: "deno",
  kubectl: "kubectl",
  awscli: "aws",
  gcloud: "gcloud",
  uv: "uv",
};

function parseToolVersions(text: string): Pin[] {
  const out: Pin[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const [plugin, version] = line.split(/\s+/);
    const tool = TOOL_VERSIONS_PLUGINS[(plugin ?? "").toLowerCase()];
    if (!tool || !version || version === "system" || version.startsWith("ref:")) continue;
    // Java versions carry a vendor prefix (`temurin-21.0.1`); the version is what drift compares.
    const wanted = tool === "java" ? version.replace(/^[a-z][a-z0-9_]*-/i, "") : version;
    out.push(...pin(tool, wanted, ".tool-versions"));
  }
  return out;
}

const PACKAGE_MANAGERS = ["npm", "pnpm", "yarn", "bun"] as const;
const ENGINE_TOOLS = ["node", "npm", "pnpm", "yarn", "bun"] as const;

function parsePackageJson(text: string): Pin[] {
  let json: unknown;
  try {
    json = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    return [];
  }
  if (typeof json !== "object" || json === null) return [];
  const pkg = json as { engines?: unknown; packageManager?: unknown };
  const out: Pin[] = [];

  if (typeof pkg.engines === "object" && pkg.engines !== null) {
    const engines = pkg.engines as Record<string, unknown>;
    for (const tool of ENGINE_TOOLS) {
      const v = engines[tool];
      if (typeof v === "string") out.push(...pin(tool, v, `engines.${tool}`));
    }
  }

  // Corepack form: `pnpm@9.1.0` or `pnpm@9.1.0+sha512.<hash>`.
  if (typeof pkg.packageManager === "string") {
    const m = /^([a-z]+)@([^+\s]+)/i.exec(pkg.packageManager.trim());
    const name = m?.[1]?.toLowerCase();
    if (m && name && (PACKAGE_MANAGERS as readonly string[]).includes(name) && isTool(name)) {
      out.push(...pin(name, m[2], "packageManager"));
    }
  }
  return out;
}

function parseRustToolchain(text: string, toml: boolean): Pin[] {
  if (toml || text.trimStart().startsWith("[")) {
    const m = /^\s*channel\s*=\s*["']([^"']+)["']/m.exec(text);
    return pin("rustc", m?.[1], toml ? "rust-toolchain.toml" : "rust-toolchain");
  }
  return pin("rustc", firstValueLine(text), "rust-toolchain");
}

/**
 * `go 1.22` in go.mod is a MINIMUM language version, so the pin is `>=1.22` — a newer Go
 * satisfies it. (A `toolchain go1.22.3` line is a build hint, not a requirement; ignored.)
 */
function parseGoMod(text: string): Pin[] {
  const m = /^go\s+(\d+(?:\.\d+){0,2})\b/m.exec(text);
  return m ? pin("go", `>=${m[1]}`, "go.mod") : [];
}

/**
 * global.json `sdk.version` + `rollForward`. The .NET default (`latestPatch`) and the
 * minor/feature variants stay inside the pinned major; the `*Major` variants allow any
 * newer SDK; `disable` demands that exact version.
 */
function parseGlobalJson(text: string): Pin[] {
  let json: unknown;
  try {
    json = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    return [];
  }
  const sdk = (json as { sdk?: { version?: unknown; rollForward?: unknown } } | null)?.sdk;
  if (!sdk || typeof sdk.version !== "string") return [];
  const version = sdk.version.trim();
  const major = /^(\d+)\./.exec(version)?.[1];
  const roll = typeof sdk.rollForward === "string" ? sdk.rollForward.toLowerCase() : "";
  let wanted = version;
  if (roll !== "disable" && major) {
    wanted = /major/.test(roll) ? `>=${version}` : `>=${version} <${Number(major) + 1}.0.0`;
  }
  return pin("dotnet", wanted, "global.json");
}

/**
 * Parse one pin file's text. `fileName` is the base name (see `PIN_FILES`); an unknown name
 * or unparseable content yields no pins rather than throwing.
 */
export function parsePinFile(fileName: string, content: string): Pin[] {
  switch (fileName) {
    case ".nvmrc":
      return pin("node", firstValueLine(content), ".nvmrc");
    case ".node-version":
      return pin("node", firstValueLine(content), ".node-version");
    case "package.json":
      return parsePackageJson(content);
    case ".python-version":
      return pin("python", firstValueLine(content), ".python-version");
    case ".tool-versions":
      return parseToolVersions(content);
    case "rust-toolchain":
      return parseRustToolchain(content, false);
    case "rust-toolchain.toml":
      return parseRustToolchain(content, true);
    case "go.mod":
      return parseGoMod(content);
    case "global.json":
      return parseGlobalJson(content);
    default:
      return [];
  }
}

/** Parse every file a repo supplied (`{ fileName: text }`), in `PIN_FILES` order. */
export function parsePins(files: Readonly<Record<string, string>>): Pin[] {
  const out: Pin[] = [];
  for (const name of PIN_FILES) {
    const text = files[name];
    if (typeof text === "string") out.push(...parsePinFile(name, text));
  }
  return out;
}
