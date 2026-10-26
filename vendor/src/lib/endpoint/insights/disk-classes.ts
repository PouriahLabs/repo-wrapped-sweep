// Regenerable-folder classes for Machine Insights disk reclaim (ENDPOINT-MACHINE-INSIGHTS
// § C2.2) — PURE data and predicates: no fs, no clock (`isStale` takes `now`).
//
// A folder is only ever called reclaimable when a SIBLING file proves it can be rebuilt
// (`node_modules` next to a lockfile, `target` next to `Cargo.toml`, …). The collector
// lists a directory's entries and asks `classifyDir`; nothing here touches the disk, and
// nothing here deletes — `disk clean` (Phase C3) decides what to act on.
//
// `dist/` and `out/` are NEVER classified: they are too often hand-built or committed, so
// they are reported by size only (`isReportOnlyDir`).

const DAY_MS = 86_400_000;

export const DISK_CLASSES = [
  "node-modules",
  "next-build",
  "rust-target",
  "python-cache",
  "gradle-build",
  "package-cache",
  "docker",
] as const;
export type DiskClass = (typeof DISK_CLASSES)[number];

/** How a class may be reclaimed. `never` = reported only. */
export type CleanMode = "remove" | "tool" | "never";

export interface DiskClassSpec {
  id: DiskClass;
  label: string;
  /** Folder names. A `/` means a nested path under the project folder (`.vercel/output`). */
  dirs: readonly string[];
  /** Sibling files, ANY of which proves the folder is regenerable; `*` is a wildcard. Empty = no proof applies. */
  proof: readonly string[];
  clean: CleanMode;
}

export const DISK_CLASS_TABLE: readonly DiskClassSpec[] = [
  {
    id: "node-modules",
    label: "node_modules",
    dirs: ["node_modules"],
    proof: ["pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lock*"],
    clean: "remove",
  },
  {
    id: "next-build",
    label: "Framework build output",
    dirs: [".next", ".turbo", ".nuxt", ".svelte-kit", ".vercel/output"],
    proof: ["package.json"],
    clean: "remove",
  },
  {
    id: "rust-target",
    label: "Rust target",
    dirs: ["target"],
    proof: ["Cargo.toml"],
    clean: "remove",
  },
  {
    id: "python-cache",
    label: "Python caches",
    // `.venv` is classified (so it is reported) but only removed with --include-venv.
    dirs: ["__pycache__", ".pytest_cache", ".mypy_cache", ".venv"],
    proof: ["pyproject.toml", "requirements*.txt"],
    clean: "remove",
  },
  {
    id: "gradle-build",
    label: "Gradle build",
    dirs: ["build", ".gradle"],
    proof: ["build.gradle*", "settings.gradle*"],
    clean: "remove",
  },
  {
    id: "package-cache",
    label: "Package-manager caches",
    dirs: [],
    proof: [],
    clean: "tool",
  },
  {
    id: "docker",
    label: "Docker",
    dirs: [],
    proof: [],
    clean: "never",
  },
];

/** Folders that are reported by size but never classified or cleaned. */
export const REPORT_ONLY_DIRS: readonly string[] = ["dist", "out"];

export const isReportOnlyDir = (name: string): boolean => REPORT_ONLY_DIRS.includes(name);

/** The one class member that needs an extra opt-in to clean (`--include-venv`). */
export const isVenvDir = (name: string): boolean => name === ".venv";

/**
 * Global package-manager caches (`package-cache`). They are cleaned through the tool's own
 * prune command — never `rm` — so `prune` is the argv to run, or null when the tool has no
 * such command (reported only). `homeRelative` lists the default locations, `/`-separated,
 * relative to the home directory, for the collector to size.
 */
export interface PackageCacheSpec {
  tool: "pnpm" | "npm" | "yarn" | "gradle" | "pip";
  label: string;
  prune: readonly string[] | null;
  homeRelative: readonly string[];
}

export const PACKAGE_CACHES: readonly PackageCacheSpec[] = [
  {
    tool: "pnpm",
    label: "pnpm store",
    prune: ["pnpm", "store", "prune"],
    homeRelative: [".local/share/pnpm/store", "AppData/Local/pnpm/store", "Library/pnpm/store"],
  },
  {
    tool: "npm",
    label: "npm cache",
    prune: ["npm", "cache", "clean", "--force"],
    homeRelative: [".npm/_cacache", "AppData/Local/npm-cache/_cacache"],
  },
  {
    tool: "yarn",
    label: "Yarn cache",
    prune: ["yarn", "cache", "clean"],
    homeRelative: [
      ".yarn/berry/cache",
      ".cache/yarn",
      "AppData/Local/Yarn/Cache",
      "Library/Caches/Yarn",
    ],
  },
  {
    tool: "gradle",
    label: "Gradle caches",
    prune: null,
    homeRelative: [".gradle/caches"],
  },
  {
    tool: "pip",
    label: "pip cache",
    prune: ["pip", "cache", "purge"],
    homeRelative: [".cache/pip", "AppData/Local/pip/Cache", "Library/Caches/pip"],
  },
];

// --- classification -------------------------------------------------------------------

/** Does `name` match `pattern`, where `*` stands for any run of characters? Exact otherwise. */
export function matchesSiblingPattern(pattern: string, name: string): boolean {
  if (!pattern.includes("*")) return pattern === name;
  const re = new RegExp(
    `^${pattern
      .split("*")
      .map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
      .join(".*")}$`,
  );
  return re.test(name);
}

/**
 * Which regenerable class does a directory belong to?
 *
 * `name` is the folder's name — or, for a nested class folder, its path under the project
 * folder (`.vercel/output`, `/`-separated). `siblings` are the entry names in the folder
 * that CONTAINS it (for `.vercel/output`, the folder that contains `.vercel`). Returns null
 * unless a proving sibling is present, so `build/` in a Node project, a `target/` with no
 * `Cargo.toml`, and — always — `dist/` and `out/` are not classified.
 */
export function classifyDir(name: string, siblings: Iterable<string>): DiskClass | null {
  if (isReportOnlyDir(name)) return null;
  const present = [...siblings];
  for (const spec of DISK_CLASS_TABLE) {
    if (!spec.dirs.includes(name)) continue;
    if (spec.proof.some((p) => present.some((s) => matchesSiblingPattern(p, s)))) return spec.id;
  }
  return null;
}

/**
 * Has the project not been touched for `days`? `lastTouched` is the newest source mtime or last
 * commit time (epoch ms or a Date). An unknown time is NOT stale — we only call a project
 * stale when we can prove it. Default window is 30 days.
 */
export function isStale(
  lastTouched: number | Date | null | undefined,
  now: number | Date,
  days = 30,
): boolean {
  if (lastTouched === null || lastTouched === undefined) return false;
  const t = typeof lastTouched === "number" ? lastTouched : lastTouched.getTime();
  const n = typeof now === "number" ? now : now.getTime();
  if (!Number.isFinite(t) || !Number.isFinite(n)) return false;
  return n - t >= days * DAY_MS;
}
