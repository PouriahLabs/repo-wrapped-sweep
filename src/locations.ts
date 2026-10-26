// Location classes, high-risk targets, cloud roots and excludes (§ A2.1).
// Pure over an injected `SweepEnv` — no I/O — so every OS table is testable on
// any host.

import type { LocationClass } from "@/lib/native-scan/path-rules";
import { isUnder, normPath, type SweepEnv } from "./env";

const join = (base: string, ...parts: string[]) =>
  [base.replace(/[\\/]+$/, ""), ...parts].join("/");

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// --- classification ---------------------------------------------------------

const EDITOR_HISTORY =
  /\/(?:code|code - insiders|vscodium|cursor|windsurf)\/user\/history(?:\/|$)/i;

/** Home-relative expected credential stores (§ A2.1 `credential-store`). */
const HOME_CREDENTIAL_FILES = new Set([
  ".aws/credentials",
  ".npmrc",
  ".docker/config.json",
  ".kube/config",
  ".netrc",
  ".git-credentials",
]);

const SHELL_HISTORY_NAMES = new Set([
  ".zsh_history",
  ".bash_history",
  "fish_history",
  "consolehost_history.txt",
  ".python_history",
  ".node_repl_history",
  ".psql_history",
  ".mysql_history",
]);

/**
 * Which § A2.1 class a file belongs to. Order matters: the specific stores win
 * over the catch-all `documents`. `credential-store` is reserved for the
 * HOME-LEVEL files (`~/.npmrc`) — a project's own `.npmrc` is a copy, not the
 * expected store.
 */
export function classifyLocation(abs: string, env: SweepEnv): LocationClass {
  const p = normPath(abs, env.platform);
  const home = normPath(env.home, env.platform);
  const base = p.slice(p.lastIndexOf("/") + 1);

  if (p === `${home}/.ssh` || p.startsWith(`${home}/.ssh/`)) return "ssh";
  if (EDITOR_HISTORY.test(p)) return "editor-history";
  if (p.startsWith(`${home}/.claude/`) && (base.endsWith(".jsonl") || p.includes("/projects/"))) {
    return "agent-transcript";
  }
  if (p === `${home}/.codex/sessions` || p.startsWith(`${home}/.codex/sessions/`)) {
    return "agent-transcript";
  }
  if (SHELL_HISTORY_NAMES.has(base.toLowerCase())) return "shell-history";
  if (p.startsWith(`${home}/`) && HOME_CREDENTIAL_FILES.has(p.slice(home.length + 1))) {
    return "credential-store";
  }
  // Downloads/Desktop are capitalised on Linux/macOS, so compare folded.
  const rel = p.startsWith(`${home}/`) ? p.slice(home.length + 1).toLowerCase() : "";
  if (/^(?:downloads|desktop)(?:\/|$)/.test(rel)) return "downloads-desktop";
  return "documents";
}

// --- high-risk targets (--quick) -------------------------------------------

/**
 * The always-scanned high-risk locations for the host OS (files or dirs; the
 * walker tolerates ones that don't exist). `--quick` scans exactly these.
 */
export function highRiskTargets(env: SweepEnv): string[] {
  const h = env.home;
  const out: string[] = [];
  const editors = ["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"];

  if (env.platform === "win32") {
    const roaming = env.appData ?? join(h, "AppData", "Roaming");
    for (const e of editors) out.push(join(roaming, e, "User", "History"));
    out.push(
      join(roaming, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
    );
  } else if (env.platform === "darwin") {
    for (const e of editors)
      out.push(join(h, "Library", "Application Support", e, "User", "History"));
  } else {
    for (const e of editors) out.push(join(h, ".config", e, "User", "History"));
  }

  out.push(
    join(h, ".claude", "projects"),
    join(h, ".claude", "history.jsonl"),
    join(h, ".codex", "sessions"),
    join(h, ".zsh_history"),
    join(h, ".bash_history"),
    join(h, ".local", "share", "fish", "fish_history"),
    join(h, ".python_history"),
    join(h, ".node_repl_history"),
    join(h, ".aws", "credentials"),
    join(h, ".npmrc"),
    join(h, ".docker", "config.json"),
    join(h, ".kube", "config"),
    join(h, ".netrc"),
    join(h, ".git-credentials"),
    join(h, ".ssh"),
    join(h, "Downloads"),
    join(h, "Desktop"),
  );
  return out;
}

// --- cloud-sync roots -------------------------------------------------------

/** Cloud roots known up front: the environment's OneDrive roots and, on macOS,
 *  the iCloud container. `~/OneDrive*` and `~/Library/CloudStorage/*` are
 *  recognised by shape in `isCloudRoot`. */
export function staticCloudRoots(env: SweepEnv): string[] {
  const roots = [...env.cloudRoots];
  if (env.platform === "darwin") roots.push(join(env.home, "Library", "Mobile Documents"));
  return roots;
}

/** Is this directory a cloud-sync root? (`name` is its basename.) */
export function isCloudRoot(abs: string, name: string, env: SweepEnv): boolean {
  const p = normPath(abs, env.platform);
  const home = normPath(env.home, env.platform);
  if (staticCloudRoots(env).some((r) => normPath(r, env.platform) === p)) return true;
  const parent = p.slice(0, p.lastIndexOf("/"));
  // `~/OneDrive`, `~/OneDrive - Contoso`, … sit directly under home.
  if (parent === home && /^onedrive(?:$| - )/.test(name.toLowerCase())) return true;
  // `~/Library/CloudStorage/<provider>` (Google Drive, Dropbox, OneDrive on macOS).
  return env.platform === "darwin" && parent === `${home}/library/cloudstorage`;
}

/** True when `abs` is inside (or is) a cloud-sync root — used for explicit roots. */
export function isInCloud(abs: string, env: SweepEnv): boolean {
  if (staticCloudRoots(env).some((r) => isUnder(abs, r, env.platform))) return true;
  const p = normPath(abs, env.platform);
  const home = normPath(env.home, env.platform);
  if (new RegExp(`^${escapeRe(home)}/onedrive(?: - [^/]*)?(?:/|$)`).test(p)) return true;
  return env.platform === "darwin" && p.startsWith(`${home}/library/cloudstorage/`);
}

// --- excludes ---------------------------------------------------------------

const EXCLUDED_DIR_NAMES = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  ".turbo",
  ".venv",
  "venv",
  "__pycache__",
  ".cache",
  ".pnpm-store",
]);

/** Path suffixes (lowercased, forward-slash) excluded wherever they occur: OS
 *  caches, package caches and browser profile stores. */
const EXCLUDED_SUFFIXES = [
  "library/caches",
  "appdata/local/temp",
  "appdata/local/npm-cache",
  "appdata/local/pnpm",
  "appdata/local/pip",
  ".npm/_cacache",
  ".gradle/caches",
  ".m2/repository",
  ".cargo/registry",
  "go/pkg/mod",
  // browser profiles
  "appdata/local/google/chrome/user data",
  "appdata/local/microsoft/edge/user data",
  "appdata/local/bravesoftware",
  "appdata/roaming/mozilla/firefox/profiles",
  "library/application support/google/chrome",
  "library/application support/firefox/profiles",
  "library/application support/microsoft edge",
  "library/application support/bravesoftware",
  "library/safari",
  ".config/google-chrome",
  ".config/chromium",
  ".config/microsoft-edge",
  ".config/bravesoftware",
  ".mozilla",
];

/** Built-in directory excludes. `norm` is the forward-slash path. */
export function isDefaultExcludedDir(name: string, norm: string): boolean {
  const n = name.toLowerCase();
  if (EXCLUDED_DIR_NAMES.has(n)) return true;
  if (n.endsWith(".app")) return true; // macOS application bundles
  const lower = norm.toLowerCase();
  return EXCLUDED_SUFFIXES.some((s) => lower === s || lower.endsWith(`/${s}`));
}

/** Compile a user glob (`*`, `**`, `?`) to a case-insensitive regex. A glob with
 *  no slash matches any entry name; otherwise it matches a path suffix. */
export function compileGlob(glob: string): RegExp {
  const g = glob.replace(/\\/g, "/");
  let re = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i]!;
    if (c === "*") {
      if (g[i + 1] === "*") {
        re += ".*";
        i++;
        if (g[i + 1] === "/") i++;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += escapeRe(c);
  }
  return new RegExp(`(?:^|/)${re}$`, "i");
}

// --- installed software (A10) -------------------------------------------------

/** Editor folders (lowercase) whose `User/History` is a first-class location. */
const EDITOR_DIRS = new Set(["code", "code - insiders", "vscodium", "cursor", "windsurf"]);

/** Home-relative directories (lowercase, forward-slash) that hold installed software or a package cache — every OS. */
const SOFTWARE_HOME_DIRS = new Set([
  "go/pkg/mod",
  ".cargo/registry",
  ".rustup",
  ".m2",
  ".gradle",
  ".nuget",
  ".npm/_cacache",
  ".vscode/extensions",
  ".cursor/extensions",
]);

/** Windows home-relative installed-software directories. */
const WIN32_HOME_DIRS = new Set([
  "appdata/local/programs",
  "appdata/local/microsoft",
  "appdata/local/google/cloud sdk",
  "appdata/roaming/gcloud/logs",
  "appdata/local/epic games",
  "scoop/apps",
  "scoop/buckets",
]);

const WIN32_HOME_PATTERNS: RegExp[] = [
  // Squirrel keeps every GitHub Desktop release in its own `app-<version>`.
  /^appdata\/local\/githubdesktop\/app-[^/]+$/,
  // A Chromium-family browser profile: Edge, Chrome, Brave, Vivaldi … ("User Data").
  /^appdata\/local\/.+\/user data$/,
];

const WIN32_ABSOLUTE = /^[a-z]:\/program files(?: \(x86\))?$/;

const DARWIN_ABSOLUTE = new Set([
  "/applications",
  "/opt/homebrew/cellar",
  "/opt/homebrew/caskroom",
  "/usr/local/cellar",
  "/usr/local/caskroom",
]);

/** `~/Library/Application Support` is app data — except the editors' `User/History`. */
function isMacAppSupportNoise(relSegments: readonly string[]): boolean {
  const [lib, support, app, user, history] = relSegments;
  if (lib !== "library" || support !== "application support") return false;
  if (app === undefined) return false; // Application Support itself: look inside
  if (!EDITOR_DIRS.has(app)) return true;
  if (user === undefined) return false; // the editor's own folder: look inside
  if (user !== "user") return true;
  if (history === undefined) return false; // …/User: look inside
  return history !== "history";
}

/**
 * Is this directory an installed-software tree — programs, extensions, package
 * caches, browser profiles — rather than something the person wrote? A sweep
 * through them reports hundreds of "secrets" that are test keys in a vendored
 * library. Matches the directory ITSELF (so it is never entered); an explicit
 * `--root` placed inside one is still walked. Editor-history and agent-transcript
 * locations are never matched. Pure over `env`.
 */
export function isInstalledSoftwareDir(abs: string, env: SweepEnv): boolean {
  const p = normPath(abs, env.platform).toLowerCase();
  const home = normPath(env.home, env.platform).toLowerCase();
  const segments = p.split("/");
  if (segments[segments.length - 1] === "site-packages") return true;

  if (env.platform === "darwin" && DARWIN_ABSOLUTE.has(p)) return true;
  if (env.platform === "win32" && WIN32_ABSOLUTE.test(p)) return true;

  if (!p.startsWith(`${home}/`)) return false;
  const rel = p.slice(home.length + 1);
  if (SOFTWARE_HOME_DIRS.has(rel)) return true;
  if (env.platform === "win32") {
    return WIN32_HOME_DIRS.has(rel) || WIN32_HOME_PATTERNS.some((re) => re.test(rel));
  }
  if (env.platform === "darwin") return isMacAppSupportNoise(rel.split("/"));
  return false;
}

// --- fixtures and vendored code (A10) --------------------------------------------

/** Directory names that mark test data and third-party code. A secret there is a sample. */
const FIXTURE_SEGMENTS = new Set([
  "test",
  "tests",
  "__tests__",
  "testdata",
  "test_data",
  "fixtures",
  "third_party",
  "vendor",
  "dummyserver",
  "examples",
]);

/** Does any DIRECTORY segment of `p` (the file name is not one) name a test/vendor tree? */
export function underFixtureDir(p: string): boolean {
  const segments = p.replace(/\\/g, "/").toLowerCase().split("/");
  for (let i = 0; i < segments.length - 1; i++) {
    if (FIXTURE_SEGMENTS.has(segments[i]!)) return true;
  }
  return false;
}

// --- where a keyword assignment is believable (A10) ------------------------------------

const CONFIG_EXTENSIONS = new Set([
  "json",
  "yaml",
  "yml",
  "toml",
  "ini",
  "properties",
  "conf",
  "config",
  "xml",
]);

const LOG_LIKE: ReadonlySet<LocationClass> = new Set([
  "shell-history",
  "agent-transcript",
  "editor-history",
]);

/**
 * Files in which `password = "…"` is a credential rather than source code: env files,
 * JSON/YAML/TOML/INI/properties/conf/XML configuration, `*rc` dotfiles (`.npmrc`), and the
 * three log-like classes. In a source file the same shape is a variable named `token`.
 */
export function isConfigLikeFile(abs: string, locationClass: LocationClass): boolean {
  if (LOG_LIKE.has(locationClass)) return true;
  const base = abs.replace(/\\/g, "/").split("/").pop()!.toLowerCase();
  if (base.startsWith(".env") || base.endsWith(".env")) return true;
  if (/^\.[\w.-]*rc$/.test(base)) return true;
  const dot = base.lastIndexOf(".");
  return dot > 0 && CONFIG_EXTENSIONS.has(base.slice(dot + 1));
}

/** Lockfiles and generated bundles — high-entropy noise, never hand-written secrets. */
export function isNoiseFile(name: string): boolean {
  const n = name.toLowerCase();
  return (
    n === "package-lock.json" ||
    n === "pnpm-lock.yaml" ||
    n === "yarn.lock" ||
    n === "bun.lockb" ||
    n === "cargo.lock" ||
    n === "poetry.lock" ||
    n.endsWith(".min.js") ||
    n.endsWith(".min.css") ||
    n.endsWith(".map")
  );
}
