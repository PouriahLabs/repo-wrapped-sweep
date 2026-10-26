import os from "node:os";
import path from "node:path";

/**
 * Everything the walker/classifier needs to know about the machine, injected so
 * tests (and the hook) can run against a fake home on any host OS.
 */
export interface SweepEnv {
  platform: NodeJS.Platform;
  /** Absolute home directory. */
  home: string;
  /** `%APPDATA%` (Windows) — Roaming profile. */
  appData?: string;
  /** `%LOCALAPPDATA%` (Windows). */
  localAppData?: string;
  /** Cloud-sync roots from the environment (`%OneDrive%` …). */
  cloudRoots: string[];
  /** Where the CLI keeps its salt, baseline, device and config files. */
  configDir: string;
  /** Machine-wide MDM config (§ A3.1): `/Library/Application Support/RepoWrapped/sweep.json`
   *  on macOS, `%ProgramData%\RepoWrapped\sweep.json` on Windows. Undefined elsewhere. */
  mdmConfigPath?: string;
  /** The `git` the agent guard spawns to ask whether a file is gitignored. Both
   *  default to `git` and 30 ms; tests override them. */
  git?: { bin?: string; timeoutMs?: number };
  /** Does `abs` name an existing file? Defaults to a real stat; tests that simulate
   *  another platform's paths override it. */
  fileExists?: (abs: string) => boolean;
}

export function currentEnv(processEnv: NodeJS.ProcessEnv = process.env): SweepEnv {
  const home = os.homedir();
  const cloud = [processEnv.OneDrive, processEnv.OneDriveCommercial, processEnv.OneDriveConsumer]
    .filter((v): v is string => !!v)
    .map((v) => path.resolve(v));
  return {
    platform: process.platform,
    home,
    appData: processEnv.APPDATA,
    localAppData: processEnv.LOCALAPPDATA,
    cloudRoots: [...new Set(cloud)],
    mdmConfigPath: processEnv.REPO_WRAPPED_MDM_CONFIG
      ? path.resolve(processEnv.REPO_WRAPPED_MDM_CONFIG)
      : process.platform === "darwin"
        ? "/Library/Application Support/RepoWrapped/sweep.json"
        : process.platform === "win32"
          ? path.join(processEnv.ProgramData ?? "C:\\ProgramData", "RepoWrapped", "sweep.json")
          : undefined,
    configDir: processEnv.REPO_WRAPPED_HOME
      ? path.resolve(processEnv.REPO_WRAPPED_HOME)
      : path.join(home, ".repo-wrapped"),
  };
}

/** Windows/macOS file systems are case-insensitive by default; compare folded. */
export function foldsCase(platform: NodeJS.Platform): boolean {
  return platform === "win32" || platform === "darwin";
}

/** Forward-slash, no trailing slash; case-folded on case-insensitive platforms.
 *  For COMPARISON only — never for display or I/O. */
export function normPath(p: string, platform: NodeJS.Platform): string {
  let n = p.replace(/\\/g, "/");
  if (n.length > 1 && n.endsWith("/")) n = n.slice(0, -1);
  return foldsCase(platform) ? n.toLowerCase() : n;
}

/** True when `child` is `parent` or lives under it. */
export function isUnder(child: string, parent: string, platform: NodeJS.Platform): boolean {
  const c = normPath(child, platform);
  const p = normPath(parent, platform);
  return c === p || c.startsWith(`${p}/`);
}

/** Home-relative display path (`~/Documents/x`) — never leaks the username. */
export function displayPath(abs: string, env: Pick<SweepEnv, "home" | "platform">): string {
  if (isUnder(abs, env.home, env.platform)) {
    const rest = abs
      .replace(/\\/g, "/")
      .slice(env.home.replace(/\\/g, "/").replace(/\/$/, "").length);
    return `~${rest}`;
  }
  return abs.replace(/\\/g, "/");
}

/** Inverse of `displayPath` for paths the CLI itself wrote (`~/…` → absolute). */
export function expandPath(p: string, env: Pick<SweepEnv, "home">): string {
  if (p === "~") return env.home;
  if (p.startsWith("~/") || p.startsWith("~\\")) return path.join(env.home, p.slice(2));
  return p;
}
