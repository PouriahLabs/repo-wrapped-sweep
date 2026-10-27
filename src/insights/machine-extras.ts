// CLI 0.3 collectors: device basics, security posture, AI tooling and local coding rhythm.
//
// Same contract as the other insight collectors (run.ts): read-only, LOCAL ONLY (nothing
// here touches the network), argv-only commands with a deadline, and a failure is
// "unknown" — never an exception and never a stopped run. Every parser lives in the shared
// pure module (src/lib/endpoint/insights/machine-extras.ts, activity.ts) and returns a
// CLASSIFICATION: no key, token, path, email or name leaves this file except the
// well-known tool / extension ids it lists.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { foldActivity, type CommitTime } from "@/lib/endpoint/insights/activity";
import {
  AI_CLI_BINS,
  aiExtensionId,
  classifyCredentialHelper,
  claudeCodeAutonomy,
  codexAutonomy,
  countMcpServers,
  maxAutonomy,
  parseSshPrivateKey,
  parseSshPublicKey,
  summarizeSshKeys,
  type SshKeyInfo,
} from "@/lib/endpoint/insights/machine-extras";
import {
  MAX_AI_TOOL_ITEMS,
  type AgentAutonomy,
  type AiClient,
  type AiToolsInsights,
  type McpClientSummary,
  type OnOff,
  type PostureInsights,
} from "@/lib/endpoint/insights/wire";
import type { SweepEnv } from "../env";
import { GIT_COMMAND_TIMEOUT_MS, GIT_POOL, git } from "./git";
import { findOnPath, mapPool, runCommand, type RunResult } from "./run";

/** Deadline for one OS query (PowerShell can take a few seconds to start). */
const OS_QUERY_TIMEOUT_MS = 15_000;
/** Config files bigger than this are not parsed (Claude's ~/.claude.json can grow large). */
const MAX_CONFIG_BYTES = 25 * 1024 * 1024;
/** SSH files bigger than this are not keys. */
const MAX_KEY_BYTES = 64 * 1024;
/** Repos whose log is read for the coding-rhythm section. */
const MAX_ACTIVITY_REPOS = 400;

const DAY_MS = 86_400_000;

const stdout = (r: RunResult): string | null => (r.ok && r.code === 0 ? r.stdout : null);

function readText(file: string, max = MAX_CONFIG_BYTES): string | null {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > max) return null;
    return fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

/** JSON, or JSON-with-comments (VS Code settings) — null when it doesn't parse. */
function readJson(file: string): unknown {
  const text = readText(file);
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch {
    try {
      // Strip // and /* */ comments outside strings, then trailing commas.
      const stripped = text
        .replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (_m, s: string) => s ?? "")
        .replace(/,(\s*[}\]])/g, "$1");
      return JSON.parse(stripped);
    } catch {
      return null;
    }
  }
}

const pathVar = (vars: NodeJS.ProcessEnv): string =>
  vars.PATH ??
  vars.Path ??
  Object.entries(vars).find(([k]) => k.toUpperCase() === "PATH")?.[1] ??
  "";

function onPath(env: SweepEnv, name: string): string | null {
  const vars = env.processEnv ?? process.env;
  return findOnPath(name, { path: pathVar(vars), pathext: vars.PATHEXT, platform: env.platform });
}

/** Run a constant PowerShell snippet (Windows). Never user input. */
async function powershell(env: SweepEnv, script: string): Promise<string | null> {
  const exe = onPath(env, "powershell") ?? onPath(env, "pwsh");
  if (!exe) return null;
  const r = await runCommand(exe, ["-NoProfile", "-NonInteractive", "-Command", script], {
    timeoutMs: OS_QUERY_TIMEOUT_MS,
    cwd: os.tmpdir(),
  });
  return stdout(r);
}

/** Run an OS tool resolved through the sweep's own PATH lookup (so tests' stub PATH wins);
 *  an absolute path is used as is. Missing tool → "unavailable", no spawn. */
async function cmd(
  env: SweepEnv,
  bin: string,
  args: string[],
  timeoutMs = OS_QUERY_TIMEOUT_MS,
): Promise<RunResult> {
  const abs = path.isAbsolute(bin) ? bin : onPath(env, bin);
  if (!abs) return { ok: false, failure: "unavailable" };
  return runCommand(abs, args, { timeoutMs, cwd: os.tmpdir() });
}

/** Per-OS app-config folder (`~/Library/Application Support`, `%APPDATA%`, `~/.config`). */
function appConfigDir(env: SweepEnv): string {
  if (env.platform === "darwin") return path.join(env.home, "Library", "Application Support");
  if (env.platform === "win32") return env.appData ?? path.join(env.home, "AppData", "Roaming");
  return path.join(env.home, ".config");
}

// ---------------------------------------------------------------------------
// Device basics
// ---------------------------------------------------------------------------

export interface MachineExtras {
  osName?: string;
  cpuModel?: string;
  uptimeHours?: number;
  shell?: string;
}

/** `Windows 10 Pro` + build ≥ 22000 is Windows 11 (the registry never renamed it). PURE. */
export function windowsName(
  productName: string,
  displayVersion: string | null,
  release: string,
): string {
  const build = Number(release.split(".")[2] ?? 0);
  const name = build >= 22000 ? productName.replace(/^Windows 10/, "Windows 11") : productName;
  return displayVersion ? `${name} ${displayVersion}` : name;
}

/** `/etc/os-release` text → PRETTY_NAME. PURE. */
export function linuxPrettyName(osRelease: string): string | null {
  const m = /^PRETTY_NAME=(?:"([^"]*)"|(.*))$/m.exec(osRelease);
  return (m?.[1] ?? m?.[2] ?? "").trim() || null;
}

async function osName(env: SweepEnv): Promise<string | undefined> {
  if (env.platform === "darwin") {
    const v = stdout(await cmd(env, "sw_vers", ["-productVersion"]))?.trim();
    return v ? `macOS ${v}` : undefined;
  }
  if (env.platform === "win32") {
    const key = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    const read = async (value: string) => {
      const out = stdout(await cmd(env, "reg", ["query", key, "/v", value]));
      return out ? (new RegExp(`${value}\\s+REG_SZ\\s+(.+)`).exec(out)?.[1]?.trim() ?? null) : null;
    };
    const [product, display] = await Promise.all([read("ProductName"), read("DisplayVersion")]);
    return product ? windowsName(product, display, os.release()) : undefined;
  }
  const text = readText("/etc/os-release", 64 * 1024);
  return (text && linuxPrettyName(text)) || undefined;
}

export async function collectMachineExtras(env: SweepEnv): Promise<MachineExtras> {
  const vars = env.processEnv ?? process.env;
  // SHELL is unset in a plain Windows console; Git Bash / WSL set it.
  const shellPath = vars.SHELL;
  const shell = shellPath
    ? path
        .basename(shellPath)
        .replace(/\.exe$/i, "")
        .slice(0, 16)
    : undefined;
  const cpu = os.cpus()[0]?.model?.replace(/\s+/g, " ").trim();
  const name = await osName(env).catch(() => undefined);
  return {
    ...(name ? { osName: name.slice(0, 64) } : {}),
    ...(cpu ? { cpuModel: cpu.slice(0, 64) } : {}),
    uptimeHours: Math.round((os.uptime() / 3600) * 10) / 10,
    ...(shell ? { shell } : {}),
  };
}

// ---------------------------------------------------------------------------
// Security posture
// ---------------------------------------------------------------------------

/** BitLocker shell property → on/off. 1/3/6 are protected or getting there. PURE. */
export function bitlockerState(value: string | null): OnOff {
  const n = Number((value ?? "").trim());
  if ([1, 3, 6].includes(n)) return "on";
  if ([2, 4, 5].includes(n)) return "off";
  return "unknown";
}

/** `netsh advfirewall show allprofiles state` → on only if every profile is ON. PURE. */
export function netshFirewall(output: string | null): OnOff {
  if (!output) return "unknown";
  const states = [...output.matchAll(/^State\s+(ON|OFF)\s*$/gim)].map((m) => m[1]!.toUpperCase());
  if (states.length === 0) return "unknown";
  return states.every((s) => s === "ON") ? "on" : "off";
}

async function diskEncryption(env: SweepEnv): Promise<OnOff> {
  if (env.platform === "darwin") {
    const out = stdout(await cmd(env, "fdesetup", ["status"]));
    if (!out) return "unknown";
    return /FileVault is On/i.test(out) ? "on" : /FileVault is Off/i.test(out) ? "off" : "unknown";
  }
  if (env.platform === "win32") {
    const drive = ((env.processEnv ?? process.env).SystemDrive ?? "C:").replace(/[^A-Za-z:]/g, "");
    return bitlockerState(
      await powershell(
        env,
        `(New-Object -ComObject Shell.Application).NameSpace('${drive}').Self.ExtendedProperty('System.Volume.BitLockerProtection')`,
      ),
    );
  }
  const out = stdout(await cmd(env, "lsblk", ["-nro", "TYPE"]));
  if (!out) return "unknown";
  return /^crypt$/m.test(out) ? "on" : "off";
}

async function firewall(env: SweepEnv): Promise<OnOff> {
  if (env.platform === "darwin") {
    const out = stdout(
      await cmd(env, "/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]),
    );
    if (!out) return "unknown";
    return /enabled/i.test(out) ? "on" : /disabled/i.test(out) ? "off" : "unknown";
  }
  if (env.platform === "win32") {
    return netshFirewall(
      stdout(await cmd(env, "netsh", ["advfirewall", "show", "allprofiles", "state"])),
    );
  }
  return "unknown"; // ufw / nft need root to read
}

/** Newest install date (ms) among macOS install-history entries from Software Update. PURE. */
export function macLastUpdateMs(historyJson: string | null): number | null {
  if (!historyJson) return null;
  try {
    const items = JSON.parse(historyJson) as Array<{ date?: string; processName?: string }>;
    let best: number | null = null;
    for (const it of items) {
      if (!it.date || !/softwareupdate|macOS Installer/i.test(it.processName ?? "")) continue;
      const t = Date.parse(it.date);
      if (!Number.isNaN(t)) best = best === null ? t : Math.max(best, t);
    }
    return best;
  } catch {
    return null;
  }
}

async function osUpdateAgeDays(env: SweepEnv, now: number): Promise<number | null> {
  let last: number | null = null;
  if (env.platform === "darwin") {
    last = macLastUpdateMs(
      stdout(
        await cmd(env, "plutil", [
          "-convert",
          "json",
          "-o",
          "-",
          "/Library/Receipts/InstallHistory.plist",
        ]),
      ),
    );
  } else if (env.platform === "win32") {
    const out = await powershell(
      env,
      "(Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn.ToString('o')",
    );
    const t = out ? Date.parse(out.trim()) : NaN;
    last = Number.isNaN(t) ? null : t;
  } else {
    for (const f of ["/var/log/apt/history.log", "/var/log/dnf.log", "/var/log/pacman.log"]) {
      try {
        last = fs.statSync(f).mtimeMs;
        break;
      } catch {
        // not this distro
      }
    }
  }
  return last === null ? null : Math.max(0, Math.floor((now - last) / DAY_MS));
}

/** `git config` outside any repo: `--global` only, or every user-level scope (system +
 *  global — Git for Windows sets `credential.helper=manager` at the SYSTEM level). */
async function gitGlobal(
  env: SweepEnv,
  args: string[],
  scope: "global" | "all" = "global",
): Promise<string[] | null> {
  const r = await git(
    env,
    env.home,
    ["config", ...(scope === "global" ? ["--global"] : []), ...args],
    GIT_COMMAND_TIMEOUT_MS,
  );
  if (!r.ok) return null;
  // Exit 1 = key not set (git present).
  if (r.code === 1) return [];
  return r.code === 0 ? r.stdout.split("\n").filter((l) => l.trim().length > 0) : null;
}

function sshKeys(env: SweepEnv, now: number): Array<SshKeyInfo & { ageDays: number }> {
  const dir = path.join(env.home, ".ssh");
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const skip = /\.pub$|^known_hosts|^authorized_keys|^config$|\.bak$|\.old$/i;
  const out: Array<SshKeyInfo & { ageDays: number }> = [];
  for (const name of names) {
    if (skip.test(name)) continue;
    const file = path.join(dir, name);
    const text = readText(file, MAX_KEY_BYTES);
    if (text === null) continue;
    const info = parseSshPrivateKey(text);
    if (!info) continue;
    if (info.bits === null && (info.type === "rsa" || info.type === "other")) {
      const pub = readText(`${file}.pub`, MAX_KEY_BYTES);
      const p = pub ? parseSshPublicKey(pub) : null;
      if (p) Object.assign(info, info.type === "other" ? p : { bits: p.bits });
    }
    let ageDays = 0;
    try {
      ageDays = Math.max(0, Math.floor((now - fs.statSync(file).mtimeMs) / DAY_MS));
    } catch {
      // keep 0
    }
    out.push({ ...info, ageDays });
  }
  return out;
}

export async function collectPosture(env: SweepEnv, now = Date.now()): Promise<PostureInsights> {
  const [enc, fw, updateAge, helpers, signing] = await Promise.all([
    diskEncryption(env).catch((): OnOff => "unknown"),
    firewall(env).catch((): OnOff => "unknown"),
    osUpdateAgeDays(env, now).catch(() => null),
    gitGlobal(env, ["--get-all", "credential.helper"], "all"),
    gitGlobal(env, ["--get", "commit.gpgsign"]),
  ]);
  return {
    diskEncryption: enc,
    firewall: fw,
    osUpdateAgeDays: updateAge,
    gitCredentialHelper: helpers === null ? null : classifyCredentialHelper(helpers),
    commitSigning: signing === null ? null : signing.some((v) => v.trim() === "true"),
    sshKeys: summarizeSshKeys(sshKeys(env, now)),
  };
}

// ---------------------------------------------------------------------------
// AI tooling
// ---------------------------------------------------------------------------

function mcpConfigs(env: SweepEnv): Array<{ client: AiClient; files: string[] }> {
  const app = appConfigDir(env);
  return [
    { client: "claude-code", files: [path.join(env.home, ".claude.json")] },
    { client: "claude-desktop", files: [path.join(app, "Claude", "claude_desktop_config.json")] },
    { client: "cursor", files: [path.join(env.home, ".cursor", "mcp.json")] },
    {
      client: "vscode",
      files: [
        path.join(app, "Code", "User", "mcp.json"),
        path.join(app, "Code", "User", "settings.json"),
      ],
    },
  ];
}

/** `[mcp_servers.<name>]` tables in a Codex `config.toml`. PURE. */
export function codexMcpCount(toml: string): number {
  return new Set([...toml.matchAll(/^\s*\[mcp_servers\.([^\]\s.]+)\]/gm)].map((m) => m[1])).size;
}

export async function collectAiTools(env: SweepEnv): Promise<AiToolsInsights> {
  const clis = AI_CLI_BINS.filter((b) => onPath(env, b) !== null);

  const extensions = new Set<string>();
  const editorDirs: Array<[string, string]> = [
    ["vscode", path.join(env.home, ".vscode", "extensions")],
    ["vscode-insiders", path.join(env.home, ".vscode-insiders", "extensions")],
    ["cursor", path.join(env.home, ".cursor", "extensions")],
    ["windsurf", path.join(env.home, ".windsurf", "extensions")],
  ];
  for (const [editor, dir] of editorDirs) {
    let entries: string[];
    try {
      entries = fs.readdirSync(dir);
    } catch {
      continue;
    }
    for (const e of entries) {
      const id = aiExtensionId(e);
      if (id) extensions.add(`${editor}:${id}`);
    }
  }

  const mcp: McpClientSummary[] = [];
  for (const { client, files } of mcpConfigs(env)) {
    let servers = 0;
    let inlineSecrets = 0;
    for (const f of files) {
      const c = countMcpServers(readJson(f));
      servers += c.servers;
      inlineSecrets += c.inlineSecrets;
    }
    if (servers > 0) mcp.push({ client, servers, inlineSecrets });
  }
  const codexToml = readText(path.join(env.home, ".codex", "config.toml"), 1024 * 1024);
  if (codexToml) {
    const n = codexMcpCount(codexToml);
    if (n > 0) mcp.push({ client: "codex", servers: n, inlineSecrets: 0 });
  }

  const autonomy: Array<{ client: AiClient; level: AgentAutonomy }> = [];
  const claudeDir = path.join(env.home, ".claude");
  if (fs.existsSync(claudeDir)) {
    const level = maxAutonomy(
      claudeCodeAutonomy(readJson(path.join(claudeDir, "settings.json"))),
      claudeCodeAutonomy(readJson(path.join(claudeDir, "settings.local.json"))),
    );
    autonomy.push({ client: "claude-code", level });
  }
  if (codexToml !== null) autonomy.push({ client: "codex", level: codexAutonomy(codexToml) });

  return {
    clis: [...clis].slice(0, MAX_AI_TOOL_ITEMS),
    extensions: [...extensions].sort().slice(0, MAX_AI_TOOL_ITEMS),
    mcp,
    autonomy,
  };
}

// ---------------------------------------------------------------------------
// Local coding rhythm
// ---------------------------------------------------------------------------

/** Escape a string for git's (basic) regex `--author` match. PURE. */
export function gitRegexEscape(s: string): string {
  return s.replace(/[.*[\]^$\\]/g, (c) => `\\${c}`);
}

function localParts(ts: number): { hour: number; weekday: number; day: string } {
  const d = new Date(ts * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return {
    hour: d.getHours(),
    weekday: d.getDay(),
    day: `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`,
  };
}

export interface ActivityCollection {
  fold: ReturnType<typeof foldActivity>;
}

/**
 * Commit times in the last year for the GLOBAL git identity across `repos`. The email is used
 * only as a local `git log --author` filter — it is never returned. null = no identity set.
 */
export async function collectActivity(
  env: SweepEnv,
  repos: readonly string[],
  now = Date.now(),
): Promise<ActivityCollection | null> {
  const email = (await gitGlobal(env, ["--get", "user.email"]))?.[0]?.trim();
  if (!email) return null;
  const author = gitRegexEscape(email);
  const lists = await mapPool(repos.slice(0, MAX_ACTIVITY_REPOS), GIT_POOL, async (repo) => {
    const r = await git(
      env,
      repo,
      ["log", "--all", "--no-merges", "--since=365.days", `--author=${author}`, "--format=%at"],
      GIT_COMMAND_TIMEOUT_MS,
    );
    const out = stdout(r);
    if (!out) return [] as CommitTime[];
    return out
      .split("\n")
      .map((l) => Number(l.trim()))
      .filter((n) => Number.isFinite(n) && n > 0)
      .map((ts) => ({ repo, ts }));
  });
  return { fold: foldActivity(lists.flat(), Math.floor(now / 1000), localParts) };
}
