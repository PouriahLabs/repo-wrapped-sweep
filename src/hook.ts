// Agent guard (§ A2.7): a Claude Code `PreToolUse` hook that refuses to let an
// agent read a credential file, so the secret never enters a transcript.
//
//   hook install [--scope user|project]   merge our entry into settings.json
//   hook uninstall                        remove only our entry
//   hook status                           show where it is installed
//   hook check                            the hook itself: JSON on stdin,
//                                         exit 2 + reason on stderr to deny
//
// `hook check` is on the critical path of every tool call, so it is cheap by
// construction: pure path rules over the call's arguments, one baseline JSON
// load, and at most a 4 KB header probe on a `.pem`/`.key` candidate (so a
// certificate is not blocked). It FAILS OPEN on any malformed input — a bug in
// the guard must never wedge the agent.

import fs from "node:fs";
import path from "node:path";
import {
  HEAD_PROBE_BYTES,
  confirmPathRule,
  isExampleEnvFile,
  matchPath,
  type LocationClass,
  type PathRuleId,
} from "@/lib/native-scan/path-rules";
import { defaultBaselinePath, loadBaseline } from "./baseline";
import { displayPath, expandPath, normPath, type SweepEnv } from "./env";
import {
  findFlagged,
  isDirectory,
  isFile,
  type FlaggedFile,
  type GitFailure,
  type SearchDeps,
} from "./hook-search";
import {
  detectShellSearches,
  grepToolRequest,
  tokenizeSegments,
  tokenizeShell,
  type SearchRequest,
} from "./hook-shell";
import { classifyLocation, compileGlob } from "./locations";
import { loadConfig } from "./state";

// Every tool that can put the contents of a file in front of the model: Read/Edit
// variants by path, Grep by directory, and the shells (Bash, and PowerShell on
// Windows) by argument.
export const HOOK_MATCHER = "Read|Bash|PowerShell|Grep|Edit|MultiEdit|NotebookEdit";
export const HOOK_COMMAND = "repo-wrapped-sweep hook check";

export type HookScope = "user" | "project";

// ---------------------------------------------------------------------------
// settings.json merge
// ---------------------------------------------------------------------------

interface HookCommand {
  type?: string;
  command?: string;
  [k: string]: unknown;
}
interface HookEntry {
  matcher?: string;
  hooks?: HookCommand[];
  [k: string]: unknown;
}
interface Settings {
  hooks?: { PreToolUse?: HookEntry[]; [event: string]: unknown };
  [k: string]: unknown;
}

export function settingsPath(scope: HookScope, env: Pick<SweepEnv, "home">, cwd: string): string {
  return scope === "user"
    ? path.join(env.home, ".claude", "settings.json")
    : path.join(cwd, ".claude", "settings.json");
}

/** A hook command is ours when it invokes `… hook check` of a sweep binary. */
export function isOurCommand(command: unknown): boolean {
  return typeof command === "string" && /sweep/i.test(command) && /\bhook\s+check\b/.test(command);
}

function readSettings(file: string): Settings {
  let raw: string;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw err;
  }
  if (raw.trim() === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Never overwrite a file we can't parse — it is the user's.
    throw new Error(`${file} is not valid JSON; fix it (or remove the file) and re-run`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${file} must contain a JSON object`);
  }
  return parsed as Settings;
}

function writeSettings(file: string, settings: Settings): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(settings, null, 2)}\n`);
  fs.renameSync(tmp, file);
}

/**
 * Merge our `PreToolUse` entry into a settings file — never overwriting other
 * hooks or keys. Idempotent: installing twice leaves exactly one entry.
 */
export function installHook(
  file: string,
  command: string = HOOK_COMMAND,
): { changed: boolean; file: string } {
  const settings = readSettings(file);
  const hooks = (settings.hooks ??= {});
  if (!Array.isArray(hooks.PreToolUse)) hooks.PreToolUse = [];
  const entries = hooks.PreToolUse;

  let found: { entry: HookEntry; cmd: HookCommand } | null = null;
  for (const entry of entries) {
    for (const cmd of entry.hooks ?? []) {
      if (isOurCommand(cmd.command)) found = found ?? { entry, cmd };
    }
  }

  if (found) {
    const upToDate = found.entry.matcher === HOOK_MATCHER && found.cmd.command === command;
    if (upToDate) return { changed: false, file };
    found.entry.matcher = HOOK_MATCHER;
    found.cmd.command = command;
    found.cmd.type = "command";
  } else {
    entries.push({ matcher: HOOK_MATCHER, hooks: [{ type: "command", command }] });
  }
  writeSettings(file, settings);
  return { changed: true, file };
}

/** Remove only our entry; leaves every other hook and setting untouched. */
export function uninstallHook(file: string): { removed: number; file: string } {
  if (!fs.existsSync(file)) return { removed: 0, file };
  const settings = readSettings(file);
  const entries = settings.hooks?.PreToolUse;
  if (!Array.isArray(entries)) return { removed: 0, file };

  let removed = 0;
  const kept: HookEntry[] = [];
  for (const entry of entries) {
    const before = entry.hooks ?? [];
    const after = before.filter((h) => !isOurCommand(h.command));
    removed += before.length - after.length;
    if (after.length === before.length) {
      kept.push(entry);
    } else if (after.length > 0) {
      kept.push({ ...entry, hooks: after });
    }
  }
  if (removed === 0) return { removed: 0, file };

  const hooks = settings.hooks!;
  if (kept.length > 0) hooks.PreToolUse = kept;
  else delete hooks.PreToolUse;
  if (Object.keys(hooks).length === 0) delete settings.hooks;
  writeSettings(file, settings);
  return { removed, file };
}

export function hookInstalled(file: string): boolean {
  try {
    const entries = readSettings(file).hooks?.PreToolUse;
    return (
      Array.isArray(entries) &&
      entries.some((e) => (e.hooks ?? []).some((h) => isOurCommand(h.command)))
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Candidate extraction
// ---------------------------------------------------------------------------

export { tokenizeShell };

export interface HookInput {
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  cwd?: string;
}

const PATH_FIELDS = ["file_path", "path", "notebook_path"] as const;

/** `--file=.env`, `-Path:.env` (PowerShell): the value follows the first separator. */
const PARAM_VALUE = /^-{1,2}[A-Za-z][\w-]*[:=]([\s\S]+)$/;
/** cmd switches: `/f:.env`, `/d:C:\x`. */
const SWITCH_VALUE = /^\/[A-Za-z][:=]([\s\S]+)$/;

function pushToken(out: string[], tok: string): void {
  // A comma list (`Get-Content .env,.env.local`) is several paths.
  const add = (v: string) => {
    out.push(v);
    if (v.includes(",")) for (const part of v.split(",")) if (part) out.push(part);
  };
  if (tok.startsWith("-")) {
    const eq = tok.indexOf("=");
    if (eq >= 0 && eq < tok.length - 1) add(tok.slice(eq + 1));
    else {
      const m = PARAM_VALUE.exec(tok);
      if (m) add(m[1]!);
    }
    return;
  }
  add(tok);
  const sw = SWITCH_VALUE.exec(tok);
  if (sw) add(sw[1]!);
  // `FOO=.env` style assignments / `of=file`.
  const eq = tok.indexOf("=");
  if (eq > 0 && eq < tok.length - 1) add(tok.slice(eq + 1));
}

/** Raw path-like strings from a tool call's arguments. */
export function extractCandidates(input: HookInput): string[] {
  const ti = input.tool_input;
  if (!ti || typeof ti !== "object") return [];
  const out: string[] = [];
  for (const f of PATH_FIELDS) {
    const v = ti[f];
    if (typeof v === "string" && v) out.push(v);
  }
  const cmd = ti.command;
  if (typeof cmd === "string" && cmd) {
    for (const seg of tokenizeSegments(cmd)) {
      const skip = exclusionValueIndexes(seg.words);
      seg.words.forEach((tok, i) => {
        if (!skip.has(i)) pushToken(out, tok);
      });
    }
  }
  return out;
}

/**
 * Indexes of words that are the VALUE of an exclusion option (`--exclude=.env`,
 * `rg -g '!.env'`, `-Exclude .env`). They name files a search must NOT read — the
 * very remedy a directory-search denial suggests — so they are not paths to check.
 * Positive filters (`--include`, `-g '*.env'`) are still treated as paths.
 */
function exclusionValueIndexes(words: readonly string[]): Set<number> {
  const skip = new Set<number>();
  words.forEach((w, i) => {
    const lower = w.toLowerCase();
    if (/^--exclude(?:-dir)?=/.test(lower) || /^-exclude:/.test(lower)) skip.add(i);
    else if (lower === "--exclude" || lower === "--exclude-dir" || lower === "-exclude")
      skip.add(i + 1);
    else if (/^(?:-g|--glob|--iglob)$/.test(w) && words[i + 1]?.startsWith("!")) skip.add(i + 1);
    else if (/^(?:--glob=|--iglob=|-g)!/.test(w)) skip.add(i);
  });
  return skip;
}

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

function expandVars(
  token: string,
  env: Pick<SweepEnv, "home" | "appData" | "localAppData">,
): string {
  let t = token.replace(/^~(?=$|[\\/])/, () => env.home);
  t = t.replace(
    /\$\{?(?:HOME|USERPROFILE)\}?|%USERPROFILE%|\$env:(?:USERPROFILE|HOME)\b/gi,
    () => env.home,
  );
  if (env.appData) {
    t = t.replace(/%APPDATA%|\$env:APPDATA\b/gi, () => env.appData!);
  }
  if (env.localAppData) {
    t = t.replace(/%LOCALAPPDATA%|\$env:LOCALAPPDATA\b/gi, () => env.localAppData!);
  }
  return t;
}

/** The path module whose rules match the environment's OS (the host's, in real use). */
const pathFor = (env: Pick<SweepEnv, "platform">): path.PlatformPath =>
  env.platform === "win32" ? path.win32 : path.posix;

/** Git Bash / MSYS / WSL / Cygwin spell `C:\Users` as `/c/Users`, `/mnt/c/Users`, `/cygdrive/c/Users`. */
const MSYS_DRIVE = /^\/(?:mnt\/|cygdrive\/)?([A-Za-z])(?=\/|$)/;

function winNormalize(p: string, isToken: boolean): string {
  let t = p.replace(/^[\\/]{2}[?.][\\/]/, ""); // \\?\C:\x, \\.\C:\x
  t = t.replace(MSYS_DRIVE, (_m, d: string) => `${d.toUpperCase()}:`);
  if (!isToken) return t;
  // Alternate data streams: `.env::$DATA`, `.env:stream` open `.env`.
  const sep = Math.max(t.lastIndexOf("/"), t.lastIndexOf("\\"));
  const seg = t.slice(sep + 1);
  const colon = seg.indexOf(":");
  if (colon > 0 && !(sep < 0 && colon === 1)) t = t.slice(0, sep + 1) + seg.slice(0, colon);
  // Windows ignores trailing dots and spaces: `.env.` is `.env`.
  const stripped = t.replace(/[. ]+$/, "");
  const lastSeg = stripped.slice(
    Math.max(stripped.lastIndexOf("/"), stripped.lastIndexOf("\\")) + 1,
  );
  return lastSeg ? stripped : t;
}

/**
 * Every absolute path a shell token could mean: expanded (`~`, `$HOME`,
 * `%USERPROFILE%`), resolved against the call's cwd, with Windows quirks undone.
 * On POSIX a backslash is a path separator in a Windows-style token and an escape
 * in a bash one, so both readings are returned.
 */
export function resolveVariants(token: string, cwd: string, env: SweepEnv): string[] {
  const win = env.platform === "win32";
  const P = pathFor(env);
  let t = expandVars(token, env);
  let base = cwd;
  if (win) {
    t = winNormalize(t, true);
    base = winNormalize(cwd, false);
  }
  const out = new Set<string>([P.resolve(base, t)]);
  if (!win && t.includes("\\")) {
    out.add(P.resolve(base, t.replace(/\\/g, "/")));
    out.add(P.resolve(base, t.replace(/\\(.)/g, "$1")));
  }
  return [...out];
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

/** Path rules that make a file unreadable to an agent. */
const BLOCKING: ReadonlySet<PathRuleId> = new Set([
  "path.private-key",
  "path.pkcs12",
  "path.env-file",
  "path.cookie-jar",
  "path.service-account",
  "path.aws-long-lived",
]);

export interface HookContext {
  env: SweepEnv;
  /** Working directory of the tool call (relative paths resolve against it). */
  cwd: string;
  /** Normalized absolute paths a previous sweep found secrets in. */
  baseline: ReadonlySet<string>;
  /** The same locations, original case — for directory searches and messages. */
  baselineAbs?: readonly string[];
  /** `hookAllow[]` globs, compiled. */
  allow: RegExp[];
  /** `exclude[]` globs from sweep.json, compiled (directory searches skip them). */
  exclude?: RegExp[];
}

export interface HookDecision {
  deny: boolean;
  /** One-line reason (home-relative path, no secret material). */
  reason?: string;
}

/** Directory-relative expansion of a single trailing-segment wildcard (`.env*`). */
function expandWildcard(abs: string, P: path.PlatformPath): string[] {
  const dir = P.dirname(abs);
  const base = P.basename(abs);
  if (/[*?[]/.test(dir)) return [];
  try {
    const re = compileGlob(base);
    return fs
      .readdirSync(dir)
      .slice(0, 2000)
      .filter((name) => re.test(name))
      .map((name) => P.join(dir, name));
  } catch {
    return [];
  }
}

function probeHead(abs: string): string | null {
  let fd: number | undefined;
  try {
    fd = fs.openSync(abs, "r");
    const buf = Buffer.alloc(HEAD_PROBE_BYTES);
    const n = fs.readSync(fd, buf, 0, HEAD_PROBE_BYTES, 0);
    return buf.subarray(0, n).toString("utf8");
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
}

/** Credential files that are secrets by NAME (no content probe needed). */
function isCredentialFile(normalized: string, locationClass: LocationClass): boolean {
  if (locationClass === "credential-store") return true; // home-level ~/.npmrc, ~/.aws/credentials, …
  const base = normalized.slice(normalized.lastIndexOf("/") + 1);
  return (
    base === ".netrc" ||
    base === ".git-credentials" ||
    normalized.endsWith("/.aws/credentials") ||
    normalized.endsWith("/.kube/config")
  );
}

function blockReason(abs: string, ctx: HookContext): string | null {
  const { env } = ctx;
  const normalized = normPath(abs, env.platform);
  if (ctx.baseline.has(normalized)) return "a previous sweep found a plaintext secret in this file";
  if (isExampleEnvFile(abs)) return null;
  // A path that names no existing file leaks nothing. Without this, text that only
  // MENTIONS `.env.local` — a heredoc body, an inline script, a commit message —
  // was refused as a read.
  if (!(env.fileExists ?? isFile)(abs)) return null;

  const cls = classifyLocation(abs, env);
  if (isCredentialFile(normalized, cls)) return "credential file";

  const hit = matchPath(abs, cls);
  // `env.bak`, `prod.env.old`: a backup copy of an environment file is one too. (The
  // bare backup rule fires only alongside a content hit, so require "env" in the name.)
  if (hit?.ruleId === "path.env-backup") {
    const base = normalized.slice(normalized.lastIndexOf("/") + 1);
    return /(?:^|[._-])env(?:[._-]|$)/.test(base) ? "environment file backup" : null;
  }
  if (!hit || !BLOCKING.has(hit.ruleId)) return null;
  if (hit.ruleId === "path.env-file" && normalized.endsWith(".json")) return null; // too ambiguous to block unread

  if (hit.ruleId === "path.private-key") {
    const head = probeHead(abs);
    if (head === null) return null; // does not exist (or unreadable): nothing to protect
    return confirmPathRule(hit.ruleId, head).fires ? "private key" : null; // a certificate is fine
  }
  const label: Partial<Record<PathRuleId, string>> = {
    "path.env-file": "environment file",
    "path.cookie-jar": "cookie jar",
    "path.service-account": "service-account / client-secret file",
    "path.pkcs12": "PKCS#12 key bundle",
    "path.aws-long-lived": "AWS credentials file",
  };
  return label[hit.ruleId] ?? "credential file";
}

const isAllowed = (abs: string, ctx: HookContext) =>
  ctx.allow.some((re) => re.test(abs.replace(/\\/g, "/")));

const ASK_USER =
  "Ask the user for the specific value you need, or have them allow the path in " +
  "~/.repo-wrapped/sweep.json (hookAllow).";

/** Files named in a deny reason (the rest are counted, not listed). */
const MAX_NAMED = 3;

function describeFlagged(flagged: readonly FlaggedFile[], env: SweepEnv): string {
  const shown = flagged.slice(0, MAX_NAMED);
  const list = shown.map((f) => `${displayPath(f.path, env)} (${f.reason})`).join(", ");
  const more = flagged.length - shown.length;
  return more > 0 ? `${list} and ${more} more` : list;
}

/** The directory searches a tool call performs (`Grep`, or a recursive shell reader). */
function searchRequests(input: HookInput): SearchRequest[] {
  const ti = input.tool_input;
  if (!ti || typeof ti !== "object") return [];
  if (input.tool_name === "Grep") return [grepToolRequest(ti)];
  return typeof ti.command === "string" && ti.command ? detectShellSearches(ti.command) : [];
}

/** How to leave the credential files out of this particular kind of search. */
function exclusionHint(tool: string, names: string[]): string {
  const glob = names.length === 1 ? names[0]! : `{${names.join(",")}}`;
  switch (tool) {
    case "Grep":
      return `a Grep glob like "!${glob}"`;
    case "rg":
    case "ripgrep":
      return `rg --glob '!${glob}'`;
    case "grep":
    case "egrep":
    case "fgrep":
    case "zgrep":
      return names.map((n) => `--exclude=${n}`).join(" ");
    default:
      return "a narrower file spec";
  }
}

function checkSearch(req: SearchRequest, cwd: string, ctx: HookContext): HookDecision | null {
  const deps: SearchDeps = {
    env: ctx.env,
    baselineAbs: ctx.baselineAbs ?? [],
    userExclude: ctx.exclude ?? [],
    allow: ctx.allow,
    blockReason: (abs) => blockReason(abs, ctx),
  };
  for (const raw of req.dirs.length > 0 ? req.dirs : ["."]) {
    if (raw.includes("://")) continue;
    for (const dir of resolveVariants(raw, cwd, ctx.env)) {
      if (!isDirectory(dir)) continue;
      const { flagged, gitFailure } = findFlagged(dir, req, deps);
      if (flagged.length === 0) continue;
      const names = [
        ...new Set(
          flagged.slice(0, MAX_NAMED).map((f) => f.path.replace(/\\/g, "/").split("/").pop()!),
        ),
      ];
      return {
        deny: true,
        reason:
          `repo-wrapped-sweep blocked a recursive search of ${displayPath(dir, ctx.env)}: ` +
          `it would read ${describeFlagged(flagged, ctx.env)}. ` +
          `Search a narrower path or exclude them (${exclusionHint(req.tool, names)}). ` +
          "Reading them would copy plaintext secrets into this transcript. " +
          ASK_USER +
          gitFailureNote(gitFailure),
      };
    }
  }
  return null;
}

/** Explains a denial that only stood because .gitignore status was unknown. */
export function gitFailureNote(failure: GitFailure | undefined): string {
  if (failure === "timeout") return " (could not confirm .gitignore — git check-ignore timed out)";
  if (failure === "unavailable") return " (could not confirm .gitignore — git unavailable)";
  return "";
}

/** Decide one tool call. Pure over its context apart from the 4 KB header probe,
 *  directory listings (wildcard tokens) and the bounded directory-search walk. */
export function decide(input: HookInput, ctx: HookContext): HookDecision {
  const cwd = typeof input.cwd === "string" && input.cwd ? input.cwd : ctx.cwd;
  const P = pathFor(ctx.env);

  for (const raw of extractCandidates(input)) {
    if (!raw || raw.includes("://")) continue;
    for (const abs of resolveVariants(raw, cwd, ctx.env)) {
      const isWildcard = /[*?]/.test(P.basename(abs));
      const flagged: FlaggedFile[] = [];
      for (const candidate of isWildcard ? expandWildcard(abs, P) : [abs]) {
        if (isAllowed(candidate, ctx)) continue;
        const reason = blockReason(candidate, ctx);
        if (reason) flagged.push({ path: candidate, reason });
      }
      if (flagged.length === 1) {
        const [only] = flagged;
        return {
          deny: true,
          reason:
            `repo-wrapped-sweep blocked access to ${displayPath(only!.path, ctx.env)} (${only!.reason}). ` +
            "Reading it would copy plaintext secrets into this transcript. " +
            ASK_USER,
        };
      }
      if (flagged.length > 1) {
        // `cat dir/*`: name the files the pattern would read, not just the first.
        return {
          deny: true,
          reason:
            `repo-wrapped-sweep blocked ${displayPath(abs, ctx.env)}: it matches ${describeFlagged(flagged, ctx.env)}. ` +
            "Use a narrower pattern that leaves them out. " +
            "Reading them would copy plaintext secrets into this transcript. " +
            ASK_USER,
        };
      }
    }
  }

  for (const req of searchRequests(input)) {
    const denied = checkSearch(req, cwd, ctx);
    if (denied) return denied;
  }
  return { deny: false };
}

/** Build the per-call context: baseline path set + hookAllow/exclude globs. */
export function loadHookContext(env: SweepEnv, cwd: string): HookContext {
  const baseline = new Set<string>();
  const baselineAbs: string[] = [];
  const b = loadBaseline(defaultBaselinePath(env));
  if (b) {
    for (const entry of Object.values(b.findings)) {
      if (entry.resolvedAt) continue;
      // Low = samples, test fixtures and vendored copies (the scanner's own test
      // suite, library test certs). Blocking them made the guard unusable in any
      // repo that tests secret handling; the path rules still cover real key files.
      if (entry.severity === "low") continue;
      for (const loc of entry.locations) {
        const abs = expandPath(loc, env);
        baseline.add(normPath(abs, env.platform));
        baselineAbs.push(abs);
      }
    }
  }
  const config = loadConfig(env);
  const allow = config.hookAllow.map((g) => compileGlob(expandPath(g, env)));
  const exclude = config.exclude.map((g) => compileGlob(expandPath(g, env)));
  return { env, cwd, baseline, baselineAbs, allow, exclude };
}

export interface HookCheckResult {
  code: 0 | 2;
  stderr: string;
}

/**
 * The `hook check` entry: stdin text in, exit code + stderr out. Anything
 * unparseable ALLOWS (logged) — a broken guard must not block the agent.
 */
export function runHookCheck(
  stdin: string,
  env: SweepEnv,
  cwd: string = process.cwd(),
): HookCheckResult {
  let input: HookInput;
  try {
    input = JSON.parse(stdin) as HookInput;
    if (input === null || typeof input !== "object") throw new Error("not an object");
  } catch {
    return { code: 0, stderr: "repo-wrapped-sweep hook: ignoring malformed input (allowing)\n" };
  }
  try {
    const decision = decide(input, loadHookContext(env, cwd));
    return decision.deny ? { code: 2, stderr: `${decision.reason}\n` } : { code: 0, stderr: "" };
  } catch (err) {
    return { code: 0, stderr: `repo-wrapped-sweep hook: ${(err as Error).message} (allowing)\n` };
  }
}
