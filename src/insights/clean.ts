// `disk clean` (ENDPOINT-MACHINE-INSIGHTS § C2.2, Phase C3) — the ONLY command in the CLI
// that changes the machine. Safety is the design; every rule below has a test
// (test/disk-clean.test.ts):
//
// - Dry run unless `--yes` (or a "y" to the per-project question at an interactive TTY).
//   Non-interactive without --yes is always a dry run.
// - Only the C2.2 `remove` classes the walk found, only next to their proving sibling
//   (re-checked from a fresh listing just before acting), only in projects untouched for
//   --older-than days (default 30). `.venv` only with --include-venv. Never `dist/`/`out/`,
//   Docker, or anything outside the home directory.
// - Never follows a symlink or junction. A target that IS a link is refused; a link INSIDE a
//   target (pnpm's node_modules is full of junctions) is unlinked as a link — its target is
//   never listed, let alone deleted. A target whose realpath leaves the project folder or
//   the home directory is refused.
// - A target holding git-tracked files, or untracked/modified files git can see, is refused
//   (`git status`/`git ls-files` on that path). If git cannot answer, the target is refused.
// - Package caches are cleaned only through the tool's own prune command, never `rm`; npm's
//   only with --include-npm-cache.
// - Deletion is permanent (decision C9.4), and every action is appended to
//   `<configDir>/clean-log.jsonl` as `{ path, bytes, time, … }`.
// - Never reachable from `schedule` or MDM: the scheduled invocation is a plain sweep, and
//   `disk clean --scheduled` is refused outright (cli.ts).

import fs from "node:fs";
import path from "node:path";
import {
  PACKAGE_CACHES,
  classifyDir,
  isReportOnlyDir,
  isStale,
  isVenvDir,
  type DiskClass,
  type PackageCacheSpec,
} from "@/lib/endpoint/insights/disk-classes";
import { displayPath, isUnder, normPath, type SweepEnv } from "../env";
import { dirSize, formatBytes, type DiskCollection } from "./disk";
import { git } from "./git";
import { commandFor, findOnPath, mapPool, runCommand } from "./run";

/** Default --older-than (§ C2.2). */
export const CLEAN_OLDER_THAN_DAYS = 30;
/** The git guard's per-command deadline (a status limited to one path). */
export const CLEAN_GIT_TIMEOUT_MS = 10_000;
/** A package manager's own prune can take a while on a large store. */
export const PRUNE_TIMEOUT_MS = 10 * 60_000;
/** The log every action is appended to, under the config dir (~/.repo-wrapped). */
export const CLEAN_LOG_FILE = "clean-log.jsonl";

const DAY_MS = 86_400_000;

export type SkipReason =
  | "venv" // .venv without --include-venv
  | "recent" // project (or the folder itself) touched inside the window
  | "unknown-age" // no way to date the project — never stale on a guess
  | "missing" // gone since the walk
  | "outside-home"
  | "link" // the target (or a parent under the project) is a symlink/junction
  | "escapes" // realpath leaves the project folder or the home directory
  | "no-proof" // the proving sibling file is no longer there
  | "report-only" // dist/ or out/ — never cleaned
  | "nested-repo" // the folder holds its own .git
  | "tracked" // git tracks files inside it
  | "uncommitted" // git sees untracked or modified files inside it
  | "git-unknown"; // in a repo, but git could not answer

export const SKIP_LABELS: Record<SkipReason, string> = {
  venv: "a .venv (add --include-venv)",
  recent: "in a project touched inside the window",
  "unknown-age": "in a project that could not be dated",
  missing: "no longer there",
  "outside-home": "outside the home directory",
  link: "a symlink or junction",
  escapes: "resolves outside its project or home",
  "no-proof": "no longer next to the file that rebuilds it",
  "report-only": "dist/ or out/ (never cleaned)",
  "nested-repo": "holding its own git repository",
  tracked: "holding files tracked by git",
  uncommitted: "holding untracked or modified files git can see",
  "git-unknown": "in a repo git could not check",
};

export interface CleanTarget {
  path: string;
  cls: DiskClass;
  project: string;
  bytes: number;
  /** The size is a lower bound (the measuring pass was cut short). */
  partial: boolean;
  /** Newest of the project's last touch and the folder's own mtime. */
  lastTouched: number | null;
}

export interface SkippedTarget extends CleanTarget {
  reason: SkipReason;
}

export interface CachePrune {
  tool: PackageCacheSpec["tool"];
  label: string;
  /** The measured cache folders. */
  paths: string[];
  bytes: number;
  /** The prune argv, e.g. ["pnpm", "store", "prune"]. */
  argv: readonly string[];
  /** Absolute binary the argv[0] resolved to. */
  bin: string;
}

export type CacheSkipReason = "npm-opt-in" | "no-prune" | "not-installed";

export const CACHE_SKIP_LABELS: Record<CacheSkipReason, string> = {
  "npm-opt-in": "npm's cache is cleaned only with --include-npm-cache",
  "no-prune": "has no prune command of its own (reported only)",
  "not-installed": "its tool is not on PATH",
};

export interface CacheSkipped {
  tool: PackageCacheSpec["tool"];
  label: string;
  bytes: number;
  reason: CacheSkipReason;
}

export interface CleanPlan {
  olderThanDays: number;
  remove: CleanTarget[];
  skipped: SkippedTarget[];
  caches: CachePrune[];
  cachesSkipped: CacheSkipped[];
  /** Bytes of `remove` (a lower bound when `partial`). */
  removeBytes: number;
  partial: boolean;
}

export interface CleanOptions {
  env: SweepEnv;
  olderThanDays?: number;
  includeVenv?: boolean;
  includeNpmCache?: boolean;
  now?: number;
}

// ---------------------------------------------------------------------------
// Path guards
// ---------------------------------------------------------------------------

function realpath(p: string): string | null {
  try {
    return fs.realpathSync(p);
  } catch {
    return null;
  }
}

function lstat(p: string): fs.Stats | null {
  try {
    return fs.lstatSync(p);
  } catch {
    return null;
  }
}

/**
 * May `target` (a class folder of `cls` inside `project`) be deleted, as far as the file
 * system says? Re-checked immediately before every deletion, so a folder that became a
 * link, moved, or lost its proving sibling since the walk is refused.
 */
export function vetTarget(
  target: string,
  project: string,
  cls: DiskClass,
  env: SweepEnv,
): SkipReason | null {
  const p = env.platform;
  // 1. Lexically inside home and inside its project, strictly below both.
  if (!isUnder(target, env.home, p) || !isUnder(project, env.home, p)) return "outside-home";
  if (normPath(project, p) === normPath(env.home, p)) return "outside-home";
  const rel = path.relative(project, target);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) return "escapes";
  const relPosix = rel.split(path.sep).join("/");
  if (isReportOnlyDir(path.basename(target))) return "report-only";

  // 2. The folder itself: a real directory, never a link (a junction lstats as a link).
  const st = lstat(target);
  if (!st) return "missing";
  if (st.isSymbolicLink()) return "link";
  if (!st.isDirectory()) return "missing";
  // Every step between the project and the target (`.vercel` of `.vercel/output`).
  let step = path.dirname(target);
  while (normPath(step, p) !== normPath(project, p) && isUnder(step, project, p)) {
    if (lstat(step)?.isSymbolicLink()) return "link";
    step = path.dirname(step);
  }

  // 3. Realpaths: the target must resolve to exactly <real project>/<rel>, and the project
  //    must resolve inside the real home. A link anywhere above (home/code → elsewhere)
  //    fails here.
  const realHome = realpath(env.home);
  const realProject = realpath(project);
  const realTarget = realpath(target);
  if (!realHome || !realProject || !realTarget) return "missing";
  if (!isUnder(realProject, realHome, p) || normPath(realProject, p) === normPath(realHome, p)) {
    return "escapes";
  }
  if (normPath(realTarget, p) !== normPath(path.join(realProject, rel), p)) return "escapes";
  if (!isUnder(realTarget, realHome, p)) return "escapes";

  // 4. The proving sibling is still there, from a fresh listing of the project folder.
  let names: string[];
  try {
    names = fs.readdirSync(project);
  } catch {
    return "missing";
  }
  if (classifyDir(relPosix, names) !== cls) return "no-proof";

  // 5. A git repository living inside a build folder is someone's work, not output.
  if (lstat(path.join(target, ".git"))) return "nested-repo";
  return null;
}

/** The nearest folder at or above `dir` (and inside home) holding a `.git`. */
export function findRepoRoot(dir: string, env: SweepEnv): string | null {
  let d = dir;
  for (;;) {
    if (!isUnder(d, env.home, env.platform)) return null;
    if (lstat(path.join(d, ".git"))) return d;
    const up = path.dirname(d);
    if (up === d) return null;
    d = up;
  }
}

/**
 * Does git object to deleting `target`? Tracked files inside it, or untracked/modified
 * files git can see (i.e. not ignored), refuse it. In a repo where git cannot answer —
 * missing, slow, broken — it is refused too: we never delete on a guess. Outside any repo
 * there is nothing to check.
 */
export async function gitGuard(
  target: string,
  env: SweepEnv,
  timeoutMs = CLEAN_GIT_TIMEOUT_MS,
): Promise<SkipReason | null> {
  const repo = findRepoRoot(path.dirname(target), env);
  if (!repo) return null;
  const rel = path.relative(repo, target).split(path.sep).join("/");
  // --literal-pathspecs: a project folder named `[x]` or `*` is a path, not a pattern.
  const tracked = await git(
    env,
    repo,
    ["--literal-pathspecs", "ls-files", "-z", "--", rel],
    timeoutMs,
    4096,
  );
  if (!tracked.ok || tracked.code !== 0) return "git-unknown";
  if (tracked.stdout.length > 0) return "tracked";
  const status = await git(
    env,
    repo,
    [
      "--literal-pathspecs",
      "status",
      "--porcelain=v1",
      "-z",
      "--untracked-files=normal",
      "--",
      rel,
    ],
    timeoutMs,
    4096,
  );
  if (!status.ok || status.code !== 0) return "git-unknown";
  if (status.stdout.length > 0) return "uncommitted";
  return null;
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

function mtimeOf(p: string): number | null {
  const st = lstat(p);
  return st ? st.mtimeMs : null;
}

const newest = (...ts: Array<number | null>): number | null =>
  ts.reduce<number | null>((a, t) => (t === null ? a : a === null || t > a ? t : a), null);

/**
 * What `disk clean` would do, from a `disk` collection. Reads the file system and runs
 * read-only git; changes nothing.
 */
export async function planClean(disk: DiskCollection, opts: CleanOptions): Promise<CleanPlan> {
  const env = opts.env;
  const now = opts.now ?? Date.now();
  const days = opts.olderThanDays ?? CLEAN_OLDER_THAN_DAYS;
  const skipped: SkippedTarget[] = [];
  const pending: CleanTarget[] = [];

  for (const f of disk.folders) {
    // The folder's own mtime counts as a touch: a fresh `npm install` or `next build` is use.
    const lastTouched = newest(f.lastTouched, mtimeOf(f.path));
    const t: CleanTarget = {
      path: f.path,
      cls: f.cls,
      project: f.project,
      bytes: f.bytes,
      partial: f.partial,
      lastTouched,
    };
    if (isVenvDir(path.basename(f.path)) && !opts.includeVenv) {
      skipped.push({ ...t, reason: "venv" });
    } else if (lastTouched === null) {
      skipped.push({ ...t, reason: "unknown-age" });
    } else if (!isStale(lastTouched, now, days)) {
      skipped.push({ ...t, reason: "recent" });
    } else {
      const reason = vetTarget(f.path, f.project, f.cls, env);
      if (reason) skipped.push({ ...t, reason });
      else pending.push(t);
    }
  }

  const guarded = await mapPool(pending, 4, (t) => gitGuard(t.path, env));
  const remove: CleanTarget[] = [];
  pending.forEach((t, i) => {
    const reason = guarded[i];
    if (reason) skipped.push({ ...t, reason });
    else remove.push(t);
  });

  const { caches, cachesSkipped } = planCaches(disk, opts);
  remove.sort((a, b) => b.bytes - a.bytes || a.path.localeCompare(b.path));
  skipped.sort((a, b) => b.bytes - a.bytes || a.path.localeCompare(b.path));
  return {
    olderThanDays: days,
    remove,
    skipped,
    caches,
    cachesSkipped,
    removeBytes: remove.reduce((n, t) => n + t.bytes, 0),
    partial: remove.some((t) => t.partial),
  };
}

function planCaches(
  disk: DiskCollection,
  opts: CleanOptions,
): { caches: CachePrune[]; cachesSkipped: CacheSkipped[] } {
  const caches: CachePrune[] = [];
  const cachesSkipped: CacheSkipped[] = [];
  const pe = opts.env.processEnv ?? process.env;
  for (const spec of PACKAGE_CACHES) {
    const found = disk.packageCaches.filter((c) => c.tool === spec.tool);
    if (found.length === 0) continue;
    const bytes = found.reduce((n, c) => n + c.bytes, 0);
    const base = { tool: spec.tool, label: spec.label, bytes };
    if (!spec.prune) {
      cachesSkipped.push({ ...base, reason: "no-prune" });
      continue;
    }
    if (spec.tool === "npm" && !opts.includeNpmCache) {
      cachesSkipped.push({ ...base, reason: "npm-opt-in" });
      continue;
    }
    const bin = findOnPath(spec.prune[0]!, {
      path: pe.PATH ?? pe.Path ?? "",
      pathext: pe.PATHEXT,
      platform: opts.env.platform,
    });
    if (!bin) {
      cachesSkipped.push({ ...base, reason: "not-installed" });
      continue;
    }
    caches.push({ ...base, paths: found.map((c) => c.path), argv: spec.prune, bin });
  }
  return { caches, cachesSkipped };
}

// ---------------------------------------------------------------------------
// Acting
// ---------------------------------------------------------------------------

export interface RemoveResult {
  bytes: number;
  /** Links (symlinks / junctions) removed as links — their targets were never touched. */
  links: number;
  errors: string[];
}

function unlinkLink(abs: string): void {
  try {
    fs.unlinkSync(abs);
  } catch (err) {
    // A Windows directory junction/symlink: rmdir (NON-recursive) removes the link itself.
    if (process.platform === "win32") fs.rmdirSync(abs);
    else throw err;
  }
}

function unlinkFile(abs: string): void {
  try {
    fs.unlinkSync(abs);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "EPERM" && code !== "EACCES") throw err;
    // A read-only file (common in Windows build output): clear the flag and retry once.
    fs.chmodSync(abs, 0o666);
    fs.unlinkSync(abs);
  }
}

/**
 * Delete a folder tree WITHOUT EVER FOLLOWING A LINK: every entry is lstat'ed; a symlink or
 * junction is unlinked as a link (never listed, never descended into), a directory is
 * emptied and rmdir'ed, a file is unlinked. Never `rm -rf`, never `fs.rm({ recursive })`.
 * Errors are collected, not thrown — whatever could not be removed stays.
 */
export function removeTree(root: string): RemoveResult {
  const out: RemoveResult = { bytes: 0, links: 0, errors: [] };
  const rm = (abs: string): void => {
    let st: fs.Stats;
    try {
      st = fs.lstatSync(abs);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") out.errors.push(errLine(abs, err));
      return;
    }
    try {
      if (st.isSymbolicLink()) {
        unlinkLink(abs);
        out.links++;
      } else if (st.isDirectory()) {
        for (const name of fs.readdirSync(abs)) rm(path.join(abs, name));
        fs.rmdirSync(abs);
      } else {
        unlinkFile(abs);
        out.bytes += st.size;
      }
    } catch (err) {
      out.errors.push(errLine(abs, err));
    }
  };
  rm(root);
  return out;
}

const errLine = (abs: string, err: unknown) =>
  `${abs}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`;

export interface CleanLogEntry {
  path: string;
  bytes: number;
  time: string;
  cls: DiskClass;
  /** `package-cache` entries: the tool whose prune ran. */
  tool?: string;
  /** Some entries could not be removed (or the prune failed). */
  incomplete?: boolean;
}

export function cleanLogPath(env: Pick<SweepEnv, "configDir">): string {
  return path.join(env.configDir, CLEAN_LOG_FILE);
}

export function appendCleanLog(env: Pick<SweepEnv, "configDir">, entry: CleanLogEntry): void {
  fs.mkdirSync(env.configDir, { recursive: true });
  fs.appendFileSync(cleanLogPath(env), `${JSON.stringify(entry)}\n`);
}

export interface RemovalOutcome {
  target: CleanTarget;
  /** Refused at the last moment (re-check) — nothing was touched. */
  refused?: SkipReason;
  result?: RemoveResult;
}

/**
 * Delete one planned folder: re-run every guard first (the walk may be minutes old), then
 * remove, then log. Never throws.
 */
export async function removeTarget(t: CleanTarget, env: SweepEnv): Promise<RemovalOutcome> {
  const refused = vetTarget(t.path, t.project, t.cls, env) ?? (await gitGuard(t.path, env));
  if (refused) return { target: t, refused };
  const result = removeTree(t.path);
  appendCleanLog(env, {
    path: t.path,
    bytes: result.bytes,
    time: new Date().toISOString(),
    cls: t.cls,
    ...(result.errors.length > 0 ? { incomplete: true } : {}),
  });
  return { target: t, result };
}

export interface PruneOutcome {
  cache: CachePrune;
  ok: boolean;
  /** Measured before − after (never negative). */
  freed: number;
  error?: string;
}

/** Run a tool's own prune (never rm), measure what it freed, log it. Never throws. */
export async function pruneCache(c: CachePrune, env: SweepEnv): Promise<PruneOutcome> {
  const { cmd, args } = commandFor(c.bin, c.argv.slice(1), env.platform);
  const r = await runCommand(cmd, args, {
    cwd: env.home,
    timeoutMs: PRUNE_TIMEOUT_MS,
    env: env.processEnv ?? process.env,
  });
  const ok = r.ok && r.code === 0;
  let after = 0;
  for (const p of c.paths) {
    after += (await dirSize(p, { deadline: Date.now() + 2 * 60_000 })).bytes;
  }
  const freed = Math.max(0, c.bytes - after);
  appendCleanLog(env, {
    path: c.paths[0] ?? "",
    bytes: freed,
    time: new Date().toISOString(),
    cls: "package-cache",
    tool: c.tool,
    ...(ok ? {} : { incomplete: true }),
  });
  const error = ok
    ? undefined
    : r.ok
      ? `exit ${r.code}${r.stderr.trim() ? `: ${r.stderr.trim().split("\n")[0]}` : ""}`
      : r.failure;
  return { cache: c, ok, freed, error };
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/** Group planned folders by project, biggest project first (the interactive question unit). */
export function byProject(remove: readonly CleanTarget[]): Array<[string, CleanTarget[]]> {
  const m = new Map<string, CleanTarget[]>();
  for (const t of remove) m.set(t.project, [...(m.get(t.project) ?? []), t]);
  const sum = (ts: CleanTarget[]) => ts.reduce((n, t) => n + t.bytes, 0);
  return [...m.entries()].sort((a, b) => sum(b[1]) - sum(a[1]) || a[0].localeCompare(b[0]));
}

const ageDays = (t: number | null, now: number) =>
  t === null ? "?" : `${Math.max(0, Math.floor((now - t) / DAY_MS))}d`;

export function renderPlanText(
  plan: CleanPlan,
  env: SweepEnv,
  opts: { now?: number; all?: boolean; dryRun: boolean },
): string {
  const now = opts.now ?? Date.now();
  const L: string[] = [];
  const approx = plan.partial ? "at least " : "";
  L.push(
    opts.dryRun
      ? `disk clean — DRY RUN, nothing is deleted. Projects untouched for ${plan.olderThanDays}+ days.`
      : `disk clean — projects untouched for ${plan.olderThanDays}+ days.`,
  );
  L.push("");
  if (plan.remove.length === 0) {
    L.push("No regenerable folder qualifies.");
  } else {
    L.push(opts.dryRun ? "Would delete permanently:" : "To delete permanently:");
    for (const t of plan.remove) {
      L.push(
        `  ${formatBytes(t.bytes).padStart(9)}${t.partial ? "+" : " "} ${t.cls.padEnd(13)} ${displayPath(t.path, env)}  (untouched ${ageDays(t.lastTouched, now)})`,
      );
    }
  }
  if (plan.caches.length > 0) {
    L.push("");
    L.push(opts.dryRun ? "Would run (the tool's own prune):" : "Will run (the tool's own prune):");
    for (const c of plan.caches) {
      L.push(`  ${c.argv.join(" ").padEnd(26)} ${c.label}, ${formatBytes(c.bytes)} now`);
    }
  }
  L.push("");
  const projects = new Set(plan.remove.map((t) => t.project)).size;
  L.push(
    `Total: ${approx}${formatBytes(plan.removeBytes)} in ${plan.remove.length} folder${plan.remove.length === 1 ? "" : "s"} across ${projects} project${projects === 1 ? "" : "s"}` +
      (plan.caches.length > 0
        ? ` (+ up to ${formatBytes(plan.caches.reduce((n, c) => n + c.bytes, 0))} of package caches)`
        : ""),
  );

  if (plan.skipped.length > 0 || plan.cachesSkipped.length > 0) {
    L.push("");
    L.push("Kept:");
    if (opts.all) {
      for (const s of plan.skipped) {
        L.push(
          `  ${formatBytes(s.bytes).padStart(9)}  ${displayPath(s.path, env)} — ${SKIP_LABELS[s.reason]}`,
        );
      }
    } else {
      const counts = new Map<SkipReason, { n: number; bytes: number }>();
      for (const s of plan.skipped) {
        const c = counts.get(s.reason) ?? { n: 0, bytes: 0 };
        counts.set(s.reason, { n: c.n + 1, bytes: c.bytes + s.bytes });
      }
      for (const [reason, c] of counts) {
        L.push(
          `  ${c.n} folder${c.n === 1 ? "" : "s"} (${formatBytes(c.bytes)}) ${SKIP_LABELS[reason]}`,
        );
      }
    }
    for (const c of plan.cachesSkipped) {
      L.push(`  ${c.label} (${formatBytes(c.bytes)}): ${CACHE_SKIP_LABELS[c.reason]}`);
    }
    if (!opts.all && plan.skipped.length > 0) L.push("  (--all lists every kept folder)");
  }
  L.push("");
  L.push(
    `dist/, out/, Docker and anything outside your home folder are never touched. Deletion is permanent (not the Recycle Bin/Trash); every action is logged to ${displayPath(cleanLogPath(env), env)}.`,
  );
  return L.join("\n");
}

export function planJson(plan: CleanPlan, env: SweepEnv) {
  const t = (x: CleanTarget) => ({
    path: displayPath(x.path, env),
    project: displayPath(x.project, env),
    cls: x.cls,
    bytes: x.bytes,
    partial: x.partial,
    lastTouched: x.lastTouched === null ? null : new Date(x.lastTouched).toISOString(),
  });
  return {
    olderThanDays: plan.olderThanDays,
    removeBytes: plan.removeBytes,
    partial: plan.partial,
    remove: plan.remove.map(t),
    skipped: plan.skipped.map((s) => ({ ...t(s), reason: s.reason })),
    caches: plan.caches.map((c) => ({
      tool: c.tool,
      label: c.label,
      bytes: c.bytes,
      command: c.argv.join(" "),
    })),
    cachesSkipped: plan.cachesSkipped,
  };
}

/** `--older-than`: `30d`, `30` or `4w`. Null when unusable (must be at least 1 day). */
export function parseOlderThan(v: string | undefined): number | null {
  if (v === undefined) return CLEAN_OLDER_THAN_DAYS;
  const m = /^(\d+)\s*([dw]?)$/i.exec(v.trim());
  if (!m) return null;
  const n = Number(m[1]) * (m[2]!.toLowerCase() === "w" ? 7 : 1);
  return Number.isInteger(n) && n >= 1 ? n : null;
}
