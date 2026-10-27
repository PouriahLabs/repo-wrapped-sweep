// The Machine Insights block an `--upload` sends (ENDPOINT-MACHINE-INSIGHTS § C3, schema v2).
//
// METADATA ONLY, like the findings: counts, sizes, versions, token totals. A repo leaves the
// machine as a `RepoRef` — HMAC(device salt, normalized remote URL or home-relative path).
// The device salt IS the scope's salt (`device.saltHex`: the org's for an org device, the
// user's own for a personal one — the same one findings are fingerprinted with), so two
// laptops in one org that cloned the same remote send the same id. The readable name (the
// home-relative path) goes only when the enrolment shares paths; the server strips it
// otherwise.
//
// WHAT AN UPLOAD COLLECTS — chosen so the daily scheduled run stays fast:
//   machine     os/statfs calls only, no spawn.
//   toolchain   ~25 local `--version` probes (2 s deadline each, 8 in flight; a missing tool
//               costs no spawn) — cheap, and the fleet/drift views need it. Always.
//   git         per-repo `git status`/`for-each-ref`/`stash`/`log` (3 s deadline each, 4
//               repos in flight, NEVER `git fetch`), plus one `git config` per repo that
//               is actually referenced, for its remote URL. Full-scope sweeps only.
//   disk/backup folder sizing, capped by UPLOAD_SIZE_BUDGET_MS each (sizes past the
//               budget are reported partial, never waited for). No machine-wide package
//               caches and no `docker system df` — Docker can boot a VM and take minutes.
//               Full-scope sweeps only: a `--root`/`--quick` run would under-report them.
//   ai          the incremental transcript cursor (C2) — only new lines are read — and only
//               the days since the last successful upload are sent (`upload-cursor.json`).
// `disk clean` never runs here, and nothing here touches the network.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { foldUsage, type UsageRow } from "@/lib/endpoint/insights/ai-usage";
import { repoDisplayName, repoRefId } from "@/lib/endpoint/insights/repo-ref";
import {
  MAX_AI_ROWS,
  MAX_BACKUP_TOP,
  MAX_DRIFT_ROWS,
  MAX_GIT_TOP,
  MAX_MODEL_LENGTH,
  MAX_REPO_NAME_LENGTH,
  MAX_REPO_NAMES,
  MAX_VERSION_LENGTH,
  type AiDayRow,
  type AiToolsInsights,
  type InsightsBlock,
  type MachineInfo,
  type PostureInsights,
  type RepoRef,
} from "@/lib/endpoint/insights/wire";
import { displayPath, expandPath, type SweepEnv } from "../env";
import { writeJsonPrivate } from "../state";
import type { BackupCollection } from "./backup";
import type { Discovery } from "./discover";
import type { DiskCollection } from "./disk";
import { GIT_COMMAND_TIMEOUT_MS, GIT_POOL, git, type GitCollection } from "./git";
import { collectInsights } from "./index";
import { collectAiUsage, repoResolver } from "./ai-usage";
import {
  collectActivity,
  collectAiTools,
  collectMachineExtras,
  collectPosture,
  type ActivityCollection,
} from "./machine-extras";
import { mapPool } from "./run";
import { collectToolchain, type ToolchainCollection } from "./toolchain";

/** Folder-sizing budget per section (disk, backup) on an upload run. */
export const UPLOAD_SIZE_BUDGET_MS = 30_000;
/** Where the AI upload cursor lives (next to `device.json`). */
export const UPLOAD_CURSOR_FILE = "upload-cursor.json";

const DAY_MS = 86_400_000;
const utcDay = (ms: number) => new Date(ms).toISOString().slice(0, 10);
const round3 = (n: number) => Math.round(n * 1000) / 1000;
const toGb = (bytes: number) => round3(bytes / 1e9);

// ---------------------------------------------------------------------------
// Machine facts
// ---------------------------------------------------------------------------

export interface MachineProbe {
  release(): string;
  arch(): string;
  cpus(): number;
  totalmem(): number;
  /** Total/free bytes of the volume holding `dir`, or null. */
  disk(dir: string): { total: number; free: number } | null;
}

const realMachine: MachineProbe = {
  release: () => os.release(),
  arch: () => os.arch(),
  cpus: () =>
    typeof os.availableParallelism === "function" ? os.availableParallelism() : os.cpus().length,
  totalmem: () => os.totalmem(),
  disk: (dir) => {
    try {
      const s = fs.statfsSync(dir);
      return { total: s.blocks * s.bsize, free: s.bavail * s.bsize };
    } catch {
      return null;
    }
  },
};

export function machineInfo(
  env: Pick<SweepEnv, "home">,
  probe: MachineProbe = realMachine,
): MachineInfo {
  const d = probe.disk(env.home);
  return {
    osVersion: probe.release().slice(0, MAX_VERSION_LENGTH),
    arch: probe.arch().slice(0, 16),
    cpuCount: probe.cpus(),
    memGb: round3(probe.totalmem() / 2 ** 30),
    diskTotalGb: d ? toGb(d.total) : 0,
    diskFreeGb: d ? toGb(d.free) : 0,
  };
}

// ---------------------------------------------------------------------------
// RepoRefs
// ---------------------------------------------------------------------------

/** `git config --get-regexp` output → the `origin` URL, else the first remote's, else null. */
export function pickRemoteUrl(output: string): string | null {
  let first: string | null = null;
  for (const raw of output.split("\n")) {
    const m = /^remote\.(.+)\.url\s+(\S.*)$/.exec(raw.replace(/\r$/, "").trim());
    if (!m) continue;
    const url = m[2]!.trim();
    if (m[1] === "origin") return url;
    first ??= url;
  }
  return first;
}

/** Remote URL per repo root (one bounded `git config` each); null when it has none / git failed. */
export async function collectRemotes(
  repos: readonly string[],
  env: SweepEnv,
): Promise<Map<string, string | null>> {
  const urls = await mapPool(repos, GIT_POOL, async (repo) => {
    const r = await git(
      env,
      repo,
      ["config", "--get-regexp", "^remote\\..*\\.url$"],
      GIT_COMMAND_TIMEOUT_MS,
    );
    return r.ok && r.code === 0 ? pickRemoteUrl(r.stdout) : null;
  });
  return new Map(repos.map((p, i) => [p, urls[i]!]));
}

export interface RefContext {
  env: Pick<SweepEnv, "home" | "platform">;
  /** The device's scope salt (org salt for an org device). */
  salt: Uint8Array;
  sharePaths: boolean;
  /** Name repos `owner/repo` (or the folder name) — wins over `sharePaths`' path. */
  shareRepoNames?: boolean;
  /** Remote URL per absolute repo root (missing / null = no usable remote → path identity). */
  remotes: ReadonlyMap<string, string | null>;
}

/** A RepoRef for an absolute folder. PURE given its inputs. */
export function makeRepoRef(abs: string, ctx: RefContext): RepoRef {
  const shown = displayPath(abs, ctx.env);
  const homeRelativePath = shown.startsWith("~/") ? shown.slice(2) : shown;
  const identity = { remoteUrl: ctx.remotes.get(abs) ?? null, homeRelativePath };
  const id = repoRefId(ctx.salt, identity);
  if (ctx.shareRepoNames) {
    const name = repoDisplayName(identity);
    if (name) return { id, name };
  }
  return ctx.sharePaths && shown.startsWith("~/") && shown.length <= MAX_REPO_NAME_LENGTH
    ? { id, name: shown }
    : { id };
}

// ---------------------------------------------------------------------------
// AI days since the last upload
// ---------------------------------------------------------------------------

/**
 * Which complete days to send. Rows are complete-day totals (the server REPLACES a day's
 * rows), so re-sending a day is harmless and missing one is not: everything from `sinceDay`
 * on is sent, whole days at a time, up to the row cap. A first upload (no cursor) backfills
 * the retained history oldest-first over successive runs.
 *
 * Returns the rows and the cursor to store once the upload succeeds: on a complete send,
 * YESTERDAY (so a session that crossed midnight while the last upload ran is re-sent); on a
 * capped send, the day after the last one included.
 */
export function selectAiDays<T extends Pick<UsageRow, "day">>(
  rows: readonly T[],
  sinceDay: string | null,
  now: number,
  max = MAX_AI_ROWS,
): { rows: T[]; nextCursor: string } {
  const pending = rows
    .filter((r) => sinceDay === null || r.day >= sinceDay)
    .sort((a, b) => a.day.localeCompare(b.day));
  const complete = utcDay(now - DAY_MS);
  if (pending.length <= max) return { rows: pending, nextCursor: complete };

  const out: T[] = [];
  let i = 0;
  while (i < pending.length) {
    const day = pending[i]!.day;
    let j = i;
    while (j < pending.length && pending[j]!.day === day) j++;
    const size = j - i;
    if (out.length + size > max) {
      // A single day over the cap on its own: send what fits and move past it, or the
      // cursor could never advance.
      if (out.length === 0) out.push(...pending.slice(i, i + max));
      break;
    }
    out.push(...pending.slice(i, j));
    i = j;
  }
  const last = out[out.length - 1]!.day;
  return { rows: out, nextCursor: utcDay(Date.parse(`${last}T00:00:00Z`) + DAY_MS) };
}

interface UploadCursorFile {
  version: 1;
  /** The cursor belongs to one enrolment; a re-enrolled device starts over. */
  deviceId: string;
  /** Send AI days on or after this UTC day. */
  aiSinceDay: string;
}

export function loadUploadCursor(
  env: Pick<SweepEnv, "configDir">,
  deviceId: string,
): string | null {
  let j: Partial<UploadCursorFile> | null;
  try {
    j = JSON.parse(fs.readFileSync(path.join(env.configDir, UPLOAD_CURSOR_FILE), "utf8"));
  } catch {
    return null;
  }
  if (!j || typeof j !== "object" || j.version !== 1 || j.deviceId !== deviceId) return null;
  return typeof j.aiSinceDay === "string" && /^\d{4}-\d{2}-\d{2}$/.test(j.aiSinceDay)
    ? j.aiSinceDay
    : null;
}

export function saveUploadCursor(
  env: Pick<SweepEnv, "configDir">,
  deviceId: string,
  aiSinceDay: string,
): void {
  writeJsonPrivate(path.join(env.configDir, UPLOAD_CURSOR_FILE), {
    version: 1,
    deviceId,
    aiSinceDay,
  } satisfies UploadCursorFile);
}

// ---------------------------------------------------------------------------
// The block (pure)
// ---------------------------------------------------------------------------

export interface BlockInput {
  collectedAt: string;
  machine: MachineInfo;
  git?: GitCollection;
  disk?: DiskCollection;
  toolchain?: ToolchainCollection;
  backup?: BackupCollection;
  /** Folded AI rows whose `repo` is an ABSOLUTE repo root (or null). */
  ai?: { rows: readonly UsageRow[]; pricesAsOf: string };
  posture?: PostureInsights;
  aiTools?: AiToolsInsights;
  /** Commit-rhythm fold whose `topRepo.repo` is an ABSOLUTE repo root. */
  activity?: ActivityCollection;
  ref: (abs: string) => RepoRef;
}

/** Biggest and longest-untouched project from the backup sizing (null-safe). PURE. */
export function projectExtremes(backup: BackupCollection | undefined): {
  biggest: { path: string; bytes: number } | null;
  oldest: { path: string; lastTouched: number } | null;
} {
  let biggest: { path: string; bytes: number } | null = null;
  let oldest: { path: string; lastTouched: number } | null = null;
  for (const p of backup?.projects ?? []) {
    if (p.bytes !== null && p.bytes > 0 && (!biggest || p.bytes > biggest.bytes)) {
      biggest = { path: p.path, bytes: p.bytes };
    }
    if (p.lastTouched !== null && (!oldest || p.lastTouched < oldest.lastTouched)) {
      oldest = { path: p.path, lastTouched: p.lastTouched };
    }
  }
  return { biggest, oldest };
}

const clip = (s: string, n: number) => s.slice(0, n);

/** Map the collectors' local results to the wire block, applying every § C3 cap. PURE. */
export function buildInsightsBlock(input: BlockInput): InsightsBlock {
  const { ref } = input;
  const out: InsightsBlock = { collectedAt: input.collectedAt, machine: input.machine };

  if (input.git) {
    const g = input.git;
    const top = g.repos
      .filter((r) => r.state !== null && r.states.some((s) => s !== "clean"))
      .slice(0, MAX_GIT_TOP)
      .map((r) => ({
        repo: ref(r.path),
        states: r.states,
        ahead: r.state!.hasRemote ? r.state!.unpushedCommits : 0,
        uncommitted: r.state!.changed,
        stashes: r.state!.stashTimes.length,
      }));
    out.git = {
      repos: g.summary.repos,
      byState: { ...g.summary.byState },
      unpushedCommits: g.summary.unpushedCommits,
      staleStashes: g.summary.staleStashes,
      ...(top.length > 0 ? { top } : {}),
    };
  }

  if (input.disk) {
    const t = input.disk.totals;
    const byClass: NonNullable<InsightsBlock["disk"]>["byClass"] = {};
    for (const [k, v] of Object.entries(t.byClass)) {
      if (v && v > 0) byClass[k as keyof typeof byClass] = toGb(v);
    }
    out.disk = {
      reclaimableGb: toGb(t.reclaimableBytes),
      staleReclaimableGb: toGb(t.staleReclaimableBytes),
      byClass,
      ...(input.disk.dockerBytes !== null ? { dockerGb: toGb(input.disk.dockerBytes) } : {}),
    };
  }

  if (input.toolchain) {
    const tc = input.toolchain;
    const tools: NonNullable<InsightsBlock["toolchain"]>["tools"] = {};
    for (const p of tc.tools) {
      tools[p.tool] =
        p.status === "present" && p.version ? clip(p.version, MAX_VERSION_LENGTH) : null;
    }
    const drift = tc.repos
      .flatMap((r) =>
        r.drift.map((d) => ({
          repo: ref(r.path),
          tool: d.tool,
          installed: d.installed === null ? null : clip(d.installed, MAX_VERSION_LENGTH),
          wanted: clip(d.wanted, MAX_VERSION_LENGTH),
        })),
      )
      .slice(0, MAX_DRIFT_ROWS);
    out.toolchain = { tools, managers: [...tc.managers], drift };
  }

  if (input.ai) {
    const days: AiDayRow[] = input.ai.rows
      .filter((r) => r.model.length > 0)
      .slice(0, MAX_AI_ROWS)
      .map((r) => ({
        day: r.day,
        repo: r.repo === null ? null : ref(r.repo),
        tool: r.tool,
        model: clip(r.model, MAX_MODEL_LENGTH),
        sessions: r.sessions,
        activeMinutes: r.activeMinutes,
        inputTokens: r.inputTokens,
        outputTokens: r.outputTokens,
        cacheWriteTokens: r.cacheWriteTokens,
        cacheReadTokens: r.cacheReadTokens,
        costUsd: r.costUsd,
      }));
    out.ai = { pricesAsOf: input.ai.pricesAsOf, days };
  }

  if (input.backup) {
    const b = input.backup;
    const top = b.projects
      .filter((p) => p.state === "local-only" || p.state === "partly-pushed")
      .slice(0, MAX_BACKUP_TOP)
      .map((p) => ({
        project: ref(p.path),
        state: p.state,
        bytes: p.bytes ?? 0,
        lastTouched: p.lastTouched === null ? null : new Date(p.lastTouched).toISOString(),
      }));
    out.backup = {
      projects: b.summary.projects,
      byState: { ...b.summary.byState },
      localOnlyBytes: b.summary.localOnlyBytes,
      ...(top.length > 0 ? { top } : {}),
    };
  }

  if (input.posture) out.posture = input.posture;
  if (input.aiTools) out.aiTools = input.aiTools;
  if (input.activity) {
    const f = input.activity.fold;
    const { biggest, oldest } = projectExtremes(input.backup);
    out.activity = {
      commits7d: f.commits7d,
      commits365d: f.commits365d,
      activeDays365d: f.activeDays365d,
      longestStreakDays: f.longestStreakDays,
      byHour: f.byHour,
      byWeekday: f.byWeekday,
      topRepo: f.topRepo ? { repo: ref(f.topRepo.repo), commits: f.topRepo.commits } : null,
      biggestProject: biggest ? { repo: ref(biggest.path), bytes: biggest.bytes } : null,
      oldestProject: oldest
        ? { repo: ref(oldest.path), lastTouched: new Date(oldest.lastTouched).toISOString() }
        : null,
    };
  }
  return out;
}

/** Every absolute folder the block will reference — the only ones whose remote we look up. */
export function referencedFolders(
  input: Omit<BlockInput, "ref" | "collectedAt" | "machine">,
): string[] {
  const out = new Set<string>();
  for (const r of input.git?.repos ?? []) out.add(r.path);
  for (const r of input.toolchain?.repos ?? []) if (r.drift.length > 0) out.add(r.path);
  for (const r of input.ai?.rows ?? []) if (r.repo !== null) out.add(r.repo);
  for (const p of input.backup?.projects ?? []) out.add(p.path);
  const top = input.activity?.fold.topRepo;
  if (top) out.add(top.repo);
  return [...out].sort();
}

// ---------------------------------------------------------------------------
// Orchestration (the CLI calls this)
// ---------------------------------------------------------------------------

export interface UploadInsightsOptions {
  env: SweepEnv;
  /** The sweep's passive walk observer — present for a full-scope sweep. */
  found?: Discovery;
  device: { deviceId: string; saltHex: string; sharePaths: boolean; shareRepoNames?: boolean };
  now?: number;
  sizeBudgetMs?: number;
  machine?: MachineProbe;
}

export interface UploadInsights {
  insights: InsightsBlock;
  /** Store with `saveUploadCursor` ONLY after the server accepted the upload; null = keep. */
  nextAiCursor: string | null;
}

/** Collect and build the upload block. Never throws for one failing collector. */
export async function collectUploadInsights(opts: UploadInsightsOptions): Promise<UploadInsights> {
  const now = opts.now ?? Date.now();
  const { env, found } = opts;

  let local: Pick<BlockInput, "git" | "disk" | "toolchain" | "backup">;
  if (found) {
    local = await collectInsights(found, ["git", "disk", "toolchain", "backup"], {
      env,
      scope: "full",
      machineWide: false,
      sizeBudgetMs: opts.sizeBudgetMs ?? UPLOAD_SIZE_BUDGET_MS,
      now,
    });
  } else {
    local = { toolchain: await collectToolchain({ env }) };
  }

  // AI: attribute each session's cwd to its repo ROOT (absolute), then send the days since
  // the last successful upload.
  let ai: BlockInput["ai"];
  // null = the AI section failed: leave the cursor where it is.
  let nextAiCursor: string | null = null;
  try {
    const collected = await collectAiUsage({ env, now });
    const shown = repoResolver(env, found ? found.repos() : []);
    const repoOf = (cwd: string | null) => {
      const d = shown(cwd);
      if (d === null) return null;
      return d.startsWith("~/") ? expandPath(d, env) : d;
    };
    const fold = foldUsage(collected.events, { repoOf });
    const sel = selectAiDays(fold.rows, loadUploadCursor(env, opts.device.deviceId), now);
    ai = { rows: sel.rows, pricesAsOf: fold.pricesAsOf };
    nextAiCursor = sel.nextCursor;
  } catch {
    ai = undefined; // the AI section is optional; the rest still goes
  }

  // CLI 0.3 sections. Each is optional and independent: one failing never drops the others.
  const [extras, posture, aiTools, activity] = await Promise.all([
    collectMachineExtras(env).catch(() => ({})),
    collectPosture(env, now).catch(() => undefined),
    collectAiTools(env).catch(() => undefined),
    found ? collectActivity(env, found.repos(), now).catch(() => null) : Promise.resolve(null),
  ]);

  const parts = {
    ...local,
    ai,
    ...(posture ? { posture } : {}),
    ...(aiTools ? { aiTools } : {}),
    ...(activity ? { activity } : {}),
  };
  const folders = referencedFolders(parts);
  const repoRoots = found
    ? folders.filter((f) => found.repoRoots.has(f) || (ai?.rows.some((r) => r.repo === f) ?? false))
    : folders;
  const shareRepoNames = opts.device.shareRepoNames === true;
  // With repo names on, every repo the sweep saw goes into the name directory, so AI days
  // uploaded before sharing was turned on can be named too (ids never change).
  const directory = shareRepoNames
    ? [...new Set([...repoRoots, ...(found ? found.repoRoots : [])])].slice(0, MAX_REPO_NAMES)
    : [];
  const remotes = await collectRemotes(shareRepoNames ? directory : repoRoots, env);
  const ctx: RefContext = {
    env,
    salt: Buffer.from(opts.device.saltHex, "hex"),
    sharePaths: opts.device.sharePaths,
    shareRepoNames,
    remotes,
  };
  const insights = buildInsightsBlock({
    collectedAt: new Date(now).toISOString(),
    machine: { ...machineInfo(env, opts.machine), ...extras },
    ...parts,
    ref: (abs) => makeRepoRef(abs, ctx),
  });
  if (shareRepoNames) {
    const named = directory.map((abs) => makeRepoRef(abs, ctx)).filter((r) => r.name);
    if (named.length > 0) insights.repoNames = named;
  }
  return { insights, nextAiCursor };
}
