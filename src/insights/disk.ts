// Disk reclaim (ENDPOINT-MACHINE-INSIGHTS § C2.2, C-2): how much space regenerable build
// output and caches take, and how much of it sits in projects untouched for 30+ days.
// The classes and the "proving sibling" rule are the shared pure core
// (`@/lib/endpoint/insights/disk-classes`); the walk found the folders (discover.ts);
// this module measures them. READ-ONLY — `disk clean` (clean.ts) is the one that acts.
//
// Sizes are apparent sizes (sum of file lengths) from a `du`-style pass: lstat only,
// never following a link or junction, bounded by an entry cap and a time budget. A
// folder cut short is marked `partial` and its size is a lower bound.

import fs from "node:fs";
import path from "node:path";
import {
  DISK_CLASSES,
  PACKAGE_CACHES,
  isStale,
  isVenvDir,
  type DiskClass,
} from "@/lib/endpoint/insights/disk-classes";
import { isUnder, type SweepEnv } from "../env";
import type { Discovery } from "./discover";
import { mapPool, runCommand } from "./run";

/** Default staleness window (§ C2.2). */
export const STALE_DAYS = 30;
/** Folders measured in parallel. */
export const SIZE_POOL = 4;
/** Entries one folder may cost before its size is reported as a lower bound. */
export const MAX_ENTRIES_PER_DIR = 500_000;

export interface SizeResult {
  bytes: number;
  /** The entry cap or the time budget cut the count short: `bytes` is a lower bound. */
  partial: boolean;
}

export interface SizeBudget {
  /** Epoch ms after which every measurement stops early (partial). */
  deadline: number;
  maxEntries?: number;
  /** Folder paths (exact) not to descend into. */
  skip?: (abs: string, name: string) => boolean;
}

/** Apparent size of a folder tree. Never follows links; unreadable entries are skipped. */
export async function dirSize(root: string, budget: SizeBudget): Promise<SizeResult> {
  const max = budget.maxEntries ?? MAX_ENTRIES_PER_DIR;
  let bytes = 0;
  let entries = 0;
  const stack = [root];
  while (stack.length > 0) {
    if (entries >= max || Date.now() > budget.deadline) return { bytes, partial: true };
    const dir = stack.pop()!;
    let handle: fs.Dir;
    try {
      handle = await fs.promises.opendir(dir);
    } catch {
      continue;
    }
    try {
      for await (const e of handle) {
        entries++;
        if (e.isSymbolicLink()) continue;
        const abs = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (!budget.skip?.(abs, e.name)) stack.push(abs);
          continue;
        }
        try {
          const st = await fs.promises.lstat(abs);
          if (st.isFile()) bytes += st.size;
          else if (st.isDirectory() && !budget.skip?.(abs, e.name)) stack.push(abs);
        } catch {
          // vanished or unreadable
        }
      }
    } catch {
      // permission denied part-way
    } finally {
      await handle.close().catch(() => {});
    }
  }
  return { bytes, partial: false };
}

/**
 * When was a project last touched? The newest of: the last commit of the repo it sits in,
 * and the mtime of its top-level files. (Deep source edits that are not yet committed are
 * not seen — the git collector's dirty state covers those.)
 */
export function lastTouchedOf(dir: string, lastCommitAt: number | null): number | null {
  let newest = lastCommitAt;
  try {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!e.isFile()) continue;
      try {
        const m = fs.lstatSync(path.join(dir, e.name)).mtimeMs;
        if (newest === null || m > newest) newest = m;
      } catch {
        // skip
      }
    }
  } catch {
    // unreadable folder
  }
  return newest;
}

export interface DiskFolder {
  path: string;
  cls: DiskClass;
  project: string;
  bytes: number;
  partial: boolean;
  lastTouched: number | null;
  stale: boolean;
  /** `.venv`: reported, but only ever cleaned with an explicit opt-in. */
  venv: boolean;
}

export interface PackageCacheReport {
  tool: string;
  label: string;
  path: string;
  bytes: number;
  partial: boolean;
}

export interface DiskCollection {
  folders: DiskFolder[];
  /** `dist/` and `out/` — reported by size, never a cleanup class. */
  reportOnly: Array<{ path: string; project: string; bytes: number; partial: boolean }>;
  packageCaches: PackageCacheReport[];
  /** `docker system df` total, when Docker answered; reported only, never cleaned. */
  dockerBytes: number | null;
  totals: {
    reclaimableBytes: number;
    staleReclaimableBytes: number;
    staleProjects: number;
    projects: number;
    byClass: Partial<Record<DiskClass, number>>;
  };
  /** Some measurement hit the cap or the time budget. */
  partial: boolean;
  staleDays: number;
}

export interface DiskCollectOptions {
  env: SweepEnv;
  /** Last commit time per repo root (from the git collector), when known. */
  lastCommitByRepo?: ReadonlyMap<string, number | null>;
  /** Measure the machine-wide package caches and Docker too (a home-directory run). */
  machineWide?: boolean;
  /** Time budget for all measurements together. */
  budgetMs?: number;
  staleDays?: number;
  now?: number;
}

/** The repo root `dir` sits in, if any (nearest ancestor-or-self). */
function nearestRepo(
  dir: string,
  repos: ReadonlyMap<string, number | null>,
  env: SweepEnv,
): string | null {
  let best: string | null = null;
  for (const r of repos.keys()) {
    if (isUnder(dir, r, env.platform) && (best === null || r.length > best.length)) best = r;
  }
  return best;
}

/** Parse a Docker size (`1.2GB`, `512.3MB`, `0B`, `12kB`) to bytes; null when unreadable. */
export function parseDockerSize(s: string): number | null {
  const m = /^([\d.]+)\s*([kKMGT]?i?B)$/.exec(s.trim());
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n)) return null;
  const unit = m[2]!.toUpperCase().replace("I", "");
  const mult = { B: 1, KB: 1e3, MB: 1e6, GB: 1e9, TB: 1e12 }[unit] ?? null;
  return mult === null ? null : Math.round(n * mult);
}

/** `docker system df` total, or null when Docker is absent, stopped or slow. */
export async function dockerTotal(timeoutMs = 5_000): Promise<number | null> {
  const r = await runCommand("docker", ["system", "df", "--format", "{{.Size}}"], { timeoutMs });
  if (!r.ok || r.code !== 0) return null;
  let total = 0;
  let any = false;
  for (const line of r.stdout.split("\n")) {
    const n = parseDockerSize(line);
    if (n !== null) {
      total += n;
      any = true;
    }
  }
  return any ? total : null;
}

export async function collectDisk(
  found: Discovery,
  opts: DiskCollectOptions,
): Promise<DiskCollection> {
  const now = opts.now ?? Date.now();
  const staleDays = opts.staleDays ?? STALE_DAYS;
  const deadline = now + (opts.budgetMs ?? 5 * 60_000);
  const repos = opts.lastCommitByRepo ?? new Map<string, number | null>();

  const touched = new Map<string, number | null>();
  const touchedOf = (project: string) => {
    if (!touched.has(project)) {
      const repo = nearestRepo(project, repos, opts.env);
      touched.set(project, lastTouchedOf(project, repo ? (repos.get(repo) ?? null) : null));
    }
    return touched.get(project) ?? null;
  };

  const classDirs = found.regenerable();
  const sized = await mapPool(classDirs, SIZE_POOL, (d) => dirSize(d.path, { deadline }));
  const folders: DiskFolder[] = classDirs.map((d, i) => {
    const lastTouched = touchedOf(d.project);
    return {
      path: d.path,
      cls: d.cls,
      project: d.project,
      bytes: sized[i]!.bytes,
      partial: sized[i]!.partial,
      lastTouched,
      stale: isStale(lastTouched, now, staleDays),
      venv: isVenvDir(path.basename(d.path)),
    };
  });
  folders.sort((a, b) => b.bytes - a.bytes || a.path.localeCompare(b.path));

  const reportSized = await mapPool(found.reportOnly, SIZE_POOL, (d) =>
    dirSize(d.path, { deadline }),
  );
  const reportOnly = found.reportOnly
    .map((d, i) => ({ ...d, bytes: reportSized[i]!.bytes, partial: reportSized[i]!.partial }))
    .sort((a, b) => b.bytes - a.bytes);

  const packageCaches: PackageCacheReport[] = [];
  let dockerBytes: number | null = null;
  if (opts.machineWide) {
    for (const spec of PACKAGE_CACHES) {
      for (const rel of spec.homeRelative) {
        const abs = path.join(opts.env.home, ...rel.split("/"));
        try {
          if (!fs.lstatSync(abs).isDirectory()) continue;
        } catch {
          continue;
        }
        const s = await dirSize(abs, { deadline });
        packageCaches.push({ tool: spec.tool, label: spec.label, path: abs, ...s });
      }
    }
    packageCaches.sort((a, b) => b.bytes - a.bytes);
    dockerBytes = await dockerTotal();
  }

  const byClass: Partial<Record<DiskClass, number>> = {};
  const projects = new Set<string>();
  const staleProjects = new Set<string>();
  let reclaimableBytes = 0;
  let staleReclaimableBytes = 0;
  for (const f of folders) {
    byClass[f.cls] = (byClass[f.cls] ?? 0) + f.bytes;
    reclaimableBytes += f.bytes;
    projects.add(f.project);
    if (f.stale) {
      staleReclaimableBytes += f.bytes;
      staleProjects.add(f.project);
    }
  }
  const cacheBytes = packageCaches.reduce((n, c) => n + c.bytes, 0);
  if (cacheBytes > 0) {
    byClass["package-cache"] = cacheBytes;
    reclaimableBytes += cacheBytes;
  }
  if (dockerBytes !== null) byClass.docker = dockerBytes;

  return {
    folders,
    reportOnly,
    packageCaches,
    dockerBytes,
    totals: {
      reclaimableBytes,
      staleReclaimableBytes,
      staleProjects: staleProjects.size,
      projects: projects.size,
      byClass: Object.fromEntries(
        DISK_CLASSES.filter((c) => byClass[c] !== undefined).map((c) => [c, byClass[c]]),
      ) as Partial<Record<DiskClass, number>>,
    },
    partial:
      folders.some((f) => f.partial) ||
      reportOnly.some((r) => r.partial) ||
      packageCaches.some((c) => c.partial),
    staleDays,
  };
}

export function formatBytes(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB`;
  if (n >= 1e3) return `${Math.round(n / 1e3)} KB`;
  return `${n} B`;
}

/** `reclaim 38.2 GB from 41 projects untouched for 30+ days (52.0 GB regenerable in total)` */
export function describeDisk(d: DiskCollection): string {
  const t = d.totals;
  const approx = d.partial ? "at least " : "";
  if (t.reclaimableBytes === 0) return "No regenerable build output or caches found";
  const total = `${approx}${formatBytes(t.reclaimableBytes)} regenerable in total`;
  if (t.staleProjects === 0) {
    return `${total}; no project with build output has been untouched for ${d.staleDays}+ days`;
  }
  return (
    `reclaim ${approx}${formatBytes(t.staleReclaimableBytes)} from ${t.staleProjects} ` +
    `project${t.staleProjects === 1 ? "" : "s"} untouched for ${d.staleDays}+ days (${total})`
  );
}
