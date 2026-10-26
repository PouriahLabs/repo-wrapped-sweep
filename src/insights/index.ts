// Machine Insights orchestration (ENDPOINT-MACHINE-INSIGHTS § C2): run the requested
// collectors over one Discovery. Local only — nothing here uploads, and nothing here
// touches the network unless `fetch` is set.

import type { SweepEnv } from "../env";
import { collectBackup, type BackupCollection } from "./backup";
import type { Discovery } from "./discover";
import { collectDisk, type DiskCollection } from "./disk";
import { collectGit, collectLastCommits, type GitCollection } from "./git";
import { collectToolchain, type ToolchainCollection } from "./toolchain";

export const INSIGHT_SECTIONS = ["git", "disk", "toolchain", "backup"] as const;
export type InsightSection = (typeof INSIGHT_SECTIONS)[number];

export interface InsightsResult {
  collectedAt: string;
  /** `full` = the home directory; `paths` = explicit --root folders. */
  scope: "full" | "paths";
  git?: GitCollection;
  /** True when --fetch ran `git fetch` first. */
  fetched?: boolean;
  disk?: DiskCollection;
  toolchain?: ToolchainCollection;
  backup?: BackupCollection;
}

export interface CollectOptions {
  env: SweepEnv;
  scope: "full" | "paths";
  fetch?: boolean;
  /** Measure package caches and Docker (default: on for a full-scope run). */
  machineWide?: boolean;
  /** Time budget for folder sizing (disk + backup each). */
  sizeBudgetMs?: number;
  now?: number;
}

export async function collectInsights(
  found: Discovery,
  sections: readonly InsightSection[],
  opts: CollectOptions,
): Promise<InsightsResult> {
  const now = opts.now ?? Date.now();
  const want = new Set(sections);
  const result: InsightsResult = { collectedAt: new Date(now).toISOString(), scope: opts.scope };
  const repos = found.repos();

  // Backup needs every repo's full state; git is reported when asked for, or reused.
  if (want.has("git") || want.has("backup")) {
    result.git = await collectGit(repos, { env: opts.env, fetch: opts.fetch, now });
    if (opts.fetch) result.fetched = true;
  }
  const lastCommits = result.git
    ? new Map(result.git.repos.map((r) => [r.path, r.state?.lastCommitAt ?? null]))
    : want.has("disk")
      ? await collectLastCommits(repos, { env: opts.env })
      : new Map<string, number | null>();

  if (want.has("disk")) {
    result.disk = await collectDisk(found, {
      env: opts.env,
      lastCommitByRepo: lastCommits,
      machineWide: opts.machineWide ?? opts.scope === "full",
      budgetMs: opts.sizeBudgetMs,
      now,
    });
  }
  if (want.has("toolchain")) {
    const folders = [...new Set([...found.topProjects().map((p) => p.path), ...repos])]
      .sort()
      .map((p) => ({ path: p, pinFiles: found.pinFilesIn(p) }));
    result.toolchain = await collectToolchain({ env: opts.env, folders });
  }
  if (want.has("backup")) {
    result.backup = await collectBackup(found, {
      env: opts.env,
      gitByRepo: new Map(result.git!.repos.map((r) => [r.path, r.state])),
      budgetMs: opts.sizeBudgetMs,
      now,
    });
  }
  if (!want.has("git")) delete result.git;
  return result;
}
