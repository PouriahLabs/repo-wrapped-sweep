// Backup coverage (ENDPOINT-MACHINE-INSIGHTS § C2.5, C-8): which project folders would be
// lost with the laptop. A project is synced (inside a cloud-sync root), pushed, partly
// pushed, or local-only; the classification is the shared pure core
// (`@/lib/endpoint/insights/backup`). This module joins the walk's project folders with
// the git collector's per-repo state and measures what is at risk.

import {
  classifyBackup,
  summarizeBackup,
  type BackupClassification,
  type BackupState,
  type BackupSummary,
} from "@/lib/endpoint/insights/backup";
import type { RepoGitState } from "@/lib/endpoint/insights/git-state";
import { isDefaultExcludedDir, isInCloud } from "../locations";
import { normPath, type SweepEnv } from "../env";
import type { Discovery } from "./discover";
import { SIZE_POOL, dirSize, lastTouchedOf } from "./disk";
import { mapPool } from "./run";

export interface BackupProject {
  path: string;
  state: BackupState;
  reason: BackupClassification["reason"];
  atRisk: BackupClassification["atRisk"];
  /** Bytes of source (regenerable folders excluded); measured for unprotected projects only. */
  bytes: number | null;
  partial: boolean;
  lastTouched: number | null;
  /** The repo's state could not be read (git timed out / failed): judged as not-git. */
  gitUnknown?: boolean;
}

export interface BackupCollection {
  projects: BackupProject[];
  summary: BackupSummary;
}

export interface BackupCollectOptions {
  env: SweepEnv;
  /** Git state per repo root (from the git collector); null = git could not answer. */
  gitByRepo: ReadonlyMap<string, RepoGitState | null>;
  budgetMs?: number;
  now?: number;
}

const ORDER: Record<BackupState, number> = {
  "local-only": 0,
  "partly-pushed": 1,
  pushed: 2,
  synced: 3,
};

export async function collectBackup(
  found: Discovery,
  opts: BackupCollectOptions,
): Promise<BackupCollection> {
  const now = opts.now ?? Date.now();
  const deadline = now + (opts.budgetMs ?? 5 * 60_000);
  const classified: BackupProject[] = [];
  for (const p of found.topProjects()) {
    const isRepo = found.repoRoots.has(p.path);
    const git = isRepo ? (opts.gitByRepo.get(p.path) ?? null) : null;
    const c = classifyBackup(
      {
        synced: isInCloud(p.path, opts.env),
        git,
        onlyRegenerable: found.onlyRegenerable(p.path),
      },
      now,
    );
    if (!c) continue;
    classified.push({
      path: p.path,
      state: c.state,
      reason: c.reason,
      atRisk: c.atRisk,
      bytes: null,
      partial: false,
      lastTouched: lastTouchedOf(p.path, git?.lastCommitAt ?? null),
      ...(isRepo && git === null ? { gitUnknown: true } : {}),
    });
  }

  // Measure only what is unprotected — sizing a synced or fully pushed tree buys nothing.
  const regenerable = new Set(found.regenerable().map((d) => normPath(d.path, opts.env.platform)));
  const skip = (abs: string, name: string) =>
    regenerable.has(normPath(abs, opts.env.platform)) ||
    (name !== ".git" && isDefaultExcludedDir(name, normPath(abs, opts.env.platform)));
  const toSize = classified.filter((p) => p.state === "local-only" || p.state === "partly-pushed");
  const sizes = await mapPool(toSize, SIZE_POOL, (p) => dirSize(p.path, { deadline, skip }));
  toSize.forEach((p, i) => {
    p.bytes = sizes[i]!.bytes;
    p.partial = sizes[i]!.partial;
  });

  classified.sort(
    (a, b) =>
      ORDER[a.state] - ORDER[b.state] ||
      (b.lastTouched ?? 0) - (a.lastTouched ?? 0) ||
      a.path.localeCompare(b.path),
  );
  return {
    projects: classified,
    summary: summarizeBackup(
      classified.map((p) => ({ state: p.state, bytes: p.bytes ?? 0, lastTouched: p.lastTouched })),
    ),
  };
}
