// Backup coverage for Machine Insights (ENDPOINT-MACHINE-INSIGHTS § C2.5) — PURE: the
// collector finds project folders and measures them; this module classifies each one.
//
//   synced         inside a cloud-synced root (OneDrive / iCloud / Dropbox…), git or not
//   pushed         a git repo with a remote, and nothing at risk
//   partly-pushed  a git repo with a remote, but unpushed commits, or uncommitted changes older
//                  than 7 days — `atRisk` says what would be lost
//   local-only     no remote (or not a git repo at all) and not synced — the headline
//
// A folder whose only content is regenerable (C2.2 classes) isn't a project worth backing up
// and classifies to null. "Not nested inside another project" and "not under the default
// excludes" are discovery rules for the collector, not decided here.

import {
  UNCOMMITTED_STALE_DAYS,
  uncommittedAgeDays,
  type RepoGitState,
} from "@/lib/endpoint/insights/git-state";

export const BACKUP_STATES = ["synced", "pushed", "partly-pushed", "local-only"] as const;
export type BackupState = (typeof BACKUP_STATES)[number];

/** File names that mark a directory as a project. `*.sln` and `build.gradle*` are matched in `isProjectMarker`. */
export const PROJECT_MARKERS: readonly string[] = [
  "package.json",
  "pyproject.toml",
  "Cargo.toml",
  "go.mod",
  "pom.xml",
  ".git",
];

/** Is this directory entry a project marker (`package.json`, `*.sln`, `build.gradle*`, `.git`, …)? */
export function isProjectMarker(name: string): boolean {
  return PROJECT_MARKERS.includes(name) || name.endsWith(".sln") || name.startsWith("build.gradle");
}

export interface BackupProjectInput {
  /** Inside a cloud-synced root (from the walker). */
  synced: boolean;
  /** null when the folder is not a git repo. */
  git: RepoGitState | null;
  /** Everything in the folder is regenerable build output or caches. */
  onlyRegenerable?: boolean;
}

export interface BackupRisk {
  unpushedCommits: number;
  /** Branches with commits on no remote. */
  unpushedBranches: string[];
  /** Whole days the working tree has been dirty, when that is 7+ days. */
  uncommittedDays: number | null;
}

export interface BackupClassification {
  state: BackupState;
  /** Why it's local-only; null otherwise. */
  reason: "no-remote" | "not-git" | null;
  /** What's unprotected. Zeroed for `synced` and `pushed`; for `local-only` it still carries the local numbers. */
  atRisk: BackupRisk;
}

export function classifyBackup(p: BackupProjectInput, now: number): BackupClassification | null {
  if (p.onlyRegenerable) return null;

  const days = p.git ? uncommittedAgeDays(p.git, now) : null;
  const staleDirty = days !== null && days >= UNCOMMITTED_STALE_DAYS;
  const atRisk: BackupRisk = {
    unpushedCommits: p.git?.unpushedCommits ?? 0,
    unpushedBranches: p.git?.unpushedBranches.map((b) => b.name) ?? [],
    uncommittedDays: staleDirty ? days : null,
  };
  const none: BackupRisk = { unpushedCommits: 0, unpushedBranches: [], uncommittedDays: null };

  if (p.synced) return { state: "synced", reason: null, atRisk: none };
  if (!p.git) return { state: "local-only", reason: "not-git", atRisk };
  if (!p.git.hasRemote) return { state: "local-only", reason: "no-remote", atRisk };

  const exposed = atRisk.unpushedCommits > 0 || staleDirty;
  return exposed
    ? { state: "partly-pushed", reason: null, atRisk }
    : { state: "pushed", reason: null, atRisk: none };
}

// --- roll-up ------------------------------------------------------------------------------

export interface BackupSummary {
  projects: number;
  byState: Partial<Record<BackupState, number>>;
  localOnlyBytes: number;
  /** Newest `lastTouched` among the local-only projects (epoch ms), or null. */
  localOnlyNewestTouched: number | null;
}

export interface BackupSummaryItem {
  state: BackupState;
  bytes: number;
  lastTouched: number | null;
}

export function summarizeBackup(items: readonly BackupSummaryItem[]): BackupSummary {
  const out: BackupSummary = {
    projects: items.length,
    byState: {},
    localOnlyBytes: 0,
    localOnlyNewestTouched: null,
  };
  for (const it of items) {
    out.byState[it.state] = (out.byState[it.state] ?? 0) + 1;
    if (it.state !== "local-only") continue;
    out.localOnlyBytes += it.bytes;
    if (it.lastTouched !== null) {
      out.localOnlyNewestTouched = Math.max(out.localOnlyNewestTouched ?? 0, it.lastTouched);
    }
  }
  return out;
}

const DAY_MS = 86_400_000;

function formatBytes(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB`;
  if (n >= 1e3) return `${Math.round(n / 1e3)} KB`;
  return `${n} B`;
}

/** `5 projects exist only on this machine (1.2 GB of source, newest touched 2 days ago)` */
export function describeBackupSummary(s: BackupSummary, now: number): string {
  const n = s.byState["local-only"] ?? 0;
  if (n === 0) return "Every project is synced or pushed";
  const parts = [`${formatBytes(s.localOnlyBytes)} of source`];
  if (s.localOnlyNewestTouched !== null) {
    const d = Math.max(0, Math.floor((now - s.localOnlyNewestTouched) / DAY_MS));
    parts.push(`newest touched ${d === 0 ? "today" : `${d} ${d === 1 ? "day" : "days"} ago`}`);
  }
  return `${n} ${n === 1 ? "project exists" : "projects exist"} only on this machine (${parts.join(", ")})`;
}
