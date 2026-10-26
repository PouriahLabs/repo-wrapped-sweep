// Local git state for Machine Insights (ENDPOINT-MACHINE-INSIGHTS § C2.1) —
// PURE: no fs, no child_process, no clock (every function that needs "now" takes it).
//
// The CLI collector runs the `git` commands; this module turns their STDOUT into a
// RepoGitState and decides which `RepoState`s apply and how risky the repo is.
// Parsers take the raw text so the shapes are unit-tested without a git binary:
//   - `git status --porcelain=v2 --branch --untracked-files=normal`  → parseStatusV2
//   - `git for-each-ref --format=%(refname:short) refs/heads`        → parseBranchNames
//   - `git stash list --format=%ct`                                  → parseStashTimes
//
// All timestamps here are epoch MILLISECONDS (`%ct` is seconds; the parser converts).
// Nothing in a state is a path, a commit message or a file name — counts and times only.

const DAY_MS = 86_400_000;

export const REPO_STATES = [
  "clean",
  "uncommitted",
  "unpushed",
  "no-remote",
  "stale-stash",
  "behind",
] as const;
export type RepoState = (typeof REPO_STATES)[number];

/** Uncommitted work older than this counts toward the risk score (§ C2.1). */
export const UNCOMMITTED_STALE_DAYS = 7;
/** A stash older than this is "stale". */
export const STASH_STALE_DAYS = 30;
/** Behind its upstream by MORE than this flags `behind`. */
export const BEHIND_THRESHOLD = 50;

// --- parsers ------------------------------------------------------------------------

export interface StatusSummary {
  /** null when HEAD is detached. */
  branch: string | null;
  upstream: string | null;
  ahead: number;
  behind: number;
  /** Entries with a change staged in the index. */
  staged: number;
  /** Entries with a change in the working tree (includes deletions). */
  modified: number;
  untracked: number;
  /** Unmerged (mid-merge / mid-rebase) entries. */
  conflicted: number;
  /** Distinct changed entries — a file both staged and modified counts once. */
  changed: number;
}

const toCount = (s: string | undefined): number => {
  const n = Number.parseInt(s ?? "", 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
};

/**
 * Parse `git status --porcelain=v2 --branch` output. Header lines are `# branch.head`,
 * `# branch.upstream`, `# branch.ab +A -B`; entries start `1`/`2` (changed, renamed),
 * `u` (unmerged) or `?` (untracked). Ignored (`!`) entries and unknown lines are skipped.
 */
export function parseStatusV2(output: string): StatusSummary {
  const s: StatusSummary = {
    branch: null,
    upstream: null,
    ahead: 0,
    behind: 0,
    staged: 0,
    modified: 0,
    untracked: 0,
    conflicted: 0,
    changed: 0,
  };
  for (const raw of output.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (line.startsWith("# branch.head ")) {
      const head = line.slice("# branch.head ".length).trim();
      s.branch = head === "(detached)" || head === "" ? null : head;
    } else if (line.startsWith("# branch.upstream ")) {
      s.upstream = line.slice("# branch.upstream ".length).trim() || null;
    } else if (line.startsWith("# branch.ab ")) {
      const m = /^\+(\d+) -(\d+)$/.exec(line.slice("# branch.ab ".length).trim());
      if (m) {
        s.ahead = toCount(m[1]);
        s.behind = toCount(m[2]);
      }
    } else if (line.startsWith("1 ") || line.startsWith("2 ")) {
      const xy = line.slice(2, 4);
      if (xy[0] !== ".") s.staged++;
      if (xy[1] !== ".") s.modified++;
      s.changed++;
    } else if (line.startsWith("u ")) {
      s.conflicted++;
      s.changed++;
    } else if (line.startsWith("? ")) {
      s.untracked++;
      s.changed++;
    }
  }
  return s;
}

/** `git for-each-ref --format=%(refname:short) refs/heads` → branch names. */
export function parseBranchNames(output: string): string[] {
  return output
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
}

/** `git stash list --format=%ct` (unix seconds, one per stash) → epoch ms, newest first as git prints. */
export function parseStashTimes(output: string): number[] {
  const out: number[] = [];
  for (const raw of output.split("\n")) {
    const secs = Number.parseInt(raw.trim(), 10);
    if (Number.isFinite(secs) && secs > 0) out.push(secs * 1000);
  }
  return out;
}

// --- state --------------------------------------------------------------------------

/** One local branch and how many of its commits exist on NO remote (`rev-list --count <b> --not --remotes`). */
export interface BranchUnpushed {
  name: string;
  unpushed: number;
}

export interface RepoGitInput {
  status: StatusSummary;
  /** `parseStashTimes` output. */
  stashTimes: readonly number[];
  /** One entry per local branch. */
  branches: readonly BranchUnpushed[];
  /**
   * `git rev-list --count --branches --not --remotes` — the de-duplicated total. Per-branch
   * counts double-count commits two branches share, so prefer this when the collector has it.
   */
  unpushedTotal?: number;
  /** `git remote` printed at least one remote. */
  hasRemote: boolean;
  /** `git log -1 --format=%ct` in ms; null when the repo has no commits. */
  lastCommitAt: number | null;
  /** Oldest mtime among the changed files, when the collector measured it; defaults to `lastCommitAt`. */
  dirtySince?: number | null;
}

export interface RepoGitState {
  branch: string | null;
  upstream: string | null;
  ahead: number;
  behind: number;
  staged: number;
  modified: number;
  untracked: number;
  conflicted: number;
  changed: number;
  stashTimes: number[];
  /** Branches with commits on no remote, most first. */
  unpushedBranches: BranchUnpushed[];
  /** Commits on no remote. For a repo with no remote at all this is every commit — see `classifyRepo`. */
  unpushedCommits: number;
  hasRemote: boolean;
  lastCommitAt: number | null;
  dirtySince: number | null;
}

export function buildRepoGitState(input: RepoGitInput): RepoGitState {
  const unpushedBranches = input.branches
    .filter((b) => b.unpushed > 0)
    .map((b) => ({ name: b.name, unpushed: b.unpushed }))
    .sort((a, b) => b.unpushed - a.unpushed || a.name.localeCompare(b.name));
  // No branch list at all (a collector failure) → the upstream's `ahead` is the best we have.
  const unpushedCommits =
    input.unpushedTotal ??
    (input.branches.length > 0
      ? unpushedBranches.reduce((n, b) => n + b.unpushed, 0)
      : input.status.ahead);
  return {
    branch: input.status.branch,
    upstream: input.status.upstream,
    ahead: input.status.ahead,
    behind: input.status.behind,
    staged: input.status.staged,
    modified: input.status.modified,
    untracked: input.status.untracked,
    conflicted: input.status.conflicted,
    changed: input.status.changed,
    stashTimes: [...input.stashTimes],
    unpushedBranches,
    unpushedCommits,
    hasRemote: input.hasRemote,
    lastCommitAt: input.lastCommitAt,
    dirtySince: input.dirtySince ?? input.lastCommitAt,
  };
}

/** How long the working tree has been dirty, in whole days; null when it is clean or the age is unknown. */
export function uncommittedAgeDays(s: RepoGitState, now: number): number | null {
  if (s.changed === 0 || s.dirtySince === null) return null;
  return Math.max(0, Math.floor((now - s.dirtySince) / DAY_MS));
}

/** Stashes older than `STASH_STALE_DAYS`. */
export function staleStashCount(s: RepoGitState, now: number): number {
  return s.stashTimes.filter((t) => now - t > STASH_STALE_DAYS * DAY_MS).length;
}

export interface RepoClassification {
  /** In `REPO_STATES` order; `["clean"]` when nothing applies. */
  states: RepoState[];
  /** Sort key, higher = more at risk. See `classifyRepo`. */
  risk: number;
}

/** One lexicographic digit of the risk score: 0 when absent, 100..199 when present (+count, capped). */
const digit = (on: boolean, n = 0): number => (on ? 100 + Math.min(Math.max(n, 0), 99) : 0);
const RADIX = 200;

/**
 * Which `RepoState`s apply and how risky the repo is (§ C2.1).
 *
 *   unpushed     has a remote, and commits that are on none of them
 *   no-remote    has commits, but no remote at all
 *   uncommitted  a dirty working tree
 *   stale-stash  a stash older than 30 days
 *   behind       more than 50 commits behind its upstream (as of the last fetch)
 *
 * `risk` orders the repos exactly as the spec does — unpushed commits > no remote with
 * commits > uncommitted older than 7 days > stashes older than 30 days > behind by > 50 —
 * as a lexicographic tuple (each tier is one base-200 digit, so no pile of lower-tier
 * signals can outrank a single higher-tier one). Within a tier a larger count ranks higher.
 * A fresh dirty tree and a recent stash are listed as states but score 0: they are not at
 * risk yet.
 */
export function classifyRepo(s: RepoGitState, now: number): RepoClassification {
  const unpushed = s.hasRemote && s.unpushedCommits > 0;
  const noRemote = !s.hasRemote && s.lastCommitAt !== null;
  const uncommitted = s.changed > 0;
  const staleStashes = staleStashCount(s, now);
  const behind = s.behind > BEHIND_THRESHOLD;

  const states: RepoState[] = [];
  if (uncommitted) states.push("uncommitted");
  if (unpushed) states.push("unpushed");
  if (noRemote) states.push("no-remote");
  if (staleStashes > 0) states.push("stale-stash");
  if (behind) states.push("behind");
  if (states.length === 0) states.push("clean");

  const dirtyDays = uncommittedAgeDays(s, now);
  const staleDirty = dirtyDays !== null && dirtyDays >= UNCOMMITTED_STALE_DAYS;
  const risk =
    digit(unpushed, s.unpushedCommits) * RADIX ** 4 +
    digit(noRemote) * RADIX ** 3 +
    digit(staleDirty, dirtyDays ?? 0) * RADIX ** 2 +
    digit(staleStashes > 0, staleStashes) * RADIX +
    digit(behind, s.behind);
  return { states, risk };
}

// --- roll-up ------------------------------------------------------------------------

export interface GitSummary {
  repos: number;
  byState: Partial<Record<RepoState, number>>;
  /** Repos holding work that exists only on this machine: unpushed, no remote, dirty, or stashed for 30+ days. */
  localOnlyRepos: number;
  /** Commits on no remote, across repos that HAVE a remote (a remote-less repo's "all commits" would swamp it). */
  unpushedCommits: number;
  /** Every stash, stale or not — all of them live only here. */
  stashes: number;
  staleStashes: number;
}

export function summarizeGit(repos: readonly RepoGitState[], now: number): GitSummary {
  const out: GitSummary = {
    repos: repos.length,
    byState: {},
    localOnlyRepos: 0,
    unpushedCommits: 0,
    stashes: 0,
    staleStashes: 0,
  };
  for (const r of repos) {
    const { states } = classifyRepo(r, now);
    for (const st of states) out.byState[st] = (out.byState[st] ?? 0) + 1;
    if (states.some((st) => st !== "clean" && st !== "behind")) out.localOnlyRepos++;
    if (r.hasRemote) out.unpushedCommits += r.unpushedCommits;
    out.stashes += r.stashTimes.length;
    out.staleStashes += staleStashCount(r, now);
  }
  return out;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** `3 repos have work that exists only on this machine (14 commits, 2 stashes)` */
export function describeGitSummary(s: GitSummary): string {
  if (s.localOnlyRepos === 0) return "No repos have work that exists only on this machine";
  const parts: string[] = [];
  if (s.unpushedCommits > 0) parts.push(plural(s.unpushedCommits, "commit"));
  if (s.stashes > 0) parts.push(plural(s.stashes, "stash", "stashes"));
  const verb = s.localOnlyRepos === 1 ? "has" : "have";
  const detail = parts.length > 0 ? ` (${parts.join(", ")})` : "";
  return `${plural(s.localOnlyRepos, "repo")} ${verb} work that exists only on this machine${detail}`;
}
