// Local git status (ENDPOINT-MACHINE-INSIGHTS § C2.1, C-1): for every clone the walk
// found, the few read-only git commands that say whether work exists only on this
// machine. The parsing and the risk ordering are the shared pure core
// (`@/lib/endpoint/insights/git-state`); this module only runs git.
//
// No network: "behind" is as of the LAST fetch, and `git fetch` runs only with --fetch.
// Every command has its own deadline; a repo whose commands time out or fail is reported
// as unknown, never as clean.

import fs from "node:fs";
import path from "node:path";
import {
  buildRepoGitState,
  classifyRepo,
  parseBranchNames,
  parseStashTimes,
  parseStatusV2,
  summarizeGit,
  type BranchUnpushed,
  type GitSummary,
  type RepoGitState,
  type RepoState,
} from "@/lib/endpoint/insights/git-state";
import type { SweepEnv } from "../env";
import { mapPool, runCommand, type RunFailure, type RunResult } from "./run";

/** Per-command deadline (§ C2.1). */
export const GIT_COMMAND_TIMEOUT_MS = 3_000;
/** `git fetch` gets longer — it is the one command that touches the network (--fetch only). */
export const GIT_FETCH_TIMEOUT_MS = 30_000;
/** Repos examined in parallel (§ C2.1). */
export const GIT_POOL = 4;
/** Branches counted one by one; past this only the de-duplicated total is known. */
export const MAX_BRANCHES_COUNTED = 25;
/** Changed files stat'ed to date the dirty working tree. */
const MAX_DIRTY_STATS = 200;

export interface RepoReport {
  /** Absolute path of the work tree. */
  path: string;
  /** Null when git could not answer (see `failure`). */
  state: RepoGitState | null;
  states: RepoState[];
  risk: number;
  failure?: RunFailure;
  /** Set with --fetch when the fetch itself failed (the status is then as of the previous fetch). */
  fetchFailure?: RunFailure | "error";
}

export interface GitCollectOptions {
  env: SweepEnv;
  /** Run `git fetch --all` first (network). Off by default. */
  fetch?: boolean;
  concurrency?: number;
  timeoutMs?: number;
  now?: number;
}

export interface GitCollection {
  repos: RepoReport[];
  summary: GitSummary;
  /** Repos git could not answer for. */
  unknown: number;
  /** git itself is missing. */
  gitMissing: boolean;
}

const gitEnv = (): NodeJS.ProcessEnv => ({
  ...process.env,
  // Read-only: never take the index lock or refresh the index on disk.
  GIT_OPTIONAL_LOCKS: "0",
  // Never prompt (credentials, ssh host keys) — a prompt would hang until the deadline.
  GIT_TERMINAL_PROMPT: "0",
  GCM_INTERACTIVE: "never",
  LC_ALL: "C",
});

/** A read-only git command in `cwd` (no locks, no prompts, C locale, raw paths). */
export function git(
  env: SweepEnv,
  cwd: string,
  args: string[],
  timeoutMs: number,
  maxBytes?: number,
): Promise<RunResult> {
  return runCommand(env.git?.bin ?? "git", ["-c", "core.quotepath=off", ...args], {
    cwd,
    timeoutMs,
    env: gitEnv(),
    maxBytes,
  });
}

/** stdout of a successful command, or the reason there is none. */
async function out(p: Promise<RunResult>): Promise<string | RunFailure> {
  const r = await p;
  if (!r.ok) return r.failure;
  return r.code === 0 ? r.stdout : "unavailable";
}

const failed = (v: string | RunFailure): v is RunFailure => v === "timeout" || v === "unavailable";

/** Paths of the changed entries in `git status --porcelain=v2` output (rename targets, not origins). */
export function changedPaths(statusOutput: string): string[] {
  const outPaths: string[] = [];
  for (const raw of statusOutput.split("\n")) {
    const line = raw.replace(/\r$/, "");
    const fields = line.split(" ");
    if (line.startsWith("1 ")) outPaths.push(fields.slice(8).join(" "));
    else if (line.startsWith("2 ")) outPaths.push(fields.slice(9).join(" ").split("\t")[0]!);
    else if (line.startsWith("u ")) outPaths.push(fields.slice(10).join(" "));
    else if (line.startsWith("? ")) outPaths.push(line.slice(2));
  }
  return outPaths.filter(Boolean);
}

/** Oldest mtime among the changed files that still exist (a deletion has none). */
function oldestMtime(repo: string, rels: readonly string[]): number | null {
  let oldest: number | null = null;
  for (const rel of rels.slice(0, MAX_DIRTY_STATS)) {
    try {
      const m = fs.statSync(path.join(repo, rel.replace(/\/$/, ""))).mtimeMs;
      if (oldest === null || m < oldest) oldest = m;
    } catch {
      // deleted, or unreadable
    }
  }
  return oldest;
}

/** Collect one repo. Never throws. */
export async function collectRepo(
  repo: string,
  opts: Pick<GitCollectOptions, "env" | "fetch" | "timeoutMs" | "now">,
): Promise<RepoReport> {
  const t = opts.timeoutMs ?? GIT_COMMAND_TIMEOUT_MS;
  const now = opts.now ?? Date.now();
  const report: RepoReport = { path: repo, state: null, states: [], risk: 0 };

  if (opts.fetch) {
    const f = await git(
      opts.env,
      repo,
      ["fetch", "--all", "--quiet", "--no-tags"],
      GIT_FETCH_TIMEOUT_MS,
    );
    if (!f.ok) report.fetchFailure = f.failure;
    else if (f.code !== 0) report.fetchFailure = "error";
  }

  const status = await out(
    git(opts.env, repo, ["status", "--porcelain=v2", "--branch", "--untracked-files=normal"], t),
  );
  if (failed(status)) return { ...report, failure: status };

  const [refs, stashes, last, remotes, total] = await Promise.all([
    out(git(opts.env, repo, ["for-each-ref", "--format=%(refname:short)", "refs/heads"], t)),
    out(git(opts.env, repo, ["stash", "list", "--format=%ct"], t)),
    git(opts.env, repo, ["log", "-1", "--format=%ct"], t),
    out(git(opts.env, repo, ["remote"], t)),
    out(git(opts.env, repo, ["rev-list", "--count", "--branches", "--not", "--remotes"], t)),
  ]);
  if (failed(refs)) return { ...report, failure: refs };
  if (failed(stashes)) return { ...report, failure: stashes };
  if (failed(remotes)) return { ...report, failure: remotes };
  if (!last.ok) return { ...report, failure: last.failure };

  // `git log` exits non-zero in a repo with no commits yet: that is "no commits", not a failure.
  const secs = last.code === 0 ? Number.parseInt(last.stdout.trim(), 10) : Number.NaN;
  const lastCommitAt = Number.isFinite(secs) && secs > 0 ? secs * 1000 : null;

  const branches: BranchUnpushed[] = [];
  for (const name of parseBranchNames(refs).slice(0, MAX_BRANCHES_COUNTED)) {
    // The full ref name: unambiguous against a same-named tag or path.
    const n = await out(
      git(opts.env, repo, ["rev-list", "--count", `refs/heads/${name}`, "--not", "--remotes"], t),
    );
    if (failed(n)) continue;
    branches.push({ name, unpushed: Number.parseInt(n.trim(), 10) || 0 });
  }
  const unpushedTotal = failed(total) ? undefined : Number.parseInt(total.trim(), 10) || 0;

  const summary = parseStatusV2(status);
  const dirtySince = summary.changed > 0 ? oldestMtime(repo, changedPaths(status)) : null;
  const state = buildRepoGitState({
    status: summary,
    stashTimes: parseStashTimes(stashes),
    branches,
    unpushedTotal,
    hasRemote: remotes.trim().length > 0,
    lastCommitAt,
    dirtySince: dirtySince ?? undefined,
  });
  const { states, risk } = classifyRepo(state, now);
  return { ...report, state, states, risk };
}

/**
 * Just the last commit time per repo (`git log -1`) — what `disk` needs to date a project
 * without the full status pass. Null for a repo with no commits or no answer.
 */
export async function collectLastCommits(
  repos: readonly string[],
  opts: Pick<GitCollectOptions, "env" | "concurrency" | "timeoutMs">,
): Promise<Map<string, number | null>> {
  const t = opts.timeoutMs ?? GIT_COMMAND_TIMEOUT_MS;
  const times = await mapPool(repos, opts.concurrency ?? GIT_POOL, async (repo) => {
    const r = await out(git(opts.env, repo, ["log", "-1", "--format=%ct"], t));
    const secs = failed(r) ? Number.NaN : Number.parseInt(r.trim(), 10);
    return Number.isFinite(secs) && secs > 0 ? secs * 1000 : null;
  });
  return new Map(repos.map((r, i) => [r, times[i] ?? null]));
}

/** Collect every repo with a bounded pool; most at-risk first. */
export async function collectGit(
  repos: readonly string[],
  opts: GitCollectOptions,
): Promise<GitCollection> {
  const now = opts.now ?? Date.now();
  if (repos.length > 0) {
    const probe = await runCommand(opts.env.git?.bin ?? "git", ["--version"], {
      timeoutMs: opts.timeoutMs ?? GIT_COMMAND_TIMEOUT_MS,
    });
    if (!probe.ok && probe.failure === "unavailable") {
      return {
        repos: repos.map((p) => ({
          path: p,
          state: null,
          states: [],
          risk: 0,
          failure: "unavailable",
        })),
        summary: summarizeGit([], now),
        unknown: repos.length,
        gitMissing: true,
      };
    }
  }
  const reports = await mapPool(repos, opts.concurrency ?? GIT_POOL, (r) =>
    collectRepo(r, { ...opts, now }),
  );
  reports.sort((a, b) => b.risk - a.risk || a.path.localeCompare(b.path));
  const known = reports.filter((r) => r.state !== null);
  const unknown = reports.length - known.length;
  return {
    repos: reports,
    summary: summarizeGit(
      known.map((r) => r.state!),
      now,
    ),
    unknown,
    gitMissing: false,
  };
}
