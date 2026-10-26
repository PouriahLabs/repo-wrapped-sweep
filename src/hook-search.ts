// Directory-search guard for the agent hook (§ A7). A recursive `grep`/`rg`/
// `Grep` over a directory reads every file in it, so a single `.env` three levels
// down defeats a per-path check. This finds the credential files such a search
// would read, with a BOUNDED walk:
//
//   - depth ≤ 4 below the searched directory, ≤ 2,000 directory entries;
//   - the same excludes as the sweep walker (node_modules, caches, nested
//     cloud-sync roots, `sweep.json` excludes), and links are never followed;
//   - if the entry bound is hit the result falls back to the baseline's recorded
//     locations only — deterministic, and never worse than the pre-walk guard.
//
// SCOPE. The guard blocks a search only if it would actually read a flagged file
// under the tool's OWN default filtering. ripgrep (the `Grep` tool, `rg`) skips
// hidden files and files its ignore files list, so those are out of scope — unless
// the call opts in (`--hidden`, `-u`/`-uu`, `--no-ignore*`) or an explicit glob
// names the file. `grep -r`, `findstr /s` and PowerShell filter nothing. Ignore
// status is decided for the FLAGGED candidates only: `.ignore`/`.rgignore` by a
// simple glob match, `.gitignore` by ONE `git check-ignore` spawn (inside a work
// tree); if git is missing, slow (> 30 ms) or errors, the file stays in scope.
//
// The call's own filters (a `--glob`, `--include`, a `type`) are applied to each
// candidate: a search that provably cannot read any flagged file is allowed.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { isUnder, normPath, type SweepEnv } from "./env";
import { expandBraces, type SearchRequest } from "./hook-shell";
import { compileGlob, isCloudRoot, isDefaultExcludedDir } from "./locations";

export const SEARCH_MAX_DEPTH = 4;
export const SEARCH_MAX_ENTRIES = 2000;

export interface FlaggedFile {
  path: string;
  reason: string;
}

export interface SearchResult {
  flagged: FlaggedFile[];
  /** The entry bound was hit; only baseline locations were considered. */
  truncated: boolean;
  /** Set when git could not confirm .gitignore status, so flagged files stayed in scope. */
  gitFailure?: GitFailure;
}

/** Why the .gitignore check gave no answer. */
export type GitFailure = "timeout" | "unavailable";

export interface SearchDeps {
  env: SweepEnv;
  /** Original-case absolute paths a previous sweep found secrets in. */
  baselineAbs: readonly string[];
  /** `sweep.json` `exclude` globs, compiled (the walker's user excludes). */
  userExclude: readonly RegExp[];
  /** `hookAllow` globs, compiled. */
  allow: readonly RegExp[];
  /** Why this file must not be read (name rules / 4 KB probe), or null. */
  blockReason(abs: string): string | null;
}

export function isDirectory(abs: string): boolean {
  try {
    return fs.statSync(abs).isDirectory();
  } catch {
    return false;
  }
}

export function isFile(abs: string): boolean {
  try {
    return fs.statSync(abs).isFile();
  } catch {
    return false;
  }
}

// --- filters ----------------------------------------------------------------

/** File types of the common ripgrep `--type` names (extensions, lowercase). */
const TYPE_EXTENSIONS: Record<string, readonly string[]> = {
  js: ["js", "jsx", "mjs", "cjs"],
  ts: ["ts", "tsx", "mts", "cts"],
  py: ["py", "pyi"],
  python: ["py", "pyi"],
  rust: ["rs"],
  rs: ["rs"],
  go: ["go"],
  java: ["java"],
  kotlin: ["kt", "kts"],
  swift: ["swift"],
  c: ["c", "h"],
  cpp: ["cpp", "cc", "cxx", "hpp", "hh", "h"],
  cs: ["cs"],
  csharp: ["cs"],
  ruby: ["rb"],
  rb: ["rb"],
  php: ["php"],
  sh: ["sh", "bash", "zsh"],
  md: ["md", "markdown"],
  markdown: ["md", "markdown"],
  json: ["json"],
  yaml: ["yaml", "yml"],
  yml: ["yaml", "yml"],
  toml: ["toml"],
  html: ["html", "htm"],
  css: ["css", "scss", "sass", "less"],
  sql: ["sql"],
  xml: ["xml"],
  txt: ["txt"],
  vue: ["vue"],
  svelte: ["svelte"],
  dart: ["dart"],
  lua: ["lua"],
  scala: ["scala"],
  elixir: ["ex", "exs"],
};

const extOf = (base: string) =>
  (base.includes(".") ? base.slice(base.lastIndexOf(".") + 1) : "").toLowerCase();

const stripLead = (g: string) => g.replace(/^\.?[\\/]+/, "");

/**
 * Build the "provably excluded" predicate for a request's own filters. `true`
 * means the search cannot read that file, so it need not be flagged. Anything the
 * engine is unsure of (an unknown `--type`) is NOT treated as an exclusion.
 *
 * Positive globs match case-insensitively (more matches = fewer exclusions) and
 * negative globs case-sensitively, so neither direction can over-allow.
 */
export function makeFilter(req: SearchRequest): (rel: string) => boolean {
  const positive = req.include.flatMap((g) => expandBraces(stripLead(g))).map(compileGlob);
  const negative = req.exclude
    .flatMap((g) => expandBraces(stripLead(g)))
    .map((g) => new RegExp(compileGlob(g).source));

  const wanted = req.types.map((t) => TYPE_EXTENSIONS[t.toLowerCase()]);
  const wantedAllKnown = wanted.length > 0 && wanted.every((e) => e !== undefined);
  const wantedExts = new Set(wanted.flatMap((e) => e ?? []));
  const unwantedExts = new Set(req.typesNot.flatMap((t) => TYPE_EXTENSIONS[t.toLowerCase()] ?? []));

  return (rel) => {
    const base = rel.slice(rel.lastIndexOf("/") + 1);
    const ext = extOf(base);
    if (wantedAllKnown && !wantedExts.has(ext)) return true;
    if (unwantedExts.has(ext)) return true;
    if (positive.length > 0 && !positive.some((re) => re.test(rel))) return true;
    return negative.some((re) => re.test(rel));
  };
}

// --- scope: what the tool would actually search -------------------------------

/**
 * Does an explicit positive glob (`rg -g '*.local'`, the Grep tool's `glob`) name
 * this file? ripgrep treats such a glob as a whitelist that beats both the hidden
 * filter and ignore files, so a match brings the file back into scope.
 */
export function makeWhitelist(req: SearchRequest): (rel: string) => boolean {
  const positive = req.include.flatMap((g) => expandBraces(stripLead(g))).map(compileGlob);
  return (rel) => positive.length > 0 && positive.some((re) => re.test(rel));
}

const hasHiddenSegment = (rel: string) => rel.split("/").some((s) => s.startsWith("."));

// .ignore / .rgignore ---------------------------------------------------------

interface IgnorePattern {
  re: RegExp;
  negate: boolean;
}

function globBody(glob: string): string {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        i++;
        if (glob[i + 1] === "/") {
          i++;
          re += "(?:.*/)?";
        } else re += ".*";
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else if (c === "\\" && i + 1 < glob.length) re += escapeRe(glob[++i]!);
    else re += escapeRe(c);
  }
  return re;
}
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Parse gitignore-syntax text (`.ignore`, `.rgignore`). Case-sensitive, like ripgrep. */
export function parseIgnoreFile(text: string): IgnorePattern[] {
  const out: IgnorePattern[] = [];
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.replace(/(?<!\\)\s+$/, "");
    if (!line || line.startsWith("#")) continue;
    const negate = line.startsWith("!");
    if (negate) line = line.slice(1);
    if (!line) continue;
    const dirOnly = line.endsWith("/");
    if (dirOnly) line = line.slice(0, -1);
    const anchored = line.startsWith("/") || line.includes("/");
    if (line.startsWith("/")) line = line.slice(1);
    if (!line) continue;
    // A directory pattern matches everything beneath it; a file pattern may be exact.
    const tail = dirOnly ? "/.*" : "(?:/.*)?";
    out.push({ re: new RegExp(`${anchored ? "^" : "(?:^|/)"}${globBody(line)}${tail}$`), negate });
  }
  return out;
}

const IGNORE_FILES = [".ignore", ".rgignore"] as const;
/** Parent directories above the search root that are consulted for ignore files. */
const IGNORE_PARENTS = 6;

/**
 * The `.ignore`/`.rgignore` verdict for a file: `ignore`, `whitelist` (a `!`
 * pattern), or null when no pattern speaks. Files nearer the file win, and
 * `.rgignore` wins over `.ignore` within a directory.
 */
function dotIgnoreVerdict(
  dirAbs: string,
  rel: string,
  cache: Map<string, IgnorePattern[]>,
): "ignore" | "whitelist" | null {
  const fileAbs = path.join(dirAbs, rel);
  // From the file's directory up to the search root, then a few parents beyond it.
  const chain: string[] = [];
  let d = path.dirname(fileAbs);
  for (let i = 0; i < 64; i++) {
    chain.push(d);
    if (path.relative(dirAbs, d) === "") break;
    const up = path.dirname(d);
    if (up === d) break;
    d = up;
  }
  for (let i = 0; i < IGNORE_PARENTS; i++) {
    const up = path.dirname(d);
    if (up === d) break;
    chain.push(up);
    d = up;
  }
  let verdict: "ignore" | "whitelist" | null = null;
  for (const dir of chain.reverse()) {
    let patterns = cache.get(dir);
    if (!patterns) {
      patterns = [];
      for (const name of IGNORE_FILES) {
        try {
          patterns.push(...parseIgnoreFile(fs.readFileSync(path.join(dir, name), "utf8")));
        } catch {
          // no such file
        }
      }
      cache.set(dir, patterns);
    }
    if (patterns.length === 0) continue;
    const local = path.relative(dir, fileAbs).replace(/\\/g, "/");
    for (const p of patterns) if (p.re.test(local)) verdict = p.negate ? "whitelist" : "ignore";
  }
  return verdict;
}

// .gitignore (one `git check-ignore`) -------------------------------------------

/** The nearest directory upward that holds a `.git` entry (bounded), or null. */
function findGitRoot(dirAbs: string): string | null {
  let d = dirAbs;
  for (let i = 0; i < 12; i++) {
    try {
      fs.statSync(path.join(d, ".git"));
      return d;
    } catch {
      // keep climbing
    }
    const up = path.dirname(d);
    if (up === d) return null;
    d = up;
  }
  return null;
}

/** Spawning git on Windows routinely takes 40–120 ms (process start plus the
 *  Defender scan), so a 30 ms deadline there turned ordinary searches into
 *  intermittent denials. Elsewhere git starts in a few ms. */
export const GIT_TIMEOUT_MS = process.platform === "win32" ? 150 : 30;

/**
 * Which of `rels` git ignores — ONE spawn for all of them. Pattern-based
 * (`--no-index`), because ripgrep skips a gitignored file even when it is tracked.
 * Returns why when the answer is unknown (git missing, slow, or errored): the
 * caller then treats every file as in scope — safety over convenience — and says so.
 */
function gitCheckIgnore(
  cwd: string,
  rels: readonly string[],
  env: SweepEnv,
): Set<string> | GitFailure {
  const git = env.git ?? {};
  try {
    const r = spawnSync(git.bin ?? "git", ["check-ignore", "--no-index", "--stdin", "-z"], {
      cwd,
      input: `${rels.join("\0")}\0`,
      timeout: git.timeoutMs ?? GIT_TIMEOUT_MS,
      windowsHide: true,
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" },
    });
    if (r.signal || (r.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT") {
      return "timeout";
    }
    if (r.error) return "unavailable";
    if (r.status !== 0 && r.status !== 1) return "unavailable"; // 1 = nothing ignored, 128 = fatal
    return new Set(r.stdout.split("\0").filter(Boolean));
  } catch {
    return "unavailable";
  }
}

/** The subset of `rels` (relative to `dirAbs`) that the tool's ignore files would skip. */
function ignoredAmong(
  dirAbs: string,
  rels: readonly string[],
  ignore: SearchRequest["ignore"],
  env: SweepEnv,
): { ignored: Set<string>; gitFailure?: GitFailure } {
  const ignored = new Set<string>();
  const undecided: string[] = [];
  const cache = new Map<string, IgnorePattern[]>();
  for (const rel of rels) {
    const verdict = ignore.dot ? dotIgnoreVerdict(dirAbs, rel, cache) : null;
    if (verdict === "ignore") ignored.add(rel);
    else if (verdict === null && ignore.vcs) undecided.push(rel);
  }
  if (undecided.length > 0 && findGitRoot(dirAbs)) {
    const fromGit = gitCheckIgnore(dirAbs, undecided, env);
    if (typeof fromGit === "string") return { ignored, gitFailure: fromGit };
    for (const rel of fromGit) ignored.add(rel);
  }
  return { ignored };
}

// --- the bounded walk ---------------------------------------------------------

const BASELINE_REASON = "a previous sweep found a plaintext secret in this file";

interface Candidate extends FlaggedFile {
  rel: string;
}

export function findFlagged(dirAbs: string, req: SearchRequest, deps: SearchDeps): SearchResult {
  const { env } = deps;
  const excludedByCall = makeFilter(req);
  const whitelisted = makeWhitelist(req);
  // Hidden files are out of scope for ripgrep-style tools — unless a glob names them.
  const hiddenOut = (rel: string) => req.skipHidden && hasHiddenSegment(rel) && !whitelisted(rel);
  const userExcluded = (abs: string, name: string) => {
    if (deps.userExclude.length === 0) return false;
    const norm = abs.replace(/\\/g, "/");
    return deps.userExclude.some((g) => g.test(norm) || g.test(name));
  };

  const dirNorm = normPath(dirAbs, env.platform);
  const relFromDir = (abs: string) => abs.replace(/\\/g, "/").slice(dirNorm.length + 1);

  // 1. Baseline locations under the directory — cheap, and the whole answer when
  //    the walk is cut short.
  const fromBaseline = new Map<string, Candidate>();
  for (const abs of deps.baselineAbs) {
    if (!isUnder(abs, dirAbs, env.platform) || normPath(abs, env.platform) === dirNorm) continue;
    const rel = relFromDir(abs);
    if (hiddenOut(rel) || excludedByCall(rel)) continue;
    if (deps.allow.some((re) => re.test(abs.replace(/\\/g, "/")))) continue;
    fromBaseline.set(normPath(abs, env.platform), { path: abs, rel, reason: BASELINE_REASON });
  }

  // 2. A bounded breadth-first walk for files the name rules would block.
  const fromWalk = new Map<string, Candidate>();
  let entries = 0;
  let truncated = false;
  // A glob can whitelist a file inside a hidden directory, so only prune those
  // directories when no glob could.
  const pruneHiddenDirs = req.skipHidden && req.include.length === 0;
  const queue: { abs: string; rel: string; depth: number }[] = [{ abs: dirAbs, rel: "", depth: 0 }];

  walk: for (let q = 0; q < queue.length; q++) {
    const here = queue[q]!;
    let dirents: fs.Dirent[];
    try {
      dirents = fs.readdirSync(here.abs, { withFileTypes: true });
    } catch {
      continue; // unreadable: nothing we can say about it
    }
    for (const e of dirents) {
      if (e.isSymbolicLink()) continue; // never follow links
      if (++entries > SEARCH_MAX_ENTRIES) {
        truncated = true;
        break walk;
      }
      const abs = path.join(here.abs, e.name);
      const rel = here.rel ? `${here.rel}/${e.name}` : e.name;
      if (userExcluded(abs, e.name)) continue;
      if (e.isDirectory()) {
        if (pruneHiddenDirs && e.name.startsWith(".")) continue;
        if (here.depth + 1 >= SEARCH_MAX_DEPTH) continue; // files in it would be deeper than the bound
        if (isDefaultExcludedDir(e.name, normPath(abs, env.platform))) continue;
        if (isCloudRoot(abs, e.name, env)) continue;
        queue.push({ abs, rel, depth: here.depth + 1 });
      } else if (e.isFile()) {
        if (hiddenOut(rel) || excludedByCall(rel)) continue;
        if (deps.allow.some((re) => re.test(abs.replace(/\\/g, "/")))) continue;
        const reason = deps.blockReason(abs);
        if (reason) fromWalk.set(normPath(abs, env.platform), { path: abs, rel, reason });
      }
    }
  }

  let candidates = [
    ...(truncated ? fromBaseline : new Map([...fromWalk, ...fromBaseline])).values(),
  ];
  let gitFailure: GitFailure | undefined;

  // 3. Ignore files: only the flagged candidates are checked (never the tree), and a
  //    glob that names a file keeps it in scope regardless.
  if ((req.ignore.vcs || req.ignore.dot) && candidates.length > 0) {
    const toCheck = candidates.filter((c) => !whitelisted(c.rel));
    if (toCheck.length > 0) {
      const verdict = ignoredAmong(
        dirAbs,
        toCheck.map((c) => c.rel),
        req.ignore,
        env,
      );
      candidates = candidates.filter((c) => !verdict.ignored.has(c.rel));
      gitFailure = verdict.gitFailure;
    }
  }

  const flagged: FlaggedFile[] = candidates
    .map(({ path: p, reason }) => ({ path: p, reason }))
    .sort((a, b) => a.path.localeCompare(b.path));
  return gitFailure && flagged.length > 0
    ? { flagged, truncated, gitFailure }
    : { flagged, truncated };
}
