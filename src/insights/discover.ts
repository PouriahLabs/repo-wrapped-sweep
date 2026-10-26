// Discovery for Machine Insights (ENDPOINT-MACHINE-INSIGHTS § C2.1, C2.2, C2.5): what the
// walk saw that is not about secrets. A `Discovery` is a `WalkObserver`, so a full sweep
// finds clones, project folders and regenerable folders in the walk it already does;
// the standalone commands (`git`, `disk`, …) run a cheap directories-only walk instead.
//
// Nothing here opens a file. It records names from directory listings — the `.git` the
// walker skips (a directory, or a `gitdir:` FILE for a worktree/submodule), the project
// markers, and the C2.2 class folders next to their proving sibling.

import fs from "node:fs";
import path from "node:path";
import { classifyDir, isReportOnlyDir, type DiskClass } from "@/lib/endpoint/insights/disk-classes";
import { isProjectMarker } from "@/lib/endpoint/insights/backup";
import { PIN_FILES } from "@/lib/endpoint/insights/pins";
import { isUnder, normPath, type SweepEnv } from "../env";
import { createPowerShellProvider, type PlaceholderProvider } from "../placeholders";
import { redirectedKnownFolders, walk, type WalkDirEntry, type WalkObserver } from "../walk";

export interface ClassDir {
  /** Absolute path of the regenerable folder. */
  path: string;
  cls: DiskClass;
  /** The folder whose sibling proved it regenerable (the project it belongs to). */
  project: string;
}

export interface ReportOnlyDir {
  path: string;
  project: string;
}

export interface ProjectFolder {
  path: string;
  /** Entry names of the folder, as listed. */
  entries: readonly WalkDirEntry[];
}

/** Lockfiles: proof files that are not "source" when deciding a folder is only regenerable. */
const LOCKFILES = new Set([
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
  "cargo.lock",
  "poetry.lock",
]);

export class Discovery implements WalkObserver {
  /** Directories holding a `.git` (dir or `gitdir:` file). */
  readonly repoRoots = new Set<string>();
  /** Every directory holding a project marker (nested ones included; see `topProjects`). */
  readonly projects = new Map<string, ProjectFolder>();
  readonly classDirs: ClassDir[] = [];
  readonly reportOnly: ReportOnlyDir[] = [];

  constructor(private readonly env: SweepEnv) {}

  onDirectory(dir: string, entries: readonly WalkDirEntry[]): void {
    // The home directory itself is never a project or a repo (a dotfiles repo, a stray
    // ~/package.json): treating it as one would fold every project under it.
    if (normPath(dir, this.env.platform) === normPath(this.env.home, this.env.platform)) return;
    const names = entries.map((e) => e.name);
    if (entries.some((e) => e.name === ".git")) this.repoRoots.add(dir);
    if (names.some(isProjectMarker)) this.projects.set(dir, { path: dir, entries });

    for (const e of entries) {
      if (!e.isDir) continue;
      const abs = path.join(dir, e.name);
      if (e.name === ".vercel") {
        const nested = path.join(abs, "output");
        if (isDirSync(nested) && classifyDir(".vercel/output", names) !== null) {
          this.classDirs.push({ path: nested, cls: "next-build", project: dir });
        }
        continue;
      }
      const cls = classifyDir(e.name, names);
      if (cls) this.classDirs.push({ path: abs, cls, project: dir });
      else if (isReportOnlyDir(e.name) && names.includes("package.json")) {
        this.reportOnly.push({ path: abs, project: dir });
      }
    }
  }

  /** Repo roots, sorted. */
  repos(): string[] {
    return [...this.repoRoots].sort();
  }

  /**
   * Project folders not nested inside another project (§ C2.5), sorted. A monorepo's
   * packages fold into the repo; a clone inside a non-git project folds into the outer one.
   */
  topProjects(): ProjectFolder[] {
    const sorted = [...this.projects.values()].sort((a, b) => a.path.localeCompare(b.path));
    const out: ProjectFolder[] = [];
    for (const p of sorted) {
      if (out.some((o) => isUnder(p.path, o.path, this.env.platform))) continue;
      out.push(p);
    }
    return out;
  }

  /** Class folders, minus any that sit inside another class folder (no double counting). */
  regenerable(): ClassDir[] {
    const sorted = [...this.classDirs].sort((a, b) => a.path.localeCompare(b.path));
    const out: ClassDir[] = [];
    for (const d of sorted) {
      if (out.some((o) => isUnder(d.path, o.path, this.env.platform))) continue;
      out.push(d);
    }
    return out;
  }

  /** Pin files present in a folder (from its listing — nothing is opened here). */
  pinFilesIn(dir: string): string[] {
    const p = this.projects.get(dir);
    if (!p) return [];
    const names = new Set(p.entries.filter((e) => !e.isDir).map((e) => e.name));
    return PIN_FILES.filter((f) => names.has(f));
  }

  /**
   * A folder whose only content is regenerable — markers, lockfiles and class folders, no
   * source and no git — is not a project worth backing up (§ C2.5).
   */
  onlyRegenerable(dir: string): boolean {
    const p = this.projects.get(dir);
    if (!p) return false;
    const classes = new Set(
      this.classDirs.filter((c) => c.project === dir).map((c) => path.basename(c.path)),
    );
    for (const e of p.entries) {
      if (e.name === ".git") return false;
      if (e.isDir) {
        if (!classes.has(e.name) && !isReportOnlyDir(e.name) && e.name !== ".vercel") return false;
      } else if (e.name !== "package.json" && !LOCKFILES.has(e.name.toLowerCase())) {
        return false;
      }
    }
    return true;
  }
}

function isDirSync(abs: string): boolean {
  try {
    return fs.lstatSync(abs).isDirectory();
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// The standalone walk
// ---------------------------------------------------------------------------

export interface DiscoverOptions {
  env: SweepEnv;
  /** Explicit roots; empty = the home directory (plus a redirected Documents/Desktop). */
  roots: string[];
  excludeGlobs: string[];
  includeCloud: boolean;
  concurrency: number;
  /** As in `ScanOptions.placeholders`: undefined → the real lister on Windows; null → none. */
  placeholders?: PlaceholderProvider | null;
}

/**
 * The cheap walk behind `git` / `disk` / `toolchain` / `backup`: the same roots, excludes
 * and cloud rules as a sweep, but directories only — no file is handed out or opened.
 */
export async function discover(opts: DiscoverOptions): Promise<Discovery> {
  const ownProvider = opts.placeholders === undefined && opts.env.platform === "win32";
  const placeholders: PlaceholderProvider | null =
    opts.placeholders !== undefined
      ? opts.placeholders
      : ownProvider
        ? createPowerShellProvider()
        : null;
  const full = opts.roots.length === 0;
  const redirected =
    full && placeholders && !opts.includeCloud ? await redirectedKnownFolders(opts.env) : [];
  const roots = [...(full ? [opts.env.home] : opts.roots), ...redirected.map((r) => r.path)];
  const found = new Discovery(opts.env);
  try {
    await walk({
      roots,
      env: opts.env,
      excludeGlobs: opts.excludeGlobs,
      includeCloud: opts.includeCloud,
      concurrency: opts.concurrency,
      placeholders,
      cloudAllowRoots: redirected.map((r) => r.path),
      observer: found,
      dirsOnly: true,
      onFile: async () => {},
    });
  } finally {
    if (ownProvider) await placeholders?.close();
  }
  return found;
}
