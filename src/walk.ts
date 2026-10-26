// The directory walker (§ A2.1): bounded worker pool over `fs.opendir`, default
// excludes, cloud-sync skipping, permission accounting. It yields FILES to a
// callback and knows nothing about secrets.

import fs from "node:fs";
import path from "node:path";
import type { LocationClass } from "@/lib/native-scan/path-rules";
import { isUnder, normPath, type SweepEnv } from "./env";
import {
  classifyLocation,
  compileGlob,
  isCloudRoot,
  isDefaultExcludedDir,
  isInCloud,
  isInstalledSoftwareDir,
} from "./locations";
import { isPlaceholderAttr, type PlaceholderProvider } from "./placeholders";

export interface WalkFile {
  path: string;
  locationClass: LocationClass;
}

export interface WalkOptions {
  roots: string[];
  env: SweepEnv;
  /** User exclude globs (`--exclude` + sweep.json). */
  excludeGlobs: string[];
  /** Descend into cloud-sync roots (may force online-only downloads). */
  includeCloud: boolean;
  /** Worker-pool size. */
  concurrency: number;
  /** Explain when Documents/Desktop sit inside cloud sync (only relevant when
   *  the sweep is meant to cover the home directory). */
  noteKnownFolders?: boolean;
  /**
   * Walk the installed-software trees too (Program Files, editor extensions, package
   * caches, browser profiles …). The always-on excludes — node_modules, .git, OS caches —
   * stay on: this restores the sweep as it was before those trees were skipped.
   */
  noDefaultExcludes?: boolean;
  /**
   * Windows cloud-placeholder detection. When set, every directory inside a cloud-sync
   * root is listed through it first and entries that would recall from the cloud are
   * skipped WITHOUT being opened; a directory whose attributes cannot be read is skipped
   * and counted. Absent → no cloud directory is attribute-checked.
   */
  placeholders?: PlaceholderProvider | null;
  /**
   * Cloud-sync folders to walk even though cloud roots are skipped by default — the
   * Known Folder Move targets (a redirected Documents/Desktop). Only meaningful with
   * `placeholders`, which is what makes walking them safe.
   */
  cloudAllowRoots?: string[];
  onFile: (file: WalkFile) => Promise<void>;
}

export interface WalkStats {
  /** Directories that could not be read (permission denied). */
  skippedDirs: number;
  /** Files that could not be read (permission denied). */
  skippedFiles: number;
  /** Cloud-sync roots left unvisited. */
  skippedCloud: number;
  /** Online-only (cloud placeholder) entries skipped without being opened or downloaded. */
  skippedPlaceholders: number;
  /** Cloud folders (or entries) skipped because their file attributes could not be read. */
  skippedUnknownAttrs: number;
  /** Permission-denied counts keyed by the top-level directory under its root. */
  deniedByTop: Record<string, number>;
  /** Unexpected per-entry failures (not ENOENT/permission). */
  errors: number;
  notes: string[];
}

type Task =
  { kind: "dir"; dir: string; root: string } | { kind: "file"; file: string; root: string };

function isPermissionError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return code === "EACCES" || code === "EPERM";
}

function topLevel(root: string, dir: string): string {
  const rel = path.relative(root, dir);
  const first = rel.split(path.sep)[0];
  return first ? path.join(root, first) : root;
}

export async function walk(opts: WalkOptions): Promise<WalkStats> {
  const { env } = opts;
  const stats: WalkStats = {
    skippedDirs: 0,
    skippedFiles: 0,
    skippedCloud: 0,
    skippedPlaceholders: 0,
    skippedUnknownAttrs: 0,
    deniedByTop: {},
    errors: 0,
    notes: [],
  };
  const globs = opts.excludeGlobs.map(compileGlob);
  const userExcluded = (abs: string, name: string) => {
    if (globs.length === 0) return false;
    const norm = abs.replace(/\\/g, "/");
    return globs.some((g) => g.test(norm) || g.test(name));
  };
  const deny = (root: string, dir: string) => {
    stats.skippedDirs++;
    const top = topLevel(root, dir);
    stats.deniedByTop[top] = (stats.deniedByTop[top] ?? 0) + 1;
  };

  const stack: Task[] = [];

  // Seed: roots are scanned wherever they point, except cloud roots by default.
  for (const root of opts.roots) {
    const abs = path.resolve(root);
    let st: fs.Stats;
    try {
      st = await fs.promises.lstat(abs);
    } catch (err) {
      if (isPermissionError(err)) deny(abs, abs);
      continue; // missing root: nothing to scan
    }
    if (st.isSymbolicLink()) continue;
    const allowedCloud = (opts.cloudAllowRoots ?? []).some(
      (r) => normPath(r, env.platform) === normPath(abs, env.platform),
    );
    if (!opts.includeCloud && !allowedCloud && isInCloud(abs, env)) {
      stats.skippedCloud++;
      continue;
    }
    if (st.isDirectory()) stack.push({ kind: "dir", dir: abs, root: abs });
    else if (st.isFile()) stack.push({ kind: "file", file: abs, root: path.dirname(abs) });
  }

  let active = 0;
  await new Promise<void>((resolve) => {
    const pump = (): void => {
      while (active < Math.max(1, opts.concurrency) && stack.length > 0) {
        const task = stack.pop()!;
        active++;
        void runTask(task)
          .catch(() => {
            stats.errors++;
          })
          .finally(() => {
            active--;
            pump();
          });
      }
      if (active === 0 && stack.length === 0) resolve();
    };

    const runTask = async (task: Task): Promise<void> => {
      if (task.kind === "file") {
        try {
          await opts.onFile({ path: task.file, locationClass: classifyLocation(task.file, env) });
        } catch (err) {
          const code = (err as NodeJS.ErrnoException | undefined)?.code;
          if (isPermissionError(err)) {
            stats.skippedFiles++;
            const top = topLevel(task.root, task.file);
            stats.deniedByTop[top] = (stats.deniedByTop[top] ?? 0) + 1;
          } else if (code !== "ENOENT") stats.errors++;
        }
        return;
      }

      // Inside a cloud-sync root, ask for every entry's attributes BEFORE reading
      // anything: a placeholder is recognised by an attribute, and the only safe move
      // when we cannot tell is not to open it.
      let attrs: Map<string, number> | null = null;
      if (opts.placeholders && isInCloud(task.dir, env)) {
        attrs = await opts.placeholders.attributes(task.dir);
        if (attrs === null) {
          stats.skippedUnknownAttrs++;
          return;
        }
      }

      let dir: fs.Dir;
      try {
        dir = await fs.promises.opendir(task.dir);
      } catch (err) {
        if (isPermissionError(err)) deny(task.root, task.dir);
        return;
      }
      try {
        for await (const entry of dir) {
          const abs = path.join(task.dir, entry.name);
          let isDir = entry.isDirectory();
          let isFile = entry.isFile();
          if (entry.isSymbolicLink()) continue; // never follow links
          if (!isDir && !isFile) {
            // Some file systems report DT_UNKNOWN; fall back to lstat.
            try {
              const st = await fs.promises.lstat(abs);
              if (st.isSymbolicLink()) continue;
              isDir = st.isDirectory();
              isFile = st.isFile();
            } catch {
              continue;
            }
          }
          if (userExcluded(abs, entry.name)) continue;
          if (attrs) {
            const a = attrs.get(entry.name);
            if (a === undefined) {
              stats.skippedUnknownAttrs++;
              continue;
            }
            if (isPlaceholderAttr(a)) {
              stats.skippedPlaceholders++;
              continue;
            }
          }
          if (isDir) {
            if (isDefaultExcludedDir(entry.name, normPath(abs, env.platform))) continue;
            if (!opts.noDefaultExcludes && isInstalledSoftwareDir(abs, env)) continue;
            if (isCloudRoot(abs, entry.name, env)) {
              if (!opts.includeCloud) {
                stats.skippedCloud++;
                continue;
              }
            }
            stack.push({ kind: "dir", dir: abs, root: task.root });
          } else if (isFile) {
            stack.push({ kind: "file", file: abs, root: task.root });
          }
          pump();
        }
      } catch (err) {
        if (isPermissionError(err)) deny(task.root, task.dir);
        else stats.errors++;
      } finally {
        await dir.close().catch(() => {});
      }
    };

    pump();
  });

  if (stats.skippedCloud > 0) {
    stats.notes.push(
      `skipped ${stats.skippedCloud} cloud-sync folder${stats.skippedCloud === 1 ? "" : "s"} ` +
        "(reading online-only files forces a download) — pass --include-cloud to scan them",
    );
  }
  const redirected = opts.noteKnownFolders ? await documentsRedirectedToCloud(env) : [];
  if (redirected.length > 0) {
    const scannedSafely =
      !opts.includeCloud && (opts.cloudAllowRoots ?? []).length > 0 && !!opts.placeholders;
    stats.notes.push(
      `${redirected.join(" and ")} ${redirected.length === 1 ? "is" : "are"} redirected into cloud sync ` +
        "(Known Folder Move), so " +
        (opts.includeCloud
          ? "they were scanned"
          : scannedSafely
            ? "they were scanned — online-only files were skipped without being downloaded"
            : "they were skipped"),
    );
  }
  if (stats.skippedPlaceholders > 0) {
    stats.notes.push(
      `skipped ${stats.skippedPlaceholders} online-only cloud item${stats.skippedPlaceholders === 1 ? "" : "s"} ` +
        "without opening or downloading them",
    );
  }
  if (stats.skippedUnknownAttrs > 0) {
    stats.notes.push(
      `skipped ${stats.skippedUnknownAttrs} cloud folder${stats.skippedUnknownAttrs === 1 ? "" : "s"} whose file attributes could not be read ` +
        "(never opened, so nothing was downloaded)",
    );
  }
  return stats;
}

/**
 * Which of Documents/Desktop actually live inside a cloud-sync root — a Windows
 * "Known Folder Move" puts them in OneDrive, so skipping cloud roots skips them
 * and the report should say so.
 */
export async function documentsRedirectedToCloud(env: SweepEnv): Promise<string[]> {
  return (await redirectedKnownFolders(env)).map((f) => f.name);
}

/**
 * The real paths of the Known Folders (Documents, Desktop) that live inside a
 * cloud-sync root. With Known Folder Move the folder the shell calls "Documents" IS
 * `~/OneDrive/Documents`, which a cloud-skipping walk never reaches from the home
 * directory — so the sweep seeds these paths directly.
 */
export async function redirectedKnownFolders(
  env: SweepEnv,
): Promise<Array<{ name: string; path: string }>> {
  const out: Array<{ name: string; path: string }> = [];
  for (const name of ["Documents", "Desktop"]) {
    const candidates = [path.join(env.home, name)];
    for (const cloud of env.cloudRoots) candidates.push(path.join(cloud, name));
    for (const c of candidates) {
      try {
        const real = await fs.promises.realpath(c);
        if (env.cloudRoots.some((r) => isUnder(real, r, env.platform))) {
          out.push({ name, path: real });
          break;
        }
      } catch {
        // not present at this candidate
      }
    }
  }
  return out;
}
