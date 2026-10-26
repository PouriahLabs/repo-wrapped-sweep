// VS Code local history → the file it was a copy of (A10).
//
// Every time you save, VS Code (and Cursor, Windsurf, VSCodium) snapshots the file
// into `User/History/<id>/<random>.<ext>`. The directory also holds an
// `entries.json`:
//
//   { "version": 1, "resource": "file:///c%3A/Users/me/proj/.env.prod", "entries": [...] }
//
// naming the ORIGINAL resource every snapshot in that directory came from. That
// matters for two reasons: a snapshot of `.env.example` is not a secret in a file
// nobody should be copying (the example-file allowlist), and a snapshot of
// `tests/fixtures/key.pem` is a fixture — neither is knowable from the opaque
// `History/-6a9ea81e/9ya8.prod`. And a report that says "VS Code history of
// ~/proj/.env.prod" tells the person what to do about it; the opaque name doesn't.
//
// Local reporting only: the original path is never uploaded.

import fs from "node:fs";
import path from "node:path";
import { displayPath, type SweepEnv } from "./env";

/** `entries.json` is a small index; refuse anything large rather than parse it. */
const MAX_ENTRIES_JSON_BYTES = 1024 * 1024;

/**
 * The `resource` URI of an `entries.json`, or null when the file isn't one.
 */
export function parseEntriesResource(text: string): string | null {
  try {
    const json = JSON.parse(text) as { resource?: unknown };
    return typeof json.resource === "string" && json.resource ? json.resource : null;
  } catch {
    return null;
  }
}

/**
 * A resource URI as a local path: `file:///c%3A/Users/me/x` → `c:/Users/me/x` on
 * Windows, `file:///home/me/x` → `/home/me/x` elsewhere. A remote resource
 * (`vscode-remote://…`) has no local path, so it comes back as `scheme:authority/path`
 * — still readable in a report, never mistaken for a file on this disk.
 */
export function resourceToPath(resource: string, platform: NodeJS.Platform): string | null {
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/]*)(\/.*)?$/i.exec(resource);
  if (!m) return null;
  const [, scheme, authority = "", rawPath = ""] = m;
  let decoded: string;
  let host: string;
  try {
    decoded = decodeURIComponent(rawPath);
    host = decodeURIComponent(authority);
  } catch {
    return null;
  }
  if (scheme!.toLowerCase() !== "file") return `${scheme}:${host}${decoded}`;
  if (platform === "win32") {
    if (/^\/[a-zA-Z]:/.test(decoded)) return decoded.slice(1);
    if (host) return `//${host}${decoded}`; // a UNC share
    return decoded;
  }
  return decoded;
}

/** Is `abs` a snapshot file — i.e. directly inside `…/History/<id>/`? */
export function isHistorySnapshot(abs: string): boolean {
  const parts = abs.replace(/\\/g, "/").split("/");
  return parts.length >= 3 && parts[parts.length - 3]!.toLowerCase() === "history";
}

export type HistoryResolver = (abs: string) => Promise<string | null>;

/**
 * Resolve a history snapshot to its original path (home-relative display form), reading
 * each directory's `entries.json` once. Returns null when `abs` is not a snapshot or the
 * index is missing/unreadable — the caller falls back to the opaque path.
 */
export function createHistoryResolver(
  env: Pick<SweepEnv, "home" | "platform">,
  readText: (file: string) => Promise<string | null> = readEntriesJson,
): HistoryResolver {
  const cache = new Map<string, Promise<string | null>>();
  return (abs) => {
    if (!isHistorySnapshot(abs)) return Promise.resolve(null);
    const dir = path.dirname(abs);
    let hit = cache.get(dir);
    if (!hit) {
      hit = (async () => {
        const text = await readText(path.join(dir, "entries.json"));
        if (text === null) return null;
        const resource = parseEntriesResource(text);
        if (!resource) return null;
        const local = resourceToPath(resource, env.platform);
        return local === null ? null : displayPath(local, env);
      })();
      cache.set(dir, hit);
    }
    return hit;
  };
}

async function readEntriesJson(file: string): Promise<string | null> {
  try {
    const st = await fs.promises.stat(file);
    if (!st.isFile() || st.size > MAX_ENTRIES_JSON_BYTES) return null;
    return await fs.promises.readFile(file, "utf8");
  } catch {
    return null;
  }
}
