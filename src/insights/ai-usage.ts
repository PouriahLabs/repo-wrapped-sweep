// AI usage collector (ENDPOINT-MACHINE-INSIGHTS § C2.4, C-6): stream Claude Code and Codex
// transcripts through the shared pure parser (`@/lib/endpoint/insights/ai-usage`) and keep
// only the usage events — never a line, never message text.
//
// Sources
//   Claude Code  ~/.claude/projects/**/*.jsonl
//   Codex        ~/.codex/sessions/**/*.jsonl[.zst] and ~/.codex/archived_sessions/** (a
//                session moves there when archived; the dedupe key below keeps it counted once)
//
// Incremental. Two owner-only files under ~/.repo-wrapped:
//   ai-cursor.json  per transcript: size, mtime, byte offset of the last complete line read,
//                   and the parser context (Codex lines are stateful — `session_meta` /
//                   `turn_context` name the model and directory their `token_count` lines omit).
//   ai-usage.json   the usage events themselves (tokens, model, time, session, cwd), kept for
//                   AI_RETENTION_DAYS. A run reads only bytes past each cursor, merges the new
//                   events in, and folds the store — so the report covers history even after
//                   Claude Code prunes old transcripts.
//
// De-duplication survives run boundaries because the store IS the seen-set: every event has a
// key (Claude Code's `message.id:requestId`; for Codex, and the rare Claude line without an id,
// a synthetic key from session, time and token counts), and a repeat of a stored key merges
// into it with the same max-per-field rule as `dedupeUsageEvents`. A resumed session copying
// history into a new file, a streamed response logged once per content block, a re-read after
// a file shrank, or a rollout moved to `archived_sessions` therefore never double counts.
//
// Bounded memory: a transcript is read in 64 KB chunks and split on newline BYTES; at most one
// line (capped at 64 KB — longer lines are dropped and counted, ≈0.3% of tokens on a real
// machine) is buffered at a time. What grows is the event store, one small record per distinct
// API response.
//
// Codex writes finished rollouts as zstd (`.jsonl.zst`). Node ships a zstd decoder only from
// 22.15 / 23.8; on an older Node those files are skipped and the report says so.

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Transform } from "node:stream";
import zlib from "node:zlib";
import {
  USAGE_LINE_CAP_CHARS,
  nearestRoot,
  newUsageContext,
  parseUsageLine,
  type AiTool,
  type UsageEvent,
  type UsageParseContext,
} from "@/lib/endpoint/insights/ai-usage";
import { displayPath, isUnder, normPath, type SweepEnv } from "../env";
import { writeJsonPrivate } from "../state";

export const AI_CURSOR_FILE = "ai-cursor.json";
export const AI_STORE_FILE = "ai-usage.json";
/** Events older than this are dropped from the store (same horizon as the server's AI rows). */
export const AI_RETENTION_DAYS = 400;
/** Read size, and so the most a reader holds besides the one line it is assembling. */
export const AI_READ_CHUNK_BYTES = 64 * 1024;
/** Line cap, in bytes (the parser's cap is in chars; bytes ≥ chars, so this is the stricter). */
export const AI_LINE_CAP_BYTES = USAGE_LINE_CAP_CHARS;

const DAY_MS = 86_400_000;
const MAX_DEPTH = 8;

export interface AiSource {
  tool: AiTool;
  dir: string;
}

export function aiSources(env: Pick<SweepEnv, "home">): AiSource[] {
  return [
    { tool: "claude-code", dir: path.join(env.home, ".claude", "projects") },
    { tool: "codex", dir: path.join(env.home, ".codex", "sessions") },
    { tool: "codex", dir: path.join(env.home, ".codex", "archived_sessions") },
  ];
}

/** A zstd decoder factory, or null when this Node has none. */
export type ZstdFactory = () => Transform;

export function detectZstd(): ZstdFactory | null {
  const z = zlib as unknown as { createZstdDecompress?: () => Transform };
  return typeof z.createZstdDecompress === "function" ? () => z.createZstdDecompress!() : null;
}

const isZst = (f: string) => f.toLowerCase().endsWith(".jsonl.zst");
const isTranscript = (f: string) => f.toLowerCase().endsWith(".jsonl") || isZst(f);

export interface TranscriptFile {
  path: string;
  tool: AiTool;
  size: number;
  mtimeMs: number;
}

/** Every transcript under the sources (no symlinks followed), oldest first. */
export function listTranscripts(sources: readonly AiSource[]): TranscriptFile[] {
  const out: TranscriptFile[] = [];
  const visit = (dir: string, tool: AiTool, depth: number) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (depth < MAX_DEPTH) visit(abs, tool, depth + 1);
      } else if (e.isFile() && isTranscript(e.name)) {
        try {
          const st = fs.statSync(abs);
          out.push({ path: abs, tool, size: st.size, mtimeMs: st.mtimeMs });
        } catch {
          // vanished between listing and stat
        }
      }
    }
  };
  for (const s of sources) visit(s.dir, s.tool, 0);
  // Oldest first: the first occurrence of a response supplies its session and directory, and
  // a resumed session's copied history is younger than the original.
  return out.sort((a, b) => a.mtimeMs - b.mtimeMs || a.path.localeCompare(b.path));
}

// ---------------------------------------------------------------------------
// Line reader (bytes, so the cursor is a byte offset)
// ---------------------------------------------------------------------------

export interface ReadStats {
  lines: number;
  /** Lines over the cap, dropped unparsed. */
  oversize: number;
  /** Largest partial line held at once, in bytes — the reader's memory bound. */
  peakBufferedBytes: number;
}

export const newReadStats = (): ReadStats => ({ lines: 0, oversize: 0, peakBufferedBytes: 0 });

interface RawLine {
  /** Null when the line was over the cap. */
  line: string | null;
  /** Bytes consumed through the end of this line (relative to where the stream started). */
  end: number;
  /** False for a trailing line with no newline yet (possibly still being written). */
  complete: boolean;
}

/** Split a byte stream on `\n`, holding at most one capped line. */
export async function* readByteLines(
  stream: AsyncIterable<Buffer | string>,
  cap: number,
  stats: ReadStats,
): AsyncGenerator<RawLine> {
  let parts: Buffer[] = [];
  let partLen = 0;
  let overflow = false;
  let consumed = 0;
  for await (const raw of stream) {
    const chunk = typeof raw === "string" ? Buffer.from(raw, "utf8") : raw;
    let start = 0;
    while (start < chunk.length) {
      const nl = chunk.indexOf(10, start);
      const stop = nl === -1 ? chunk.length : nl;
      const piece = chunk.subarray(start, stop);
      if (!overflow) {
        if (partLen + piece.length > cap) {
          overflow = true;
          parts = [];
          partLen = 0;
        } else if (piece.length > 0) {
          // Copy: a subarray would pin the whole 64 KB chunk for as long as the line lives.
          parts.push(Buffer.from(piece));
          partLen += piece.length;
          if (partLen > stats.peakBufferedBytes) stats.peakBufferedBytes = partLen;
        }
      }
      if (nl === -1) {
        consumed += chunk.length - start;
        start = chunk.length;
        continue;
      }
      consumed += nl + 1 - start;
      start = nl + 1;
      stats.lines++;
      if (overflow) stats.oversize++;
      yield { line: overflow ? null : joinLine(parts, partLen), end: consumed, complete: true };
      parts = [];
      partLen = 0;
      overflow = false;
    }
  }
  if (partLen > 0 || overflow) {
    yield { line: overflow ? null : joinLine(parts, partLen), end: consumed, complete: false };
  }
}

function joinLine(parts: Buffer[], len: number): string {
  const s = (parts.length === 1 ? parts[0]! : Buffer.concat(parts, len)).toString("utf8");
  return s.endsWith("\r") ? s.slice(0, -1) : s;
}

/** A trailing line without a newline counts only once it is a whole JSON value. */
function isWholeJson(line: string): boolean {
  try {
    JSON.parse(line);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Event store (the seen-set)
// ---------------------------------------------------------------------------

/** The stable identity of a usage event across files and runs (16 hex). */
export function eventKey(e: UsageEvent): string {
  const raw =
    e.dedupeKey !== null
      ? `${e.tool}|${e.dedupeKey}`
      : `${e.tool}|${e.sessionId}|${e.at}|${e.model}|${e.inputTokens}|${e.outputTokens}|${e.cacheWriteTokens}|${e.cacheReadTokens}`;
  return createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

/** De-duplicated usage events, keyed by `eventKey`. */
export class UsageStore {
  readonly byKey = new Map<string, UsageEvent>();

  /** Add an event; a repeat merges in with the max of each token field. True when new. */
  add(e: UsageEvent): boolean {
    const key = eventKey(e);
    const seen = this.byKey.get(key);
    if (!seen) {
      this.byKey.set(key, { ...e, dedupeKey: key });
      return true;
    }
    seen.inputTokens = Math.max(seen.inputTokens, e.inputTokens);
    seen.outputTokens = Math.max(seen.outputTokens, e.outputTokens);
    seen.cacheWriteTokens = Math.max(seen.cacheWriteTokens, e.cacheWriteTokens);
    seen.cacheReadTokens = Math.max(seen.cacheReadTokens, e.cacheReadTokens);
    return false;
  }

  events(): UsageEvent[] {
    return [...this.byKey.values()].sort((a, b) => a.at - b.at);
  }

  prune(before: number): void {
    for (const [k, e] of this.byKey) if (e.at < before) this.byKey.delete(k);
  }
}

const TOOLS: readonly AiTool[] = ["claude-code", "codex"];

/** On disk: a string table + one array per event (≈90 bytes each). */
interface StoreFile {
  version: 1;
  strings: string[];
  /** [at, tool, model, session, cwd (-1 = none), input, output, cacheWrite, cacheRead, key] */
  events: Array<[number, number, number, number, number, number, number, number, number, string]>;
}

export function serializeStore(store: UsageStore): StoreFile {
  const strings: string[] = [];
  const index = new Map<string, number>();
  const id = (s: string) => {
    let i = index.get(s);
    if (i === undefined) {
      i = strings.length;
      strings.push(s);
      index.set(s, i);
    }
    return i;
  };
  return {
    version: 1,
    strings,
    events: store
      .events()
      .map((e) => [
        e.at,
        TOOLS.indexOf(e.tool),
        id(e.model),
        id(e.sessionId),
        e.cwd === null ? -1 : id(e.cwd),
        e.inputTokens,
        e.outputTokens,
        e.cacheWriteTokens,
        e.cacheReadTokens,
        e.dedupeKey!,
      ]),
  };
}

/** Null when the file is missing or not a store this version wrote. */
export function deserializeStore(raw: unknown): UsageStore | null {
  const f = raw as Partial<StoreFile> | null;
  if (!f || f.version !== 1 || !Array.isArray(f.strings) || !Array.isArray(f.events)) return null;
  const s = f.strings;
  const store = new UsageStore();
  for (const row of f.events) {
    if (!Array.isArray(row) || row.length !== 10) return null;
    const [at, tool, model, session, cwd, i, o, cw, cr, key] = row;
    const tl = TOOLS[tool];
    if (
      !tl ||
      typeof s[model] !== "string" ||
      typeof s[session] !== "string" ||
      typeof key !== "string"
    ) {
      return null;
    }
    store.byKey.set(key, {
      tool: tl,
      model: s[model]!,
      at,
      sessionId: s[session]!,
      cwd: cwd >= 0 ? (s[cwd] ?? null) : null,
      inputTokens: i,
      outputTokens: o,
      cacheWriteTokens: cw,
      cacheReadTokens: cr,
      dedupeKey: key,
    });
  }
  return store;
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

export interface CursorEntry {
  size: number;
  mtimeMs: number;
  /** Byte offset just past the last line read (decompressed bytes for a `.zst`). */
  offset: number;
  ctx: UsageParseContext;
}

interface CursorFile {
  version: 1;
  files: Record<string, CursorEntry>;
}

function readJson(file: string): unknown {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function loadCursor(file: string): Map<string, CursorEntry> {
  const raw = readJson(file) as Partial<CursorFile> | null;
  const out = new Map<string, CursorEntry>();
  if (!raw || raw.version !== 1 || typeof raw.files !== "object" || raw.files === null) return out;
  for (const [p, e] of Object.entries(raw.files)) {
    if (
      e &&
      typeof e.size === "number" &&
      typeof e.mtimeMs === "number" &&
      typeof e.offset === "number" &&
      e.ctx &&
      typeof e.ctx === "object"
    ) {
      out.set(p, {
        size: e.size,
        mtimeMs: e.mtimeMs,
        offset: e.offset,
        ctx: newUsageContext(e.ctx),
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

export interface AiScanStats {
  /** Transcripts found. */
  files: number;
  /** Transcripts read this run (new or grown). */
  filesRead: number;
  /** Lines read this run. */
  linesRead: number;
  /** Lines over 64 KB, dropped. */
  oversizeLines: number;
  /** New distinct API responses added this run. */
  newEvents: number;
  /** `.jsonl.zst` transcripts skipped because this Node has no zstd decoder. */
  zstdSkipped: number;
  /** Transcripts that could not be read (permissions, corrupt zstd). */
  unreadable: number;
  /** Largest line buffer held, in bytes (bounded by the 64 KB cap). */
  peakBufferedBytes: number;
}

export interface AiCollection {
  /** Every stored event inside the retention window, oldest first. */
  events: UsageEvent[];
  scan: AiScanStats;
}

export interface AiCollectOptions {
  env: SweepEnv;
  now?: number;
  /** Override the transcript locations (tests). */
  sources?: AiSource[];
  /** undefined → detect; null → behave as if this Node had no zstd. */
  zstd?: ZstdFactory | null;
  /** Read without writing the cursor or store back. */
  readOnly?: boolean;
}

async function readTranscript(
  file: TranscriptFile,
  prior: CursorEntry | undefined,
  store: UsageStore,
  zstd: ZstdFactory | null,
  stats: ReadStats,
  minAt: number,
): Promise<{ entry: CursorEntry; added: number }> {
  const zst = isZst(file.path);
  // Resume a plain transcript that only grew; anything else (new, shrunk, compressed) is read
  // from the start with a fresh context — the store's keys absorb the repeats.
  const resume =
    !zst && prior !== undefined && file.size >= prior.offset && file.size >= prior.size;
  const start = resume ? prior.offset : 0;
  const ctx = resume ? { ...prior.ctx } : newUsageContext();
  let offset = start;
  let added = 0;

  if (!zst && file.size <= start) {
    return { entry: { size: file.size, mtimeMs: file.mtimeMs, offset, ctx }, added };
  }
  // Read only up to the size we stat'ed: bytes appended meanwhile are next run's.
  const fileStream = fs.createReadStream(file.path, {
    start,
    ...(zst ? {} : { end: file.size - 1 }),
    highWaterMark: AI_READ_CHUNK_BYTES,
  });
  let stream: AsyncIterable<Buffer> = fileStream;
  if (zst) {
    const decoder = zstd!();
    // `pipe` does not forward a read error; surface it through the decoder we iterate.
    fileStream.on("error", (err) => decoder.destroy(err));
    stream = fileStream.pipe(decoder);
  }
  try {
    for await (const l of readByteLines(stream, AI_LINE_CAP_BYTES, stats)) {
      if (!l.complete && (l.line === null || !isWholeJson(l.line))) break;
      offset = start + l.end;
      if (l.line === null) continue;
      const e = parseUsageLine(l.line, ctx);
      if (e && e.at >= minAt && store.add(e)) added++;
    }
  } finally {
    fileStream.destroy();
  }
  return { entry: { size: file.size, mtimeMs: file.mtimeMs, offset, ctx }, added };
}

/**
 * Bring the store up to date with every transcript and return its events. Never throws for
 * one bad transcript (it is counted as unreadable and retried next run).
 */
export async function collectAiUsage(opts: AiCollectOptions): Promise<AiCollection> {
  const now = opts.now ?? Date.now();
  const zstd = opts.zstd === undefined ? detectZstd() : opts.zstd;
  const cursorPath = path.join(opts.env.configDir, AI_CURSOR_FILE);
  const storePath = path.join(opts.env.configDir, AI_STORE_FILE);
  const minAt = now - AI_RETENTION_DAYS * DAY_MS;

  // The cursor is only meaningful next to the store it fed: without a readable store,
  // start over from the transcripts.
  const loaded = deserializeStore(readJson(storePath));
  const store = loaded ?? new UsageStore();
  const cursor = loaded ? loadCursor(cursorPath) : new Map<string, CursorEntry>();

  const files = listTranscripts(opts.sources ?? aiSources(opts.env));
  const read = newReadStats();
  const scan: AiScanStats = {
    files: files.length,
    filesRead: 0,
    linesRead: 0,
    oversizeLines: 0,
    newEvents: 0,
    zstdSkipped: 0,
    unreadable: 0,
    peakBufferedBytes: 0,
  };
  const next = new Map<string, CursorEntry>();
  for (const f of files) {
    const prior = cursor.get(f.path);
    if (prior && prior.size === f.size && prior.mtimeMs === f.mtimeMs) {
      next.set(f.path, prior);
      continue;
    }
    if (isZst(f.path) && !zstd) {
      scan.zstdSkipped++;
      continue;
    }
    try {
      const r = await readTranscript(f, prior, store, zstd, read, minAt);
      next.set(f.path, r.entry);
      scan.filesRead++;
      scan.newEvents += r.added;
    } catch {
      scan.unreadable++;
      if (prior) next.set(f.path, prior);
    }
  }
  scan.linesRead = read.lines;
  scan.oversizeLines = read.oversize;
  scan.peakBufferedBytes = read.peakBufferedBytes;

  store.prune(minAt);
  if (!opts.readOnly) {
    // Store first: a crash between the two writes re-reads lines next run, which the keys
    // absorb; the other order would lose them.
    writeJsonPrivate(storePath, serializeStore(store));
    const files: Record<string, CursorEntry> = {};
    for (const [p, e] of [...next].sort((a, b) => a[0].localeCompare(b[0]))) files[p] = e;
    writeJsonPrivate(cursorPath, { version: 1, files } satisfies CursorFile);
  }
  return { events: store.events(), scan };
}

// ---------------------------------------------------------------------------
// Attribution: cwd → nearest repo root
// ---------------------------------------------------------------------------

/**
 * A memoised `cwd → repo` resolver returning the home-relative repo root (`~/code/app`), or
 * null for `(no repo)`. Roots a discovery walk already found (C1, `Discovery.repos()`) win via
 * the shared `nearestRoot`; otherwise the same rule the walk uses — a folder holding a `.git`
 * directory or `gitdir:` file, never the home folder itself — is checked upward from the cwd,
 * which costs a few stats per distinct directory instead of a walk of the whole home.
 */
export function repoResolver(
  env: Pick<SweepEnv, "home" | "platform">,
  knownRoots: readonly string[] = [],
): (cwd: string | null) => string | null {
  const cache = new Map<string, string | null>();
  return (cwd) => {
    if (!cwd) return null;
    const hit = cache.get(cwd);
    if (hit !== undefined) return hit;
    const root =
      (knownRoots.length > 0 ? nearestRoot(cwd, knownRoots) : null) ?? findRepoUp(cwd, env);
    const out = root === null ? null : displayPath(root, env);
    cache.set(cwd, out);
    return out;
  };
}

function findRepoUp(cwd: string, env: Pick<SweepEnv, "home" | "platform">): string | null {
  const home = normPath(env.home, env.platform);
  const underHome = isUnder(cwd, env.home, env.platform);
  let dir = cwd.replace(/[\\/]+$/, "") || cwd;
  for (let i = 0; i < 64; i++) {
    const here = normPath(dir, env.platform);
    if (here === home) return null;
    if (fs.existsSync(path.join(dir, ".git"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    if (underHome && !isUnder(parent, env.home, env.platform)) return null;
    dir = parent;
  }
  return null;
}
