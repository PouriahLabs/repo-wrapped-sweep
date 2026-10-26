// Per-file scanning + the sweep orchestrator (§ A2.2–A2.3).
//
// THE RAW SECRET LIVES ONLY IN THIS FILE'S LOCALS. `ContentScanner` receives
// `RawSecretMatch`es from the content engine, hashes each `raw` with the salt
// and immediately drops it; everything that leaves a function here (`EndpointMatch`,
// `ScanResult`) carries a fingerprint and a masked preview, never the secret.

import fs from "node:fs";
import { isBinaryExtension, looksBinary } from "@/lib/code-quality/file-view";
import {
  contentFingerprint,
  extractPemBlock,
  fingerprint,
  fingerprintPem,
  groupMatches,
  type EndpointGroup,
  type EndpointMatch,
} from "@/lib/native-scan/fingerprint";
import {
  HEAD_PROBE_BYTES,
  adjustSeverity,
  confirmPathRule,
  isExampleEnvFile,
  matchPath,
  raiseSeverity,
  shadowedContentRules,
  type LocationClass,
} from "@/lib/native-scan/path-rules";
import {
  maskSecret,
  scanTextRaw,
  type RawSecretMatch,
  type ScanTextOptions,
} from "@/lib/native-scan/secret-rules";
import type { Severity } from "@/lib/org-security";
import { displayPath, type SweepEnv } from "./env";
import { highRiskTargets, isConfigLikeFile, isNoiseFile, underFixtureDir } from "./locations";
import { createPowerShellProvider, type PlaceholderProvider } from "./placeholders";
import { createHistoryResolver, type HistoryResolver } from "./vscode-history";
import { redirectedKnownFolders, walk, type WalkFile, type WalkStats } from "./walk";

// --- caps (§ A2.1) ----------------------------------------------------------

/** Files above this are skipped, except streamed line files. */
export const MAX_FILE_BYTES = 5 * 1024 * 1024;
/** Files above this are scanned in overlapping line windows. */
export const WINDOW_THRESHOLD_BYTES = 256 * 1024;
/** Per-line cap for streamed files: the remainder of a longer line is dropped. */
export const LINE_CAP_CHARS = 64 * 1024;
/** Lines shared between consecutive windows so a match never straddles a cut. */
export const WINDOW_OVERLAP_LINES = 20;
const WINDOW_CHARS = 192 * 1024;
/** Distinct secrets kept per file (the engine itself caps each window at 8). */
const MAX_DISTINCT_PER_FILE = 64;
/**
 * A generic keyword assignment on a line longer than this is a minified bundle or a
 * data blob, not a config line a person wrote. Provider rules are not subject to it.
 */
export const GENERIC_MAX_LINE_CHARS = 1000;

export type ScanScope = "full" | "quick" | "paths";

export interface ScanOptions {
  env: SweepEnv;
  /** Explicit roots; empty = the home directory. Ignored when `quick`. */
  roots: string[];
  quick: boolean;
  excludeGlobs: string[];
  includeCloud: boolean;
  concurrency: number;
  /** The fingerprint salt (local, or the org salt for an enrolled device). */
  salt: Uint8Array;
  /** Walk installed-software trees too (`--no-default-excludes`). */
  noDefaultExcludes?: boolean;
  /**
   * Cloud-placeholder detection. Undefined → the real PowerShell lister on Windows, none
   * elsewhere; null → none (tests). With it, redirected Documents/Desktop are scanned and
   * online-only files are skipped without being downloaded.
   */
  placeholders?: PlaceholderProvider | null;
  onProgress?: (files: number) => void;
}

export interface ScanStats {
  /** Files opened and examined. */
  files: number;
  skippedDirs: number;
  skippedCloud: number;
  skippedLarge: number;
  skippedBinary: number;
  /** Files that could not be read (permission denied). */
  skippedFiles: number;
  /** Online-only cloud items skipped without being opened or downloaded. */
  skippedPlaceholders: number;
  /** Cloud folders skipped because their file attributes could not be read. */
  skippedUnknownAttrs: number;
  errors: number;
  deniedByTop: Record<string, number>;
}

export interface ScanResult {
  scope: ScanScope;
  startedAt: string;
  finishedAt: string;
  groups: EndpointGroup[];
  stats: ScanStats;
  notes: string[];
}

interface ScanCounters {
  files: number;
  skippedLarge: number;
  skippedBinary: number;
}

// ---------------------------------------------------------------------------
// Streamed / windowed content scanning
// ---------------------------------------------------------------------------

/** A content hit with the secret already reduced to a fingerprint. */
interface ContentHit {
  ruleId: string;
  severity: Severity;
  line: number;
  fingerprint: string;
  preview: string;
}

/**
 * Feeds lines through the content engine in overlapping windows. Dedupes hits
 * re-found in the overlap and bounds the distinct hits per file.
 */
class ContentScanner {
  private buf: string[] = [];
  private bufChars = 0;
  private firstLine = 1;
  private readonly seen = new Set<string>();
  readonly hits: ContentHit[] = [];

  /**
   * `onSecret` is for LOCAL recovery only (`recoverSecret`: the keychain and
   * validity steps need the value back). The normal sweep never passes it, so the
   * raw span stays inside `toHit`.
   */
  constructor(
    private readonly salt: Uint8Array,
    private readonly onSecret?: (fingerprint: string, raw: string) => void,
    private readonly engine: ScanTextOptions = {},
  ) {}

  /** Scan a whole text as one window (small files). */
  scanWhole(text: string): void {
    this.buf = text.split("\n");
    this.firstLine = 1;
    this.flush();
  }

  pushLine(line: string): void {
    this.buf.push(line);
    this.bufChars += line.length + 1;
    if (this.bufChars >= WINDOW_CHARS) {
      this.flush();
      const keep = this.buf.slice(-WINDOW_OVERLAP_LINES);
      this.firstLine += this.buf.length - keep.length;
      this.buf = keep;
      this.bufChars = keep.reduce((n, l) => n + l.length + 1, 0);
    }
  }

  finish(): void {
    if (this.buf.length > 0) this.flush();
    this.buf = [];
  }

  private flush(): void {
    if (this.hits.length >= MAX_DISTINCT_PER_FILE) return;
    const text = this.buf.join("\n");
    for (const m of scanTextRaw(text, this.engine)) {
      if (this.hits.length >= MAX_DISTINCT_PER_FILE) return;
      const hit = this.toHit(m);
      if (!hit) continue;
      const key = `${hit.ruleId}|${hit.fingerprint}|${hit.line}`;
      if (this.seen.has(key)) continue;
      this.seen.add(key);
      this.hits.push(hit);
    }
  }

  private toHit(m: RawSecretMatch): ContentHit | null {
    const line = this.firstLine + m.line - 1;
    if (m.redacted) {
      const fp = fingerprint(this.salt, m.raw);
      this.onSecret?.(fp, m.raw);
      return {
        ruleId: m.ruleId,
        severity: m.severity,
        line,
        fingerprint: fp,
        preview: maskSecret(m.raw),
      };
    }
    // A bare PEM-header hit: `raw` is only the marker, so fingerprint the key
    // block that follows it, and let the key-file confirmation decide whether
    // it is encrypted (low) or live (critical).
    const fromHeader = this.buf.slice(m.line - 1).join("\n");
    const confirmation = confirmPathRule("path.private-key", fromHeader.slice(0, HEAD_PROBE_BYTES));
    if (!confirmation.fires) return null;
    const pemFp = fingerprintPem(this.salt, fromHeader);
    if (this.onSecret) {
      const block = extractPemBlock(fromHeader);
      if (block) this.onSecret(pemFp, block);
    }
    return {
      ruleId: m.ruleId,
      severity: confirmation.severity,
      line,
      fingerprint: pemFp,
      preview: "",
    };
  }
}

/**
 * Split a utf8 stream into lines, dropping everything past `cap` chars on any
 * one line (a transcript line carrying a multi-MB base64 image must not be
 * buffered whole). Yields at least one (possibly empty) line for non-empty input.
 */
export async function* readCappedLines(
  stream: AsyncIterable<string | Buffer>,
  cap: number,
): AsyncGenerator<string> {
  let cur = "";
  let overflow = false;
  for await (const chunk of stream) {
    const s = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    let start = 0;
    for (let i = 0; i < s.length; i++) {
      if (s.charCodeAt(i) !== 10) continue;
      if (!overflow) {
        cur += s.slice(start, i);
        if (cur.length > cap) cur = cur.slice(0, cap);
      }
      yield cur.endsWith("\r") ? cur.slice(0, -1) : cur;
      cur = "";
      overflow = false;
      start = i + 1;
    }
    if (!overflow && start < s.length) {
      cur += s.slice(start);
      if (cur.length > cap) {
        cur = cur.slice(0, cap);
        overflow = true;
      }
    }
  }
  if (cur.length > 0) yield cur.endsWith("\r") ? cur.slice(0, -1) : cur;
}

// ---------------------------------------------------------------------------
// One file
// ---------------------------------------------------------------------------

const streamedByClass: ReadonlySet<LocationClass> = new Set(["shell-history", "agent-transcript"]);

/** `*.jsonl` and shell-history files are streamed by line and exempt from the
 *  5 MB cap (they are append-only logs that grow without bound). */
export function isStreamedFile(abs: string, locationClass: LocationClass): boolean {
  return abs.toLowerCase().endsWith(".jsonl") || streamedByClass.has(locationClass);
}

async function readHead(abs: string): Promise<string> {
  const fh = await fs.promises.open(abs, "r");
  try {
    const buf = Buffer.alloc(HEAD_PROBE_BYTES);
    const { bytesRead } = await fh.read(buf, 0, HEAD_PROBE_BYTES, 0);
    return buf.subarray(0, bytesRead).toString("utf8");
  } finally {
    await fh.close().catch(() => {});
  }
}

interface FileContext {
  env: SweepEnv;
  salt: Uint8Array;
  counters: ScanCounters;
  /**
   * The sweep's scope. In a FULL (home-directory) sweep a keyword assignment is only
   * believable in config-like files, logs and history; an explicit `--root` is the
   * person asking for everything under it.
   */
  scope?: ScanScope;
  /** VS Code history snapshot → the file it was a copy of. */
  resolveOrigin?: HistoryResolver;
}

/** The content-engine options for one file (see `FileContext.scope`). */
function engineOptionsFor(
  abs: string,
  locationClass: LocationClass,
  scope: ScanScope | undefined,
): ScanTextOptions {
  return {
    skipGeneric: scope === "full" && !isConfigLikeFile(abs, locationClass),
    genericMaxLineChars: GENERIC_MAX_LINE_CHARS,
  };
}

/**
 * Scan one file: the path rule (content-confirmed from a 4 KB head probe) plus
 * the content rules. Returns fingerprinted, location-adjusted matches only.
 */
export async function scanFile(file: WalkFile, ctx: FileContext): Promise<EndpointMatch[]> {
  const abs = file.path;
  const { locationClass } = file;
  const name = abs.replace(/\\/g, "/").split("/").pop() ?? abs;
  if (isNoiseFile(name) || isExampleEnvFile(abs)) return [];

  // A VS Code history snapshot has an opaque name; its directory's entries.json says
  // which file it was a copy of. A copy of `.env.example` is not a finding.
  const origin =
    locationClass === "editor-history" && ctx.resolveOrigin ? await ctx.resolveOrigin(abs) : null;
  if (origin && isExampleEnvFile(origin)) return [];

  const st = await fs.promises.stat(abs);
  if (!st.isFile()) return [];
  ctx.counters.files++;

  const pathHit = matchPath(abs, locationClass);
  const finding = pathHit && pathHit.ruleId !== "path.env-backup" ? pathHit : null;
  const backup = pathHit?.backup ?? false;
  const streamed = isStreamedFile(abs, locationClass);
  const scanner = new ContentScanner(
    ctx.salt,
    undefined,
    engineOptionsFor(abs, locationClass, ctx.scope),
  );

  // Whether we have the file's text in memory (for the path confirmation and
  // content fingerprints), and what it is.
  let text: string | null = null;

  const skipContent = finding?.ruleId === "path.pkcs12" || (isBinaryExtension(abs) && !finding);
  if (skipContent) {
    if (!finding) ctx.counters.skippedBinary++;
  } else if (streamed) {
    const stream = fs.createReadStream(abs, { encoding: "utf8" });
    try {
      for await (const line of readCappedLines(stream, LINE_CAP_CHARS)) scanner.pushLine(line);
    } finally {
      stream.destroy();
    }
    scanner.finish();
  } else if (st.size > MAX_FILE_BYTES) {
    ctx.counters.skippedLarge++;
  } else {
    const raw = await fs.promises.readFile(abs, "utf8");
    const bin = looksBinary(raw.slice(0, 65536));
    if (bin && !finding) {
      ctx.counters.skippedBinary++;
    } else {
      text = raw;
      if (bin) {
        // A binary key container: the path rule may still apply, content rules don't.
      } else if (raw.length <= WINDOW_THRESHOLD_BYTES) {
        scanner.scanWhole(raw);
      } else {
        for (const line of raw.split("\n")) scanner.pushLine(line.slice(0, LINE_CAP_CHARS));
        scanner.finish();
      }
    }
  }

  const matches: EndpointMatch[] = [];
  const display = displayPath(abs, ctx.env);
  const mtimeMs = st.mtimeMs;
  // A hit under a test/vendor/fixtures directory is a sample, not a leak. An editor-history
  // snapshot is judged by the path it was a copy OF (its own path is opaque); an agent
  // transcript is never a fixture, whatever it quotes.
  const fixturePath =
    locationClass === "agent-transcript"
      ? null
      : locationClass === "editor-history"
        ? origin
        : display;
  const inFixture = fixturePath !== null && underFixtureDir(fixturePath);
  const shaped = (severity: Severity): Severity => {
    if (inFixture) return "low";
    const bumped = backup ? raiseSeverity(severity) : severity;
    return adjustSeverity(bumped, locationClass);
  };
  const where = (line?: number) => ({
    path: display,
    locationClass,
    ...(line !== undefined ? { line } : {}),
    mtimeMs,
    ...(origin ? { origin } : {}),
  });

  // --- path rule ------------------------------------------------------------
  let shadowed: readonly string[] = [];
  if (finding) {
    if (finding.ruleId === "path.pkcs12") {
      const bytes = await fs.promises.readFile(abs);
      matches.push({
        fingerprint: contentFingerprint(ctx.salt, bytes.subarray(0, MAX_FILE_BYTES)),
        ruleId: finding.ruleId,
        severity: shaped(finding.severity),
        preview: "",
        location: where(),
      });
    } else {
      const head = text !== null ? text.slice(0, HEAD_PROBE_BYTES) : await readHead(abs);
      const c = confirmPathRule(finding.ruleId, head);
      // An env file that is only "confirmed" by a content hit is reported by
      // that hit; a path finding needs its own extractable secret.
      const standalone = finding.ruleId !== "path.env-file" || c.secret !== undefined;
      if (c.fires && standalone) {
        shadowed = shadowedContentRules(finding.ruleId);
        let fp: string;
        if (c.secret !== undefined) fp = fingerprint(ctx.salt, c.secret);
        else if (finding.ruleId === "path.private-key") {
          fp = fingerprintPem(ctx.salt, text ?? head);
        } else {
          const body = text ?? (await fs.promises.readFile(abs)).subarray(0, MAX_FILE_BYTES);
          fp = contentFingerprint(ctx.salt, body);
        }
        matches.push({
          fingerprint: fp,
          ruleId: finding.ruleId,
          severity: shaped(c.severity),
          preview: c.secret !== undefined ? maskSecret(c.secret) : "",
          location: where(),
        });
      }
    }
  }

  // --- content rules ---------------------------------------------------------
  for (const hit of scanner.hits) {
    if (shadowed.includes(hit.ruleId)) continue;
    matches.push({
      fingerprint: hit.fingerprint,
      ruleId: hit.ruleId,
      severity: shaped(hit.severity),
      preview: hit.preview,
      location: where(hit.line),
    });
  }
  return matches;
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const scope: ScanScope = opts.quick ? "quick" : opts.roots.length > 0 ? "paths" : "full";
  const baseRoots = opts.quick
    ? highRiskTargets(opts.env)
    : opts.roots.length > 0
      ? opts.roots
      : [opts.env.home];

  // Cloud placeholders (Windows): the real lister unless a test injected one.
  const ownProvider = opts.placeholders === undefined && opts.env.platform === "win32";
  const placeholders: PlaceholderProvider | null =
    opts.placeholders !== undefined
      ? opts.placeholders
      : ownProvider
        ? createPowerShellProvider()
        : null;

  // Known Folder Move: Documents/Desktop live inside OneDrive, which the cloud skip
  // never enters from the home directory. Seed them directly — safe only because
  // placeholders are recognised and left unopened. (With --include-cloud the home walk
  // already reaches them.)
  const redirected =
    scope === "full" && placeholders && !opts.includeCloud
      ? await redirectedKnownFolders(opts.env)
      : [];
  const roots = [...baseRoots, ...redirected.map((r) => r.path)];

  const counters: ScanCounters = { files: 0, skippedLarge: 0, skippedBinary: 0 };
  const matches: EndpointMatch[] = [];
  let reported = 0;
  const resolveOrigin = createHistoryResolver(opts.env);

  let walked: WalkStats;
  try {
    walked = await walk({
      roots,
      env: opts.env,
      excludeGlobs: opts.excludeGlobs,
      includeCloud: opts.includeCloud,
      concurrency: opts.concurrency,
      noteKnownFolders: scope !== "paths",
      noDefaultExcludes: opts.noDefaultExcludes,
      placeholders,
      cloudAllowRoots: redirected.map((r) => r.path),
      onFile: async (f) => {
        // Failures propagate to the walker, which counts them (permission skips and
        // errors separately) and never lets one file stop the sweep.
        const found = await scanFile(f, {
          env: opts.env,
          salt: opts.salt,
          counters,
          scope,
          resolveOrigin,
        });
        for (const m of found) matches.push(m);
        if (opts.onProgress && ++reported % 500 === 0) opts.onProgress(counters.files);
      },
    });
  } finally {
    if (ownProvider) await placeholders?.close();
  }
  opts.onProgress?.(counters.files);

  return {
    scope,
    startedAt,
    finishedAt: new Date().toISOString(),
    groups: groupMatches(matches),
    stats: {
      files: counters.files,
      skippedDirs: walked.skippedDirs,
      skippedCloud: walked.skippedCloud,
      skippedLarge: counters.skippedLarge,
      skippedBinary: counters.skippedBinary,
      skippedFiles: walked.skippedFiles,
      skippedPlaceholders: walked.skippedPlaceholders,
      skippedUnknownAttrs: walked.skippedUnknownAttrs,
      errors: walked.errors,
      deniedByTop: walked.deniedByTop,
    },
    notes: walked.notes,
  };
}

// ---------------------------------------------------------------------------
// Local secret recovery (fix / --validate only)
// ---------------------------------------------------------------------------

/**
 * Re-read one file and return the raw secret whose salted fingerprint is
 * `target`, or null. LOCAL ONLY: it exists so `fix` can hand a secret to the OS
 * keychain and `--validate` can ask the secret's own provider whether it still
 * works. The caller must keep the value in a local, hash/send it nowhere else,
 * and never log it.
 */
export async function recoverSecret(
  abs: string,
  locationClass: LocationClass,
  target: string,
  salt: Uint8Array,
): Promise<string | null> {
  let found: string | null = null;
  const scanner = new ContentScanner(salt, (fp, raw) => {
    if (fp === target && found === null) found = raw;
  });

  let st: fs.Stats;
  try {
    st = await fs.promises.stat(abs);
  } catch {
    return null;
  }
  if (!st.isFile()) return null;

  let text: string | null = null;
  if (isStreamedFile(abs, locationClass)) {
    const stream = fs.createReadStream(abs, { encoding: "utf8" });
    try {
      for await (const line of readCappedLines(stream, LINE_CAP_CHARS)) scanner.pushLine(line);
    } finally {
      stream.destroy();
    }
    scanner.finish();
  } else if (st.size <= MAX_FILE_BYTES) {
    const raw = await fs.promises.readFile(abs, "utf8");
    if (looksBinary(raw.slice(0, 65536))) return null;
    text = raw;
    if (raw.length <= WINDOW_THRESHOLD_BYTES) scanner.scanWhole(raw);
    else {
      for (const line of raw.split("\n")) scanner.pushLine(line.slice(0, LINE_CAP_CHARS));
      scanner.finish();
    }
  }
  if (found !== null) return found;

  // Secrets only the path rules extract (an .npmrc token, an env value, a whole
  // PEM key file) — the same extraction the sweep used to fingerprint them.
  const hit = matchPath(abs, locationClass);
  if (hit && hit.ruleId !== "path.env-backup" && text !== null) {
    const confirmation = confirmPathRule(hit.ruleId, text.slice(0, HEAD_PROBE_BYTES));
    if (confirmation.fires) {
      if (confirmation.secret !== undefined) {
        if (fingerprint(salt, confirmation.secret) === target) return confirmation.secret;
      } else if (hit.ruleId === "path.private-key" && fingerprintPem(salt, text) === target) {
        return extractPemBlock(text);
      }
    }
  }
  return null;
}
