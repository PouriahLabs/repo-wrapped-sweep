// ---------------------------------------------------------------------------
// File viewer — pure, isomorphic helpers shared by the server loader
// (`file-loader.ts` / the `/api/deep-scan/*/file` route) and the client drawer.
//
// Everything here is I/O-free and unit-tested: language inference from the file
// extension, the binary/size guards that keep a huge or non-text blob from ever
// reaching the (server-side) highlighter, HTML escaping, and the plain-text
// line split used when a language has no grammar. The shiki call itself lives in
// `highlight.ts` (server-only); this file must stay importable from the client
// for its TYPES, so it never touches shiki.
// ---------------------------------------------------------------------------

/** Above this, we truncate before highlighting — a multi-MB minified blob would
 *  blow the highlighter's time budget and isn't readable line-by-line anyway. */
export const MAX_FILE_BYTES = 256 * 1024;

/** One rendered line of the file view. `html` is trusted, server-produced markup
 *  (shiki token spans, or escaped plain text) — safe for `dangerouslySetInnerHTML`
 *  because the loader is the only writer and it escapes everything it doesn't
 *  hand to shiki. `finding` marks a line the drawer draws a gutter marker on. */
export interface HighlightedLine {
  number: number;
  html: string;
  finding: boolean;
}

export type FileViewPayload =
  | {
      ok: true;
      lines: HighlightedLine[];
      /** false → the language had no grammar and lines are escaped plain text. */
      highlighted: boolean;
      lang: string | null;
      truncated: boolean;
      /** The ref actually read (the requested ref, or the default branch). */
      resolvedRef: string;
      defaultBranch: string;
      branches: string[];
    }
  | {
      ok: false;
      reason: "not-found" | "binary" | "too-large" | "unavailable" | "not-configured";
    };

// --- Language inference ----------------------------------------------------
// Extension → shiki bundled-language id. Kept deliberately small: the common
// source languages a scanner flags, plus a few config formats. An unmapped
// extension returns null and the loader falls back to plain (escaped) text —
// never an error. Some map to a distinct grammar id (a `.tsx` needs the `tsx`
// grammar, not `typescript`, or JSX highlights wrong).

const EXT_TO_LANG: Record<string, string> = {
  ts: "typescript",
  mts: "typescript",
  cts: "typescript",
  tsx: "tsx",
  js: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  jsx: "jsx",
  json: "json",
  jsonc: "json",
  yml: "yaml",
  yaml: "yaml",
  py: "python",
  rb: "ruby",
  go: "go",
  rs: "rust",
  java: "java",
  c: "c",
  h: "c",
  cc: "cpp",
  cpp: "cpp",
  hpp: "cpp",
  cxx: "cpp",
  php: "php",
  css: "css",
  scss: "scss",
  html: "html",
  htm: "html",
  sh: "shellscript",
  bash: "shellscript",
  zsh: "shellscript",
  sql: "sql",
  md: "markdown",
  markdown: "markdown",
  toml: "toml",
  xml: "xml",
  kt: "kotlin",
  kts: "kotlin",
  swift: "swift",
  cs: "csharp",
};

/** Lowercased extension after the last dot, or "" for a dotfile / no extension. */
export function fileExtension(path: string): string {
  const base = path.slice(path.lastIndexOf("/") + 1);
  const dot = base.lastIndexOf(".");
  // dot <= 0 covers "no dot" and a leading-dot dotfile (".gitignore") — neither
  // has a usable extension for grammar selection.
  return dot <= 0 ? "" : base.slice(dot + 1).toLowerCase();
}

/** The shiki grammar id for a path, or null when we don't ship (or can't infer)
 *  one — the loader then renders escaped plain text. */
export function langFromPath(path: string): string | null {
  return EXT_TO_LANG[fileExtension(path)] ?? null;
}

// --- Binary guard ----------------------------------------------------------
// Two cheap, independent checks. The extension list catches the obvious binary
// assets before we even fetch bytes; the content sniff catches everything else
// (a NUL byte or a high density of C0 control chars is the classic "this isn't
// text" signal). Either → the drawer shows a short note + the GitHub link.

const BINARY_EXTENSIONS = new Set([
  "png",
  "jpg",
  "jpeg",
  "gif",
  "webp",
  "avif",
  "bmp",
  "ico",
  "tiff",
  "pdf",
  "zip",
  "gz",
  "tar",
  "tgz",
  "bz2",
  "xz",
  "7z",
  "rar",
  "woff",
  "woff2",
  "ttf",
  "otf",
  "eot",
  "mp3",
  "mp4",
  "wav",
  "ogg",
  "webm",
  "mov",
  "avi",
  "flac",
  "m4a",
  "wasm",
  "exe",
  "dll",
  "so",
  "dylib",
  "bin",
  "class",
  "o",
  "a",
  "jar",
  "keystore",
  "p12",
  "pfx",
  "der",
  "psd",
  "sketch",
  "fig",
  "blend",
  "glb",
  "gltf",
]);

export function isBinaryExtension(path: string): boolean {
  return BINARY_EXTENSIONS.has(fileExtension(path));
}

/**
 * Sniff whether decoded text is really binary. GitHub's raw media type hands
 * back a lossy UTF-8 decode of any blob, so a `.bin` with no extension match
 * still needs catching. A NUL byte is a hard no; otherwise we sample the first
 * chunk and reject if control chars (excluding tab/newline/CR) exceed ~10%.
 */
export function looksBinary(text: string): boolean {
  if (text.length === 0) return false;
  if (text.includes("\u0000")) return true; // a NUL byte is a hard "not text"
  const sample = text.slice(0, 4096);
  let control = 0;
  for (let i = 0; i < sample.length; i++) {
    const c = sample.charCodeAt(i);
    // Allow \t (9), \n (10), \r (13); count other C0 controls + DEL.
    if ((c < 32 && c !== 9 && c !== 10 && c !== 13) || c === 127) control++;
  }
  return control / sample.length > 0.1;
}

/** UTF-8 byte length without allocating a Buffer (works client + server). */
export function byteLength(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) bytes += 1;
    else if (c < 0x800) bytes += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      // High surrogate — a full code point is 4 bytes; skip its low surrogate.
      bytes += 4;
      i++;
    } else bytes += 3;
  }
  return bytes;
}

/**
 * Truncate at the last whole line under `MAX_FILE_BYTES`. Returns the (possibly
 * shortened) text and whether it was cut, so the drawer can flag a partial view
 * rather than silently showing an incomplete file.
 */
export function capText(
  text: string,
  maxBytes: number = MAX_FILE_BYTES,
): {
  text: string;
  truncated: boolean;
} {
  if (byteLength(text) <= maxBytes) return { text, truncated: false };
  // Character-count proxy for the byte cap (safe: bytes ≥ chars), then trim back
  // to a line boundary so we never render a half-tokenized final line.
  let cut = text.slice(0, maxBytes);
  const lastNl = cut.lastIndexOf("\n");
  if (lastNl > 0) cut = cut.slice(0, lastNl);
  return { text: cut, truncated: true };
}

const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch]);
}

/**
 * Split raw text into escaped-plain-text lines — the fallback when no grammar
 * matched. Line numbers are 1-based; `findingLines` marks the gutter. An empty
 * final line (trailing newline) is dropped so the count matches the editor's.
 */
export function toPlainLines(text: string, findingLines: ReadonlySet<number>): HighlightedLine[] {
  const raw = text.split("\n");
  if (raw.length > 1 && raw[raw.length - 1] === "") raw.pop();
  return raw.map((line, i) => ({
    number: i + 1,
    // A blank line still needs a non-empty box to keep the row height; a NBSP
    // placeholder does that without affecting copy/paste meaningfully.
    html: line.length ? escapeHtml(line) : "&nbsp;",
    finding: findingLines.has(i + 1),
  }));
}

/**
 * Normalize a git ref to what GitHub's Contents API and blob URLs accept: a bare
 * branch/tag name or a commit SHA. Code-scanning alerts carry a fully-qualified
 * `refs/heads/main` / `refs/tags/v1`, which neither surface resolves as-is — so
 * strip those prefixes. Anything else (a raw SHA, or an unusual ref like a PR
 * ref) is passed through untouched; a ref that then doesn't resolve degrades to
 * the "View on GitHub" fallback rather than an error.
 */
export function normalizeGitRef(ref: string): string {
  if (ref.startsWith("refs/heads/")) return ref.slice("refs/heads/".length);
  if (ref.startsWith("refs/tags/")) return ref.slice("refs/tags/".length);
  return ref;
}

/** Parse a `lines=203,45` query value into a de-duped set of positive ints. */
export function parseFindingLines(raw: string | null): Set<number> {
  const out = new Set<number>();
  if (!raw) return out;
  for (const part of raw.split(",")) {
    const n = Number.parseInt(part, 10);
    if (Number.isInteger(n) && n > 0) out.add(n);
  }
  return out;
}
