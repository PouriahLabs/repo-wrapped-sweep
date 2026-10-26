// ---------------------------------------------------------------------------
// Native secret-scan rule engine (CODE-QUALITY-NATIVE-SCANNERS.md § 3) — PURE,
// no I/O, heavily unit-tested. The crux of the free secret scanner: a curated,
// HIGH-PRECISION rule set (the gitleaks/trufflehog family) run over a file's
// text, plus a keyword-anchored entropy gate and an allowlist for the usual
// false positives (`.env.example` placeholders, obvious fakes, lockfile hashes).
//
// Two invariants this module holds no matter what:
//   1. PRECISION OVER RECALL. A false positive on the free board is worse than a
//      miss — every generic/entropy rule is anchored to a secret-looking
//      identifier and allowlist-filtered. Structured provider patterns
//      (distinctive prefixes) fire on their own but still pass the allowlist.
//   2. REDACTION IS MANDATORY. The raw secret is NEVER stored or returned —
//      `scanText` emits only a MASKED preview (first/last 2 chars). The raw
//      match string lives only inside this function's dedupe key and is dropped.
//
// The engine is deliberately deterministic (no clock, no randomness): the same
// text always yields the same findings in the same order, so the file board is
// stable across renders.
// ---------------------------------------------------------------------------

import type { Severity } from "@/lib/org-security";
import { SEVERITY_ORDER } from "@/lib/charts/palette";

/** Cap on findings kept per file (mirrors deep-scan's `MAX_FINDINGS_PER_FILE`,
 *  findings.ts:23): a file "leaking" 40 secrets is almost always one repeated
 *  pattern, and unbounded findings would bloat the snapshot. */
export const MAX_SECRET_FINDINGS_PER_FILE = 8;

/** Hard cap on how much of a file the engine scans. `selectScanFiles` already
 *  drops files over 128 KB, but `scanText` is also called directly, so this
 *  bounds the regex budget on any input (a giant minified line can't wedge us). */
export const MAX_SCAN_TEXT_CHARS = 256 * 1024;

/**
 * One curated detection rule. `regex` MUST carry the global flag (the engine
 * iterates `matchAll`); a named `secret` capture group narrows the redacted/
 * gated span to the actual secret (defaults to the whole match). The optional
 * gates are SECONDARY — they only ever *reject* a raw regex hit, never widen it.
 */
export interface SecretRule {
  id: string;
  severity: Severity;
  /** Human summary prefix shown before the masked preview. */
  description: string;
  regex: RegExp;
  /** Min Shannon entropy (bits/char) required of the captured secret to fire. */
  entropyGate?: number;
  /** Min length of the captured secret to even consider. */
  minSecretLength?: number;
  /** Require ≥2 character classes (lower/upper/digit/symbol) — kills prose that
   *  happens to clear the entropy bar. */
  requireMixedClasses?: boolean;
  /** When false, the match marks a location but carries no preview (the actual
   *  secret body is deliberately never captured — e.g. a PEM private-key block). */
  redact?: boolean;
}

/** A redacted finding as it leaves the engine. NEVER carries the raw secret. */
export interface SecretMatch {
  ruleId: string;
  severity: Severity;
  /** 1-based line the secret sits on (the BEGIN line for a multiline block). */
  line: number;
  /** Human summary carrying only a MASKED preview of the secret. */
  message: string;
}

// ---------------------------------------------------------------------------
// Redaction — the raw secret must never leave this module verbatim.
// ---------------------------------------------------------------------------

/**
 * Mask a secret to a preview that reveals AT MOST the first and last two
 * characters, with the middle collapsed. A secret of 8 chars or fewer reveals
 * nothing at all (too short to expose safely). The result can never contain the
 * raw secret as a substring — the middle is always replaced.
 */
export function maskSecret(secret: string): string {
  if (secret.length <= 8) return "•".repeat(Math.min(secret.length, 6)) || "•";
  return `${secret.slice(0, 2)}••••…${secret.slice(-2)}`;
}

// ---------------------------------------------------------------------------
// Entropy — the secondary gate. Shannon entropy over the character histogram.
// ---------------------------------------------------------------------------

/** Shannon entropy in bits/char (0 for empty or single-symbol strings). */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** How many distinct character classes the string spans (prose is 1; a random
 *  token is 2–4). Used to reject natural-language values that clear entropy. */
function characterClasses(s: string): number {
  let n = 0;
  if (/[a-z]/.test(s)) n++;
  if (/[A-Z]/.test(s)) n++;
  if (/[0-9]/.test(s)) n++;
  if (/[^A-Za-z0-9]/.test(s)) n++;
  return n;
}

// ---------------------------------------------------------------------------
// Allowlist — the false-positive floor. Runs on EVERY rule's captured secret,
// so a structured provider hit (AWS docs example key) is dropped too.
// ---------------------------------------------------------------------------

// Substrings that a real random secret effectively never contains but that
// placeholders/examples/fakes overflow with. Case-insensitive. Deliberately
// multi-character so an incidental "test"/"foo" inside a real base64 blob
// doesn't suppress a true positive.
const PLACEHOLDER_SUBSTRINGS = [
  "example",
  "placeholder",
  "changeme",
  "change-me",
  "change_me",
  "your-",
  "your_",
  "yourapi",
  "yourkey",
  "yourtoken",
  "yoursecret",
  "dummy",
  "sample",
  "redacted",
  "notreal",
  "replace-me",
  "replaceme",
  "replace_me",
  "insert-your",
  "insert_your",
  "inserthere",
  "<your",
  "xxxxx",
  "todo",
  "fixme",
  "lorem",
  "ipsum",
  "foobar",
  "deadbeef",
  "test-key",
  "testkey",
  "test-token",
  "testtoken",
  "test-secret",
  "secret123",
  "password123",
  "123456789",
  "abcdefg",
  "qwerty",
  "hunter2",
  "s3cr3t",
];

// Values that are placeholders in their entirety (would otherwise dodge the
// substring list). Compared against the lowercased whole secret.
const EXACT_PLACEHOLDERS = new Set([
  "null",
  "none",
  "nil",
  "n/a",
  "na",
  "undefined",
  "true",
  "false",
  "changeme",
  "password",
  "secret",
  "token",
  "test",
  "example",
  "placeholder",
]);

/** A value that is one repeated char (`aaaa…`) or a short repeated block
 *  (`abcabcabc`, `xyzxyzxyz`) — never a real secret. */
function isRepeated(s: string): boolean {
  return /^(.)\1{4,}$/.test(s) || /^(.{2,4})\1{2,}$/.test(s);
}

/**
 * Is this captured value a known false positive? Placeholder text, an obvious
 * fake, an env-var interpolation (`${…}`, `{{…}}`, `<%= … %>`), a lockfile
 * integrity hash (`sha512-…`), or a trivially repeated string. Pure and
 * case-insensitive on the placeholder markers.
 */
export function isAllowlisted(secret: string): boolean {
  const lower = secret.toLowerCase();
  if (EXACT_PLACEHOLDERS.has(lower)) return true;
  for (const marker of PLACEHOLDER_SUBSTRINGS) {
    if (lower.includes(marker)) return true;
  }
  if (isRepeated(secret)) return true;
  // Env-var interpolation / templating — the value is a reference, not a secret.
  if (
    /\$\{|\{\{|<%|%\(|process\.env|import\.meta\.env|os\.environ|os\.getenv|getenv\(/i.test(secret)
  )
    return true;
  // Angle-bracket placeholders (`<token>`, `<REPLACE>`) — a bracket is never
  // part of a real credential the providers below emit.
  if (secret.includes("<") || secret.includes(">")) return true;
  // Package-manager integrity hashes (npm/yarn) that survive into scanned YAML.
  if (/^sha(1|256|384|512)-/i.test(secret)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// The curated rule set. Order matters: structured provider patterns come FIRST
// so that when a value is caught by both a provider rule and the generic
// keyword rule, dedupe keeps the higher-precision provider finding.
// ---------------------------------------------------------------------------

/** One PEM line break: raw (`\n`, `\r\n`) or JSON-escaped once or more (`\n`, `\\n`, `\r\n`). */
const PEM_BREAK = String.raw`(?:\r?\n|(?:\\+r)?\\+n)`;

export const SECRET_RULES: SecretRule[] = [
  // --- Private keys (PEM blocks) — the header alone is proof; the body is
  //     never captured, so there is nothing to leak (redact:false). ----------
  {
    id: "private-key",
    severity: "critical",
    description: "Private key material committed to source",
    // The header alone is NOT a key: docs, placeholders (`MIIB...`) and scanner
    // source mention it constantly. Require real key material — at least one
    // 40+ char base64 line after the header (and any `Proc-Type:`/`DEK-Info:`
    // lines). Line breaks may be raw or JSON-escaped (`\n`, `\\n`), since keys
    // pasted into chats land in transcripts escaped.
    regex: new RegExp(
      String.raw`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[ \t]*` +
        PEM_BREAK +
        String.raw`(?:[A-Za-z-]+:[^\r\n\\]*` +
        PEM_BREAK +
        `)*(?:${PEM_BREAK})?` +
        String.raw`[A-Za-z0-9+/]{40,}`,
      "g",
    ),
    redact: false,
  },

  // --- Cloud providers ------------------------------------------------------
  {
    id: "aws-access-key-id",
    severity: "critical",
    description: "AWS access key ID",
    // AKIA/ASIA/AGPA/… + 16 uppercase base36. The distinctive prefix carries it.
    regex: /\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
  },
  {
    id: "aws-secret-access-key",
    severity: "critical",
    description: "AWS secret access key",
    // No distinctive shape (40 base64 chars) → keyword-anchored to the well-known
    // identifier, then entropy-gated so a 40-char non-secret can't sneak through.
    regex: /aws_?secret_?access_?key["']?\s*[:=]\s*["'`]?(?<secret>[A-Za-z0-9/+]{40})["'`]?/gi,
    entropyGate: 3.5,
    requireMixedClasses: true,
  },
  {
    id: "gcp-api-key",
    severity: "high",
    description: "Google API key",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },

  // --- GitHub tokens --------------------------------------------------------
  {
    id: "github-personal-access-token",
    severity: "critical",
    description: "GitHub personal access token",
    regex: /\bghp_[A-Za-z0-9]{36}\b/g,
  },
  {
    id: "github-oauth-token",
    severity: "critical",
    description: "GitHub OAuth access token",
    regex: /\bgho_[A-Za-z0-9]{36}\b/g,
  },
  {
    id: "github-app-token",
    severity: "critical",
    description: "GitHub app installation/user token",
    regex: /\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b/g,
  },
  {
    id: "github-refresh-token",
    severity: "critical",
    description: "GitHub refresh token",
    regex: /\bghr_[A-Za-z0-9]{36,}\b/g,
  },
  {
    id: "github-fine-grained-pat",
    severity: "critical",
    description: "GitHub fine-grained personal access token",
    regex: /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/g,
  },

  // --- Payment / comms providers -------------------------------------------
  {
    id: "stripe-secret-key",
    severity: "critical",
    description: "Stripe live secret key",
    regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b/g,
  },
  {
    id: "slack-token",
    severity: "critical",
    description: "Slack token",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    id: "slack-webhook-url",
    severity: "high",
    description: "Slack incoming webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/g,
  },
  {
    id: "twilio-api-key",
    severity: "high",
    description: "Twilio API key SID",
    regex: /\bSK[0-9a-fA-F]{32}\b/g,
  },
  {
    id: "sendgrid-api-key",
    severity: "critical",
    description: "SendGrid API key",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
  },
  {
    id: "npm-access-token",
    severity: "critical",
    description: "npm access token",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
  },

  // --- JWTs — a distinctive three-segment shape, but frequently NON-secret
  //     (public bearer tokens), so weighted medium, not critical. ------------
  {
    id: "jwt",
    severity: "medium",
    description: "JSON Web Token",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },

  // --- Generic keyword-anchored assignments (LAST — lowest precision). Both
  //     forms require a secret-looking identifier on the left AND clear the
  //     entropy + mixed-class + allowlist gates. -----------------------------
  {
    id: "generic-secret-assignment",
    severity: "high",
    description: "Hardcoded secret assignment",
    // key contains a secret keyword → `= "value"` (quoted; single/double/back).
    // `\b[\w.-]*` lets the keyword sit at the very start of a line (`api_key:`).
    regex:
      /\b[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|credential|client[_-]?secret|private[_-]?key)[\w.-]*["']?\s*[:=]\s*(?<q>["'`])(?<secret>[^"'`\n]{12,200})\k<q>/gi,
    entropyGate: 3.0,
    minSecretLength: 12,
    requireMixedClasses: true,
  },
  {
    id: "generic-secret-assignment",
    severity: "high",
    description: "Hardcoded secret assignment",
    // Unquoted form (YAML/env-style `key: value`) — gated harder (higher entropy,
    // longer min) because the lack of quotes removes a precision signal.
    regex:
      /\b[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key)[\w.-]*\s*[:=]\s*(?<secret>[A-Za-z0-9+/_=.-]{20,200})(?=$|\s|["',;)])/gim,
    entropyGate: 3.6,
    minSecretLength: 20,
    requireMixedClasses: true,
  },
];

// ---------------------------------------------------------------------------
// Line-number resolution — offset → 1-based line via a precomputed index.
// ---------------------------------------------------------------------------

/** Offsets at which each line begins (index 0 = line 1). */
function buildLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10 /* \n */) starts.push(i + 1);
  }
  return starts;
}

/** 1-based line containing `offset`, via binary search over the line starts. */
function lineForOffset(starts: number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

// ---------------------------------------------------------------------------
// The engine.
// ---------------------------------------------------------------------------

interface RawHit {
  rule: SecretRule;
  /** The raw secret span — used ONLY for gating + the dedupe key; never emitted. */
  raw: string;
  line: number;
}

/** Rank a hit's rule for the per-file cap (worst severity kept first). */
function severityRank(sev: Severity): number {
  return SEVERITY_ORDER.indexOf(sev);
}

/** Apply a rule's secondary gates to a captured secret; true = keep. */
function passesGates(rule: SecretRule, secret: string): boolean {
  // No real credential contains whitespace — a quoted value that does is prose
  // (`"hello world this is a note"`) clearing the entropy bar via its spaces.
  if (/\s/.test(secret)) return false;
  if (rule.minSecretLength !== undefined && secret.length < rule.minSecretLength) return false;
  if (rule.requireMixedClasses && characterClasses(secret) < 2) return false;
  if (rule.entropyGate !== undefined && shannonEntropy(secret) < rule.entropyGate) return false;
  return true;
}

/**
 * A match that still carries the raw secret span. ONLY for in-process callers
 * that must fingerprint the secret (the endpoint CLI): the raw value may be
 * hashed but must never be stored, logged or serialised. `scanText` — the
 * public, redacting entry point — is a thin wrapper that drops `raw`.
 */
export interface RawSecretMatch extends SecretMatch {
  /** The captured secret span (the header marker for `redact:false` rules). */
  raw: string;
  /** False when the rule never captures the secret body (e.g. a PEM header). */
  redacted: boolean;
}

/** The catch-all keyword-anchored assignment rule (both of its forms). */
export const GENERIC_RULE_ID = "generic-secret-assignment";

/** Optional narrowing for `scanTextRaw`. Defaults leave behaviour exactly as `scanText`. */
export interface ScanTextOptions {
  /** Skip the generic keyword-assignment rule (provider rules still run). */
  skipGeneric?: boolean;
  /** Ignore generic-rule hits on a line longer than this many characters. */
  genericMaxLineChars?: number;
}

function lineLength(text: string, lineStarts: number[], line: number): number {
  const start = lineStarts[line - 1] ?? 0;
  const end = lineStarts[line] !== undefined ? lineStarts[line]! - 1 : text.length;
  return end - start;
}

/**
 * Same engine as `scanText`, but each match also carries the raw secret span so
 * a caller can fingerprint it. Pure and deterministic. Never log or persist
 * `raw` — see `RawSecretMatch`.
 */
export function scanTextRaw(text: string, options: ScanTextOptions = {}): RawSecretMatch[] {
  if (!text) return [];
  const body = text.length > MAX_SCAN_TEXT_CHARS ? text.slice(0, MAX_SCAN_TEXT_CHARS) : text;
  const lineStarts = buildLineStarts(body);

  const hits: RawHit[] = [];
  // Dedupe raw hits across rules by line + secret span, keeping the FIRST rule
  // that claimed them (rule order = precision order: providers before generic).
  const seen = new Set<string>();

  for (const rule of SECRET_RULES) {
    if (options.skipGeneric && rule.id === GENERIC_RULE_ID) continue;
    for (const m of body.matchAll(rule.regex)) {
      const groups = m.groups;
      // The secret span is the named `secret` group when present, else the whole
      // match. Redact/gate operate on this narrower span.
      const secret = groups?.secret ?? m[0];
      if (rule.redact !== false && !passesGates(rule, secret)) continue;
      if (rule.redact !== false && isAllowlisted(secret)) continue;

      // Offset of the secret span for the line number — prefer the group's
      // position (falls back to the match start for whole-match rules).
      const groupIndex = groups?.secret !== undefined ? m[0].indexOf(groups.secret) : 0;
      const offset = (m.index ?? 0) + (groupIndex >= 0 ? groupIndex : 0);
      const line = lineForOffset(lineStarts, offset);
      // A minified bundle is one enormous line of identifiers that look like
      // `token: "…"`; the generic rule has no business there.
      if (
        rule.id === GENERIC_RULE_ID &&
        options.genericMaxLineChars !== undefined &&
        lineLength(body, lineStarts, line) > options.genericMaxLineChars
      ) {
        continue;
      }

      const dedupeKey = `${rule.redact === false ? rule.id : secret}#${line}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      hits.push({ rule, raw: secret, line });
    }
  }

  // Worst-first, then by line for a stable order; cap per file.
  hits.sort(
    (a, b) => severityRank(a.rule.severity) - severityRank(b.rule.severity) || a.line - b.line,
  );

  const out: RawSecretMatch[] = [];
  for (const hit of hits) {
    if (out.length >= MAX_SECRET_FINDINGS_PER_FILE) break;
    const redacted = hit.rule.redact !== false;
    const message = redacted
      ? `${hit.rule.description}: ${maskSecret(hit.raw)}`
      : hit.rule.description;
    out.push({
      ruleId: hit.rule.id,
      severity: hit.rule.severity,
      line: hit.line,
      message,
      raw: hit.raw,
      redacted,
    });
  }
  return out;
}

/**
 * Scan text for secrets. Returns REDACTED matches (masked previews only) with
 * 1-based line numbers, deduped and capped at `MAX_SECRET_FINDINGS_PER_FILE`.
 * Pure and deterministic; never throws and never returns a raw secret.
 */
export function scanText(text: string): SecretMatch[] {
  return scanTextRaw(text).map(({ ruleId, severity, line, message }) => ({
    ruleId,
    severity,
    line,
    message,
  }));
}

/**
 * Does a string have the shape `maskSecret` produces — or is it empty (a rule
 * that carries no secret to preview)? The endpoint ingest uses this to reject a
 * client that tried to upload anything longer or more revealing than a masked
 * preview, so a client bug can never store a raw secret. Shape only: it cannot
 * (and does not try to) tell whether the two revealed characters are sensitive —
 * by construction `maskSecret` never reveals more than four characters.
 */
export function isMaskedPreview(preview: string): boolean {
  if (preview === "") return true;
  // ≤8-char secrets: 1–6 bullets and nothing else.
  if (/^\u2022{1,6}$/.test(preview)) return true;
  // Longer secrets: 2 chars, four bullets, an ellipsis, 2 chars — exactly 9 chars.
  return /^[^\r\n]{2}\u2022{4}\u2026[^\r\n]{2}$/.test(preview);
}
