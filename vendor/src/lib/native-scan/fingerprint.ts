// ---------------------------------------------------------------------------
// Endpoint Sweep fingerprinting + grouping (ENDPOINT-SWEEP-AND-PACKAGE-MAP.md
// § A2.3) — PURE (node:crypto only; no fs, no clock, no randomness: the salt is
// an input).
//
// One secret copied into 140 editor-history files is ONE finding with 140
// locations. A fingerprint is an HMAC of the normalized secret under a salt that
// never leaves the device (or, for an enrolled device, the org salt — so the
// same key on five laptops groups into one org finding without the server ever
// seeing it).
//
// The raw secret exists only as an argument to `fingerprint` — nothing here
// stores or returns it.
// ---------------------------------------------------------------------------

import { createHmac } from "node:crypto";
import type { Severity } from "@/lib/org-security";
import { SEVERITY_ORDER } from "@/lib/charts/palette";
import { LOCATION_CLASSES, type LocationClass } from "@/lib/native-scan/path-rules";

/** Fingerprint = first 16 bytes of the HMAC-SHA256, hex → 32 chars. */
export const FINGERPRINT_BYTES = 16;

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/** Literal backslash escapes a PEM picks up when embedded in JSON/JSONL/shell. */
const ESCAPED_BREAKS = /\\r\\n|\\n|\\r/g;

/**
 * Canonical form of a secret so the same material in two files matches.
 * Whitespace is trimmed; a PEM block additionally has every line break — real or
 * the literal `\n` of a JSON string — and all whitespace collapsed, so a key
 * saved with CRLF, LF, wrapped at a different width, or pasted into a transcript
 * normalizes identically.
 */
export function normalizeSecret(secret: string): string {
  const trimmed = secret.trim();
  if (trimmed.includes("-----BEGIN")) {
    return trimmed.replace(ESCAPED_BREAKS, "").replace(/\s+/g, "");
  }
  return trimmed;
}

/**
 * The first complete PEM block in `text` (BEGIN … matching END), or the
 * BEGIN-to-end-of-text remainder when the END marker is missing (a truncated
 * head probe). Null when there is no BEGIN marker. Accepts JSON-escaped `\n`.
 */
export function extractPemBlock(text: string): string | null {
  const begin = text.search(/-----BEGIN [A-Z0-9 ]+-----/);
  if (begin < 0) return null;
  const rest = text.slice(begin);
  const end = rest.search(/-----END [A-Z0-9 ]+-----/);
  if (end < 0) return rest;
  const tail = rest.slice(end).match(/^-----END [A-Z0-9 ]+-----/);
  return rest.slice(0, end + (tail ? tail[0].length : 0));
}

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------

function mac(salt: Uint8Array, domain: string, data: string | Uint8Array): string {
  if (salt.length === 0) throw new Error("fingerprint salt must not be empty");
  return createHmac("sha256", salt)
    .update(domain)
    .update(data)
    .digest()
    .subarray(0, FINGERPRINT_BYTES)
    .toString("hex");
}

/** HMAC-SHA256(salt, normalized secret), truncated to 16 bytes, hex (32 chars). */
export function fingerprint(salt: Uint8Array, secret: string): string {
  return mac(salt, "rw-secret:", normalizeSecret(secret));
}

/**
 * Fingerprint for a hit with no extractable secret (an encrypted PKCS#12 bundle,
 * a cookie jar): the HMAC of the file content. Domain-separated from `fingerprint`
 * so a content hash can never collide with a secret's.
 */
export function contentFingerprint(salt: Uint8Array, content: string | Uint8Array): string {
  return mac(salt, "rw-content:", content);
}

/**
 * Fingerprint for a private key given text that contains it: the normalized PEM
 * block when one is present, else the content hash of the whole text.
 */
export function fingerprintPem(salt: Uint8Array, text: string): string {
  const block = extractPemBlock(text);
  return block ? fingerprint(salt, block) : contentFingerprint(salt, text);
}

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

export interface EndpointLocation {
  /** Absolute or `~/`-relative path of the file holding a copy. */
  path: string;
  locationClass: LocationClass;
  /** 1-based line of the first hit in the file, when line-addressable. */
  line?: number;
  /** File modification time (ms epoch) — feeds first/last seen. */
  mtimeMs?: number;
  /**
   * Where the content ORIGINALLY lived, when `path` is an opaque copy — an editor's
   * local-history entry (`History/-6a9ea81e/9ya8.prod`) records the resource it
   * snapshotted. A home-relative display path; local reporting only, never uploaded.
   */
  origin?: string;
}

/** One located hit, already fingerprinted and location-adjusted. */
export interface EndpointMatch {
  fingerprint: string;
  ruleId: string;
  /** Severity AFTER `adjustSeverity` / backup raising. */
  severity: Severity;
  /** `maskSecret` output, or "" when the rule carries no secret to preview. */
  preview: string;
  location: EndpointLocation;
}

export interface EndpointGroup {
  fingerprint: string;
  ruleId: string;
  /** Max severity across the group's locations. */
  severity: Severity;
  preview: string;
  /** Distinct files holding the secret. */
  copies: number;
  locations: EndpointLocation[];
  locationClasses: Partial<Record<LocationClass, number>>;
  /** Oldest / newest location mtime, when known. */
  firstSeenMs?: number;
  lastSeenMs?: number;
}

const sevRank = (s: Severity) => SEVERITY_ORDER.indexOf(s);

/** Label preference: a provider-specific content rule (carries the rotation link
 *  and a masked preview) beats a path rule, which beats the catch-all generic
 *  assignment rule. */
function ruleRank(ruleId: string): number {
  if (ruleId === "generic-secret-assignment") return 2;
  return ruleId.startsWith("path.") ? 1 : 0;
}

/** Better group label: lower rank, then more severe, then alphabetical. */
function betterRule(a: EndpointMatch, b: EndpointMatch): EndpointMatch {
  const byRank = ruleRank(a.ruleId) - ruleRank(b.ruleId);
  if (byRank !== 0) return byRank < 0 ? a : b;
  const bySev = sevRank(a.severity) - sevRank(b.severity);
  if (bySev !== 0) return bySev < 0 ? a : b;
  return a.ruleId <= b.ruleId ? a : b;
}

const classRank = (c: LocationClass) => LOCATION_CLASSES.indexOf(c);

/**
 * Group matches by fingerprint. Copies are distinct PATHS (the same secret on
 * three lines of one file is one copy). Output order is stable: severity (worst
 * first), copies descending, ruleId, then fingerprint. Inputs are not mutated.
 */
export function groupMatches(matches: readonly EndpointMatch[]): EndpointGroup[] {
  const byFp = new Map<string, EndpointMatch[]>();
  for (const m of matches) {
    const list = byFp.get(m.fingerprint);
    if (list) list.push(m);
    else byFp.set(m.fingerprint, [m]);
  }

  const groups: EndpointGroup[] = [];
  for (const [fp, list] of byFp) {
    let label = list[0]!;
    let severity = list[0]!.severity;
    for (const m of list) {
      label = betterRule(label, m);
      if (sevRank(m.severity) < sevRank(severity)) severity = m.severity;
    }

    // One location per distinct path; keep the lowest line / earliest mtime.
    const byPath = new Map<string, EndpointLocation>();
    for (const m of list) {
      const prev = byPath.get(m.location.path);
      if (!prev) {
        byPath.set(m.location.path, { ...m.location });
      } else if (
        m.location.line !== undefined &&
        (prev.line === undefined || m.location.line < prev.line)
      ) {
        prev.line = m.location.line;
      }
    }
    const locations = [...byPath.values()].sort(
      (a, b) =>
        classRank(a.locationClass) - classRank(b.locationClass) || a.path.localeCompare(b.path),
    );

    const locationClasses: Partial<Record<LocationClass, number>> = {};
    for (const loc of locations) {
      locationClasses[loc.locationClass] = (locationClasses[loc.locationClass] ?? 0) + 1;
    }
    const mtimes = locations.map((l) => l.mtimeMs).filter((t): t is number => t !== undefined);

    groups.push({
      fingerprint: fp,
      ruleId: label.ruleId,
      severity,
      preview: label.preview || (list.find((m) => m.preview)?.preview ?? ""),
      copies: locations.length,
      locations,
      locationClasses,
      ...(mtimes.length
        ? { firstSeenMs: Math.min(...mtimes), lastSeenMs: Math.max(...mtimes) }
        : {}),
    });
  }

  return groups.sort(
    (a, b) =>
      sevRank(a.severity) - sevRank(b.severity) ||
      b.copies - a.copies ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.fingerprint.localeCompare(b.fingerprint),
  );
}
