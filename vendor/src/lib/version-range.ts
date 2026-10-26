// Semver range helpers shared by the Package Map (ADR 039) and Machine Insights
// toolchain drift (ENDPOINT-MACHINE-INSIGHTS § C2.3) — PURE, `semver` only.
//
// Lives on its own (not in `org/package-map.ts`) so the sweep CLI can bundle it
// without dragging in the Package Map's zod schemas.

import semver from "semver";

/** Parse a lockfile, manifest or `--version` string; null when it isn't a version at all. */
export function parseVersion(raw: string): semver.SemVer | null {
  const v = raw.trim().replace(/^[=v]+/, "");
  return semver.parse(v, { loose: true }) ?? semver.parse(semver.coerce(v)?.version ?? "");
}

/**
 * Does the declared range admit `latest`? npm semantics: a range reaches a pre-release
 * only when it names one on the same major.minor.patch (`^1.2.0` does NOT admit
 * `1.3.0-beta.1`). Only a VALID semver range can exclude it; a dist-tag, git URL or
 * alias is "unknown", reported as allowing (we claim a block only when we can prove one).
 */
export function rangeAllowsLatest(range: string, latest: string | null): boolean {
  if (!latest) return true;
  const l = parseVersion(latest);
  const valid = semver.validRange(range.trim(), { loose: true });
  if (!l || !valid) return true;
  return semver.satisfies(l, valid, { loose: true });
}
