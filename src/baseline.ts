// The local baseline (§ A2.4): ~/.repo-wrapped/sweep-baseline.json.
//
// Holds fingerprints, rule ids, counts and the home-relative paths of the copies
// — NEVER the secret and never the masked preview. The paths stay on the device
// (the agent guard reads them to refuse a copy a previous sweep found); only the
// opt-in upload (A3) leaves the machine, and it has its own path policy.

import fs from "node:fs";
import path from "node:path";
import type { EndpointGroup } from "@/lib/native-scan/fingerprint";
import type { Severity } from "@/lib/org-security";
import type { SweepEnv } from "./env";
import type { ScanScope } from "./scan";
import { writeJsonPrivate } from "./state";

export const BASELINE_SCHEMA_VERSION = 1;
/** Paths kept per finding — enough for the hook, bounded for a 140-copy key. */
export const MAX_BASELINE_LOCATIONS = 500;

export interface BaselineEntry {
  ruleId: string;
  copies: number;
  /** Home-relative (`~/…`) paths of the copies. Local only. */
  locations: string[];
  /** Max severity across the copies. Absent in baselines written before it was
   *  recorded — the agent guard then treats the entry as blocking. */
  severity?: Severity;
  firstSeen: string;
  lastSeen: string;
  /** Set by `sweep fix` once the copies are gone; cleared if the secret reappears. */
  resolvedAt?: string;
}

export interface Baseline {
  schemaVersion: 1;
  updatedAt: string;
  findings: Record<string, BaselineEntry>;
}

export function defaultBaselinePath(env: SweepEnv): string {
  return path.join(env.configDir, "sweep-baseline.json");
}

/** Read the baseline; null when missing or unreadable (a broken baseline must
 *  never fail a sweep — it just means everything is new). */
export function loadBaseline(file: string): Baseline | null {
  try {
    const j = JSON.parse(fs.readFileSync(file, "utf8")) as Partial<Baseline>;
    if (
      j.schemaVersion !== BASELINE_SCHEMA_VERSION ||
      !j.findings ||
      typeof j.findings !== "object"
    ) {
      return null;
    }
    return { schemaVersion: 1, updatedAt: String(j.updatedAt ?? ""), findings: j.findings };
  } catch {
    return null;
  }
}

export function saveBaseline(file: string, baseline: Baseline): void {
  writeJsonPrivate(file, baseline);
}

export interface BaselineDiff {
  /** A baseline file existed, so NEW/GONE markers are meaningful. */
  baselineExisted: boolean;
  /** Fingerprints not in the baseline (or reopened after being resolved). */
  newFingerprints: Set<string>;
  /** Baseline entries absent from this run — only reported for a full sweep. */
  gone: { fingerprint: string; ruleId: string }[];
}

/** NEW / GONE against the previous baseline. A partial scan (`quick`/`paths`)
 *  can't prove a secret is gone, so it reports no GONE. */
export function diffAgainstBaseline(
  groups: readonly EndpointGroup[],
  previous: Baseline | null,
  scope: ScanScope,
): BaselineDiff {
  const prev = previous?.findings ?? {};
  const newFingerprints = new Set<string>();
  for (const g of groups) {
    const entry = prev[g.fingerprint];
    if (!entry || entry.resolvedAt) newFingerprints.add(g.fingerprint);
  }
  const gone: BaselineDiff["gone"] = [];
  if (scope === "full" && previous) {
    const present = new Set(groups.map((g) => g.fingerprint));
    for (const [fingerprint, entry] of Object.entries(prev)) {
      if (!present.has(fingerprint) && !entry.resolvedAt) {
        gone.push({ fingerprint, ruleId: entry.ruleId });
      }
    }
    gone.sort(
      (a, b) => a.ruleId.localeCompare(b.ruleId) || a.fingerprint.localeCompare(b.fingerprint),
    );
  }
  return { baselineExisted: previous !== null, newFingerprints, gone };
}

/** The baseline after a run. A full sweep replaces it (what is gone is gone); a
 *  partial sweep only adds/refreshes what it saw. */
export function updateBaseline(
  groups: readonly EndpointGroup[],
  previous: Baseline | null,
  scope: ScanScope,
  nowIso: string,
): Baseline {
  const prev = previous?.findings ?? {};
  const findings: Record<string, BaselineEntry> = scope === "full" ? {} : { ...prev };
  for (const g of groups) {
    const before = prev[g.fingerprint];
    const reopened = before?.resolvedAt !== undefined;
    const locations = g.locations.map((l) => l.path);
    const merged =
      scope === "full" || !before ? locations : [...new Set([...before.locations, ...locations])];
    findings[g.fingerprint] = {
      ruleId: g.ruleId,
      copies: g.copies,
      locations: merged.slice(0, MAX_BASELINE_LOCATIONS),
      severity: g.severity,
      firstSeen: before && !reopened ? before.firstSeen : nowIso,
      lastSeen: nowIso,
    };
  }
  return { schemaVersion: BASELINE_SCHEMA_VERSION, updatedAt: nowIso, findings };
}
