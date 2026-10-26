// Reports (§ A2.4): terminal table, stable --json (schemaVersion 1) and a
// self-contained --html. Every renderer works from `EndpointGroup`s, which carry
// a fingerprint and a MASKED preview and nothing else — there is no raw secret
// anywhere in this module's reach.
//
// The Machine Insights reports (ENDPOINT-MACHINE-INSIGHTS § C2) live at the bottom:
// the same three outputs for `git` / `disk` / `toolchain` / `backup` / `insights`, plus
// the short summary a full sweep prints after its findings table.

import { SEVERITY_ORDER } from "@/lib/charts/palette";
import { describeBackupSummary } from "@/lib/endpoint/insights/backup";
import { describeDrift, driftHint } from "@/lib/endpoint/insights/drift";
import {
  describeGitSummary,
  staleStashCount,
  type GitSummary,
} from "@/lib/endpoint/insights/git-state";
import type { EndpointGroup, EndpointLocation } from "@/lib/native-scan/fingerprint";
import { LOCATION_CLASSES, rotationUrl, type LocationClass } from "@/lib/native-scan/path-rules";
import type { Severity } from "@/lib/org-security";
import type { BaselineDiff } from "./baseline";
import { displayPath, type SweepEnv } from "./env";
import { describeDisk, formatBytes } from "./insights/disk";
import type { InsightsResult } from "./insights";
import { describeToolchain } from "./insights/toolchain";
import type { ScanResult } from "./scan";
import type { Validity } from "./validate";

export const REPORT_SCHEMA_VERSION = 1;
/** Locations listed per finding in --json/--html (the full count is `copies`). */
export const REPORT_MAX_LOCATIONS = 50;

export interface ReportContext {
  version: string;
  os: string;
  diff: BaselineDiff;
  /** Interactive `--validate` results by fingerprint, when the check ran. */
  validity?: ReadonlyMap<string, Validity>;
}

const SEV_RANK = (s: Severity) => SEVERITY_ORDER.indexOf(s);

/** The location class holding most copies (ties → § A2.1 table order). */
export function topLocationClass(g: EndpointGroup): LocationClass {
  let best: LocationClass = "documents";
  let bestN = -1;
  for (const c of LOCATION_CLASSES) {
    const n = g.locationClasses[c] ?? 0;
    if (n > bestN) {
      best = c;
      bestN = n;
    }
  }
  return best;
}

/**
 * What to call a location in a report. A VS Code history snapshot is named by what it
 * is a copy of — `History/-6a9ea81e/9ya8.prod` tells nobody anything — and the real
 * path stays available in --json for `fix`.
 */
export function locationLabel(
  l: Pick<EndpointLocation, "path" | "locationClass" | "origin">,
): string {
  return l.origin && l.locationClass === "editor-history"
    ? `VS Code history of ${l.origin}`
    : l.path;
}

export function severityCounts(groups: readonly EndpointGroup[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const g of groups) out[g.severity]++;
  return out;
}

// ---------------------------------------------------------------------------
// Exit code (--fail-on)
// ---------------------------------------------------------------------------

export type FailOn = Severity | "new" | "none";

export function parseFailOn(value: string | undefined): FailOn | null {
  const v = (value ?? "high").toLowerCase();
  return v === "critical" ||
    v === "high" ||
    v === "medium" ||
    v === "low" ||
    v === "new" ||
    v === "none"
    ? v
    : null;
}

/** 0 clean · 1 findings at/above the threshold (or any NEW with `new`). */
export function exitCodeFor(
  groups: readonly EndpointGroup[],
  failOn: FailOn,
  diff: BaselineDiff,
): 0 | 1 {
  if (failOn === "none") return 0;
  if (failOn === "new") return groups.some((g) => diff.newFingerprints.has(g.fingerprint)) ? 1 : 0;
  const bar = SEV_RANK(failOn);
  return groups.some((g) => SEV_RANK(g.severity) <= bar) ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Terminal table
// ---------------------------------------------------------------------------

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  green: "\x1b[32m",
  magenta: "\x1b[35m",
};

export function severityColor(s: Severity): string {
  return s === "critical"
    ? ANSI.bold + ANSI.red
    : s === "high"
      ? ANSI.red
      : s === "medium"
        ? ANSI.yellow
        : ANSI.dim;
}

/** Shorten a path to `max` chars, keeping the tail (the filename is the clue). */
export function truncatePath(p: string, max: number): string {
  if (p.length <= max) return p;
  if (max <= 1) return "…".slice(0, max);
  return `…${p.slice(p.length - (max - 1))}`;
}

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

// Strip ANSI for width maths.
const visible = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");
function padVisible(s: string, n: number): string {
  const len = visible(s).length;
  return len >= n ? s : s + " ".repeat(n - len);
}

export interface TableOptions {
  color: boolean;
  /** Terminal width; the path column absorbs the slack. */
  width: number;
  /**
   * List low-severity findings too (`--all`). By default they are folded into one
   * summary line: on a full sweep they are overwhelmingly samples and vendored keys.
   */
  all?: boolean;
}

export function renderTable(result: ScanResult, ctx: ReportContext, opts: TableOptions): string {
  const c = (code: string, s: string) => (opts.color ? code + s + ANSI.reset : s);
  const lines: string[] = [];
  const { groups, stats } = result;
  const shown = opts.all ? groups : groups.filter((g) => g.severity !== "low");
  const hiddenLow = groups.length - shown.length;

  if (groups.length === 0) {
    lines.push(c(ANSI.green, "✓ No plaintext secrets found."));
  } else if (shown.length === 0) {
    lines.push(c(ANSI.green, "✓ No findings above low severity."));
  } else {
    const showNew = ctx.diff.baselineExisted;
    const rows = shown.map((g) => ({
      sev: g.severity.toUpperCase(),
      sevColor: severityColor(g.severity),
      rule: g.ruleId,
      preview: g.preview || "—",
      copies: String(g.copies),
      where: topLocationClass(g),
      path: g.locations[0] ? locationLabel(g.locations[0]) : "",
      isNew: showNew && ctx.diff.newFingerprints.has(g.fingerprint),
      validity: ctx.validity?.get(g.fingerprint),
    }));
    const w = {
      sev: Math.max(3, ...rows.map((r) => r.sev.length)),
      rule: Math.min(28, Math.max(4, ...rows.map((r) => r.rule.length))),
      preview: Math.max(7, ...rows.map((r) => r.preview.length)),
      copies: Math.max(6, ...rows.map((r) => r.copies.length)),
      where: Math.max(5, ...rows.map((r) => r.where.length)),
    };
    const fixed = w.sev + w.rule + w.preview + w.copies + w.where + 4 * 2 + 5 /* NEW */ + 2;
    const pathWidth = Math.max(20, opts.width - fixed);
    const head = [
      pad("SEV", w.sev),
      pad("RULE", w.rule),
      pad("PREVIEW", w.preview),
      pad("COPIES", w.copies),
      pad("WHERE", w.where),
      "FIRST PATH",
    ].join("  ");
    lines.push(c(ANSI.bold, head));
    for (const r of rows) {
      const tags = [
        r.isNew ? c(ANSI.green, "NEW") : "",
        r.validity === "live" ? c(ANSI.bold + ANSI.red, "LIVE") : "",
        r.validity === "revoked" ? c(ANSI.dim, "revoked") : "",
      ].filter(Boolean);
      const marker = tags.join(" ");
      lines.push(
        [
          c(r.sevColor, padVisible(r.sev, w.sev)),
          pad(r.rule.slice(0, w.rule), w.rule),
          pad(r.preview, w.preview),
          pad(r.copies, w.copies),
          pad(r.where, w.where),
          truncatePath(r.path, pathWidth),
        ].join("  ") + `  ${marker}`.trimEnd(),
      );
    }
  }

  const counts = severityCounts(groups);
  lines.push("");
  lines.push(
    `${groups.length} finding${groups.length === 1 ? "" : "s"}` +
      (groups.length
        ? ` (${SEVERITY_ORDER.filter((s) => counts[s] > 0)
            .map((s) => `${counts[s]} ${s}`)
            .join(", ")})`
        : "") +
      ` · ${stats.files.toLocaleString("en-US")} files scanned · ${result.scope} sweep`,
  );
  if (hiddenLow > 0) {
    lines.push(
      c(
        ANSI.dim,
        `${hiddenLow} low-severity finding${hiddenLow === 1 ? "" : "s"} not listed (samples, test fixtures and ` +
          "other low-risk copies) — run with --all to list them",
      ),
    );
  }
  if (ctx.diff.gone.length > 0) {
    lines.push(
      c(
        ANSI.green,
        `✓ ${ctx.diff.gone.length} finding${ctx.diff.gone.length === 1 ? "" : "s"} gone since the last run`,
      ),
    );
  }
  const denied = stats.skippedDirs + stats.skippedFiles;
  if (denied > 0) {
    const tops = Object.keys(stats.deniedByTop).length;
    lines.push(
      c(
        ANSI.yellow,
        `skipped ${denied} unreadable path${denied === 1 ? "" : "s"} in ${tops} folder${tops === 1 ? "" : "s"} — ` +
          "grant your terminal Full Disk Access (macOS) or run elevated to include them",
      ),
    );
  }
  if (stats.skippedLarge > 0)
    lines.push(c(ANSI.dim, `skipped ${stats.skippedLarge} file(s) over 5 MB`));
  for (const n of result.notes) lines.push(c(ANSI.dim, n));
  if (groups.length > 0) {
    lines.push(
      c(ANSI.dim, "Raw secrets are never printed. Use --json or --html for the full report."),
    );
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// JSON (schemaVersion 1)
// ---------------------------------------------------------------------------

export interface JsonReport {
  schemaVersion: 1;
  tool: "repo-wrapped-sweep";
  version: string;
  os: string;
  scope: ScanResult["scope"];
  startedAt: string;
  finishedAt: string;
  stats: ScanResult["stats"];
  notes: string[];
  summary: Record<Severity, number> & { total: number };
  findings: {
    fingerprint: string;
    ruleId: string;
    severity: Severity;
    preview: string;
    copies: number;
    isNew: boolean;
    validity?: Validity;
    locationClasses: Partial<Record<LocationClass, number>>;
    locations: { path: string; locationClass: LocationClass; line?: number; origin?: string }[];
    locationsTruncated: boolean;
    rotationUrl: string;
    firstSeen?: string;
    lastSeen?: string;
  }[];
  gone: { fingerprint: string; ruleId: string }[];
}

export function buildJsonReport(result: ScanResult, ctx: ReportContext): JsonReport {
  const counts = severityCounts(result.groups);
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: "repo-wrapped-sweep",
    version: ctx.version,
    os: ctx.os,
    scope: result.scope,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    stats: result.stats,
    notes: result.notes,
    summary: { ...counts, total: result.groups.length },
    findings: result.groups.map((g) => ({
      fingerprint: g.fingerprint,
      ruleId: g.ruleId,
      severity: g.severity,
      preview: g.preview,
      copies: g.copies,
      isNew: ctx.diff.baselineExisted && ctx.diff.newFingerprints.has(g.fingerprint),
      ...(ctx.validity?.has(g.fingerprint) ? { validity: ctx.validity.get(g.fingerprint) } : {}),
      locationClasses: g.locationClasses,
      locations: g.locations.slice(0, REPORT_MAX_LOCATIONS).map((l) => ({
        path: l.path,
        locationClass: l.locationClass,
        ...(l.line !== undefined ? { line: l.line } : {}),
        ...(l.origin ? { origin: l.origin } : {}),
      })),
      locationsTruncated: g.locations.length > REPORT_MAX_LOCATIONS,
      rotationUrl: rotationUrl(g.ruleId),
      ...(g.firstSeenMs !== undefined ? { firstSeen: new Date(g.firstSeenMs).toISOString() } : {}),
      ...(g.lastSeenMs !== undefined ? { lastSeen: new Date(g.lastSeenMs).toISOString() } : {}),
    })),
    gone: ctx.diff.gone,
  };
}

// ---------------------------------------------------------------------------
// HTML (self-contained, dark-first, the app's --sev-* tokens)
// ---------------------------------------------------------------------------

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** The reports' shared stylesheet: dark-first, the app's --sev-* tokens. */
const REPORT_CSS = `:root{color-scheme:dark light;--bg:40 6% 10%;--fg:40 14% 90%;--card:40 5% 13%;--border:40 4% 22%;--muted:42 7% 62%;
--sev-critical:0 61% 52%;--sev-high:17 79% 64%;--sev-medium:41 96% 54%;--sev-low:42 7% 62%}
@media (prefers-color-scheme:light){:root{--bg:40 30% 97%;--fg:30 8% 14%;--card:40 40% 99%;--border:40 14% 86%;--muted:35 7% 40%}}
body{margin:0;background:hsl(var(--bg));color:hsl(var(--fg));font:14px/1.5 system-ui,sans-serif;padding:24px}
main{max-width:1100px;margin:0 auto}h1{font-size:20px;margin:0 0 4px}
.muted{color:hsl(var(--muted))}code{font:12px ui-monospace,monospace;word-break:break-all}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;padding:10px 14px;min-width:90px}
.card b{display:block;font-size:22px}
table{width:100%;border-collapse:collapse;background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid hsl(var(--border));vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:hsl(var(--muted))}.num{text-align:right}
.sev{font-weight:600;text-transform:uppercase;font-size:12px}
.sev-critical{color:hsl(var(--sev-critical))}.sev-high{color:hsl(var(--sev-high))}.sev-medium{color:hsl(var(--sev-medium))}.sev-low{color:hsl(var(--sev-low))}
.live{font-size:11px;font-weight:700;color:hsl(var(--sev-critical))}.new{font-size:11px;font-weight:600;color:hsl(142 60% 50%)}summary{cursor:pointer}ul{margin:6px 0;padding-left:18px}a{color:inherit}`;

export function renderHtml(result: ScanResult, ctx: ReportContext): string {
  const report = buildJsonReport(result, ctx);
  const rows = report.findings
    .map((f) => {
      const locs = f.locations
        .map(
          (l) =>
            `<li><code>${escapeHtml(locationLabel(l))}</code> <span class="muted">${escapeHtml(l.locationClass)}</span></li>`,
        )
        .join("");
      return `<tr>
<td><span class="sev sev-${f.severity}">${escapeHtml(f.severity)}</span>${f.isNew ? ' <span class="new">NEW</span>' : ""}${f.validity === "live" ? ' <span class="live">LIVE KEY</span>' : f.validity === "revoked" ? ' <span class="muted">revoked</span>' : ""}</td>
<td><code>${escapeHtml(f.ruleId)}</code></td>
<td><code>${escapeHtml(f.preview || "—")}</code></td>
<td class="num">${f.copies}</td>
<td><details><summary>${escapeHtml(f.locations[0] ? locationLabel(f.locations[0]) : "")}</summary><ul>${locs}</ul>${
        f.locationsTruncated
          ? `<p class="muted">Showing ${REPORT_MAX_LOCATIONS} of ${f.copies}.</p>`
          : ""
      }</details></td>
<td><a href="${escapeHtml(f.rotationUrl)}" rel="noreferrer noopener">rotate</a></td>
</tr>`;
    })
    .join("\n");
  const s = report.summary;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Endpoint sweep report</title>
<style>
${REPORT_CSS}
</style>
</head>
<body>
<main>
<h1>Endpoint sweep report</h1>
<p class="muted">${escapeHtml(report.scope)} sweep · ${escapeHtml(report.finishedAt)} · repo-wrapped-sweep ${escapeHtml(report.version)} · raw secrets are never included</p>
<div class="cards">
<div class="card"><b>${s.total}</b>findings</div>
<div class="card"><b class="sev-critical">${s.critical}</b>critical</div>
<div class="card"><b class="sev-high">${s.high}</b>high</div>
<div class="card"><b class="sev-medium">${s.medium}</b>medium</div>
<div class="card"><b class="sev-low">${s.low}</b>low</div>
<div class="card"><b>${report.stats.files.toLocaleString("en-US")}</b>files scanned</div>
</div>
${
  rows
    ? `<table><thead><tr><th>Severity</th><th>Rule</th><th>Preview</th><th class="num">Copies</th><th>Where</th><th></th></tr></thead><tbody>
${rows}
</tbody></table>`
    : "<p>No plaintext secrets found.</p>"
}
${report.notes.map((n) => `<p class="muted">${escapeHtml(n)}</p>`).join("\n")}
</main>
</body>
</html>
`;
}

// ---------------------------------------------------------------------------
// Machine Insights (ENDPOINT-MACHINE-INSIGHTS § C2) — local reports only
// ---------------------------------------------------------------------------

const DAY_MS = 86_400_000;

/** `today`, `1 day ago`, `12 days ago`; `—` when unknown. */
export function ago(ms: number | null | undefined, now: number): string {
  if (ms === null || ms === undefined) return "—";
  const d = Math.max(0, Math.floor((now - ms) / DAY_MS));
  return d === 0 ? "today" : `${d} ${d === 1 ? "day" : "days"} ago`;
}

const iso = (ms: number | null | undefined) =>
  ms === null || ms === undefined ? null : new Date(ms).toISOString();

export interface InsightsJson {
  schemaVersion: 1;
  tool: "repo-wrapped-sweep";
  kind: "insights";
  version: string;
  os: string;
  scope: InsightsResult["scope"];
  collectedAt: string;
  git?: {
    line: string;
    /** "behind" counts are as of the last `git fetch` unless `fetched`. */
    fetched: boolean;
    summary: GitSummary;
    unknown: number;
    gitMissing: boolean;
    repos: Array<{
      path: string;
      states: string[];
      risk: number;
      failure?: string;
      fetchFailure?: string;
      branch?: string | null;
      upstream?: string | null;
      ahead?: number;
      behind?: number;
      staged?: number;
      modified?: number;
      untracked?: number;
      conflicted?: number;
      unpushedCommits?: number;
      unpushedBranches?: Array<{ name: string; unpushed: number }>;
      stashes?: number;
      staleStashes?: number;
      oldestStashAt?: string | null;
      hasRemote?: boolean;
      lastCommitAt?: string | null;
      dirtySince?: string | null;
    }>;
  };
  disk?: {
    line: string;
    staleDays: number;
    partial: boolean;
    totals: NonNullable<InsightsResult["disk"]>["totals"];
    folders: Array<{
      path: string;
      class: string;
      project: string;
      bytes: number;
      partial: boolean;
      lastTouched: string | null;
      stale: boolean;
      venv: boolean;
    }>;
    reportOnly: Array<{ path: string; bytes: number; partial: boolean }>;
    packageCaches: Array<{
      tool: string;
      label: string;
      path: string;
      bytes: number;
      partial: boolean;
    }>;
    dockerBytes: number | null;
  };
  toolchain?: {
    line: string;
    managers: string[];
    tools: Array<{ tool: string; version: string | null; status: string; extensions?: number }>;
    repos: Array<{
      path: string;
      pins: Array<{ tool: string; wanted: string; source: string }>;
      drift: Array<{
        tool: string;
        source: string;
        wanted: string;
        installed: string | null;
        reason: string;
        hint: string | null;
        text: string;
      }>;
    }>;
  };
  backup?: {
    line: string;
    summary: NonNullable<InsightsResult["backup"]>["summary"];
    projects: Array<{
      path: string;
      state: string;
      reason: string | null;
      bytes: number | null;
      partial: boolean;
      lastTouched: string | null;
      unpushedCommits: number;
      unpushedBranches: string[];
      uncommittedDays: number | null;
      gitUnknown?: boolean;
    }>;
  };
}

/** Machine Insights as JSON. Paths are home-relative (`~/…`), as in the sweep report. */
export function buildInsightsJson(
  r: InsightsResult,
  ctx: { version: string; os: string },
  env: Pick<SweepEnv, "home" | "platform">,
): InsightsJson {
  const now = Date.parse(r.collectedAt);
  const dp = (p: string) => displayPath(p, env);
  const out: InsightsJson = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: "repo-wrapped-sweep",
    kind: "insights",
    version: ctx.version,
    os: ctx.os,
    scope: r.scope,
    collectedAt: r.collectedAt,
  };
  if (r.git) {
    out.git = {
      line: describeGitSummary(r.git.summary),
      fetched: r.fetched === true,
      summary: r.git.summary,
      unknown: r.git.unknown,
      gitMissing: r.git.gitMissing,
      repos: r.git.repos.map((g) => {
        const s = g.state;
        const base = {
          path: dp(g.path),
          states: s ? g.states : ["unknown"],
          risk: g.risk,
          ...(g.failure ? { failure: g.failure } : {}),
          ...(g.fetchFailure ? { fetchFailure: g.fetchFailure } : {}),
        };
        if (!s) return base;
        return {
          ...base,
          branch: s.branch,
          upstream: s.upstream,
          ahead: s.ahead,
          behind: s.behind,
          staged: s.staged,
          modified: s.modified,
          untracked: s.untracked,
          conflicted: s.conflicted,
          unpushedCommits: s.unpushedCommits,
          unpushedBranches: s.unpushedBranches,
          stashes: s.stashTimes.length,
          staleStashes: staleStashCount(s, now),
          oldestStashAt: iso(s.stashTimes.length ? Math.min(...s.stashTimes) : null),
          hasRemote: s.hasRemote,
          lastCommitAt: iso(s.lastCommitAt),
          dirtySince: s.changed > 0 ? iso(s.dirtySince) : null,
        };
      }),
    };
  }
  if (r.disk) {
    const d = r.disk;
    out.disk = {
      line: describeDisk(d),
      staleDays: d.staleDays,
      partial: d.partial,
      totals: d.totals,
      folders: d.folders.map((f) => ({
        path: dp(f.path),
        class: f.cls,
        project: dp(f.project),
        bytes: f.bytes,
        partial: f.partial,
        lastTouched: iso(f.lastTouched),
        stale: f.stale,
        venv: f.venv,
      })),
      reportOnly: d.reportOnly.map((x) => ({
        path: dp(x.path),
        bytes: x.bytes,
        partial: x.partial,
      })),
      packageCaches: d.packageCaches.map((c) => ({ ...c, path: dp(c.path) })),
      dockerBytes: d.dockerBytes,
    };
  }
  if (r.toolchain) {
    const t = r.toolchain;
    out.toolchain = {
      line: describeToolchain(t, env),
      managers: t.managers,
      tools: t.tools.map((x) => ({
        tool: x.tool,
        version: x.version,
        status: x.status,
        ...(x.extensions !== undefined ? { extensions: x.extensions } : {}),
      })),
      repos: t.repos.map((rd) => ({
        path: dp(rd.path),
        pins: rd.pins,
        drift: rd.drift.map((d) => ({
          ...d,
          hint: driftHint(d, t.managers),
          text: describeDrift(d, t.managers),
        })),
      })),
    };
  }
  if (r.backup) {
    out.backup = {
      line: describeBackupSummary(r.backup.summary, now),
      summary: r.backup.summary,
      projects: r.backup.projects.map((p) => ({
        path: dp(p.path),
        state: p.state,
        reason: p.reason,
        bytes: p.bytes,
        partial: p.partial,
        lastTouched: iso(p.lastTouched),
        unpushedCommits: p.atRisk.unpushedCommits,
        unpushedBranches: p.atRisk.unpushedBranches,
        uncommittedDays: p.atRisk.uncommittedDays,
        ...(p.gitUnknown ? { gitUnknown: true } : {}),
      })),
    };
  }
  return out;
}

/** Rows → aligned columns (the last column is never padded). */
function columns(
  rows: string[][],
  header: string[],
  c: (code: string, s: string) => string,
): string[] {
  const widths = header.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => visible(r[i] ?? "").length)),
  );
  const line = (cells: string[]) =>
    cells
      .map((cell, i) => (i === cells.length - 1 ? cell : padVisible(cell, widths[i]!)))
      .join("  ")
      .trimEnd();
  return [c(ANSI.bold, line(header)), ...rows.map(line)];
}

export interface InsightsTextOptions {
  color: boolean;
  /** List clean repos, synced/pushed projects and absent tools too. */
  all?: boolean;
  /** Folders listed in the disk table (default 20, § C2.2). */
  top?: number;
}

/** The terminal report for `git` / `disk` / `toolchain` / `backup` / `insights`. */
export function renderInsightsText(
  r: InsightsResult,
  env: Pick<SweepEnv, "home" | "platform">,
  opts: InsightsTextOptions,
): string {
  const c = (code: string, s: string) => (opts.color ? code + s + ANSI.reset : s);
  const j = buildInsightsJson(r, { version: "", os: "" }, env);
  const now = Date.parse(r.collectedAt);
  const sections: string[][] = [];

  if (j.git && r.git) {
    const lines = [
      c(ANSI.bold, `Local git — ${r.git.repos.length} repo${r.git.repos.length === 1 ? "" : "s"}`) +
        c(ANSI.dim, j.git.fetched ? " (fetched just now)" : " (behind = as of the last fetch)"),
    ];
    if (r.git.gitMissing)
      lines.push(c(ANSI.yellow, "git was not found on PATH — repo state unknown"));
    const shown = j.git.repos.filter(
      (g) => opts.all || !(g.states.length === 1 && g.states[0] === "clean"),
    );
    if (shown.length > 0) {
      lines.push(
        ...columns(
          shown.map((g) => [
            g.failure ? `unknown (${g.failure})` : g.states.join(", "),
            String(g.unpushedCommits ?? "—"),
            g.untracked === undefined
              ? "—"
              : String((g.staged ?? 0) + (g.modified ?? 0) + (g.untracked ?? 0)),
            String(g.stashes ?? "—"),
            String(g.behind ?? "—"),
            g.lastCommitAt ? ago(Date.parse(g.lastCommitAt), now) : "—",
            g.path,
          ]),
          ["STATE", "UNPUSHED", "CHANGES", "STASHES", "BEHIND", "LAST COMMIT", "REPO"],
          c,
        ),
      );
    } else if (r.git.repos.length > 0) {
      lines.push(c(ANSI.green, "✓ every repo is clean and pushed"));
    }
    lines.push(j.git.line);
    if (r.git.unknown > 0 && !r.git.gitMissing) {
      lines.push(
        c(
          ANSI.yellow,
          `${r.git.unknown} repo${r.git.unknown === 1 ? "" : "s"} did not answer in time (state unknown)`,
        ),
      );
    }
    if (!opts.all && shown.length < r.git.repos.length) {
      lines.push(
        c(
          ANSI.dim,
          `${r.git.repos.length - shown.length} clean repos not listed — --all lists them`,
        ),
      );
    }
    sections.push(lines);
  }

  if (j.disk && r.disk) {
    const d = j.disk;
    const lines = [c(ANSI.bold, "Disk — regenerable build output and caches")];
    const top = d.folders.slice(0, opts.top ?? 20);
    if (top.length > 0) {
      lines.push(
        ...columns(
          top.map((f) => [
            `${f.partial ? "≥" : ""}${formatBytes(f.bytes)}`,
            f.class + (f.venv ? " (venv)" : ""),
            f.lastTouched ? ago(Date.parse(f.lastTouched), now) : "—",
            f.path + (f.stale ? c(ANSI.dim, `  untouched ${d.staleDays}+ days`) : ""),
          ]),
          ["SIZE", "CLASS", "LAST TOUCHED", "FOLDER"],
          c,
        ),
      );
      if (d.folders.length > top.length) {
        lines.push(
          c(
            ANSI.dim,
            `… ${d.folders.length - top.length} smaller folders not listed (--json lists all)`,
          ),
        );
      }
    }
    for (const pc of d.packageCaches) {
      lines.push(
        `${pc.label}: ${pc.partial ? "≥" : ""}${formatBytes(pc.bytes)} ${c(ANSI.dim, pc.path)}`,
      );
    }
    if (d.dockerBytes !== null) {
      lines.push(
        `Docker: ${formatBytes(d.dockerBytes)} ${c(ANSI.dim, "(report only — never cleaned)")}`,
      );
    }
    if (d.reportOnly.length > 0) {
      const bytes = d.reportOnly.reduce((n, x) => n + x.bytes, 0);
      lines.push(
        c(
          ANSI.dim,
          `dist/ and out/: ${d.reportOnly.length} folder${d.reportOnly.length === 1 ? "" : "s"}, ${formatBytes(bytes)} (reported only — often hand-built or committed)`,
        ),
      );
    }
    lines.push(d.line);
    sections.push(lines);
  }

  if (j.toolchain && r.toolchain) {
    const t = j.toolchain;
    const present = t.tools.filter((x) => x.status === "present");
    const lines = [
      c(ANSI.bold, `Toolchain — ${present.length} of ${t.tools.length} tools found`) +
        (t.managers.length ? c(ANSI.dim, ` · version managers: ${t.managers.join(", ")}`) : ""),
    ];
    if (present.length > 0) {
      lines.push(
        present
          .map(
            (x) =>
              `${x.tool} ${x.version}${x.extensions !== undefined ? ` (${x.extensions} extensions)` : ""}`,
          )
          .join(" · "),
      );
    }
    const unknown = t.tools.filter((x) => x.status !== "present" && x.status !== "absent");
    if (unknown.length > 0) {
      lines.push(
        c(ANSI.yellow, `no answer: ${unknown.map((x) => `${x.tool} (${x.status})`).join(", ")}`),
      );
    }
    if (opts.all) {
      const absent = t.tools.filter((x) => x.status === "absent").map((x) => x.tool);
      if (absent.length) lines.push(c(ANSI.dim, `not found: ${absent.join(", ")}`));
    }
    const drifting = t.repos.filter((x) => x.drift.length > 0);
    if (drifting.length > 0) {
      lines.push(
        ...columns(
          drifting.flatMap((rd) => rd.drift.map((d) => [rd.path, d.text])),
          ["REPO", "DRIFT"],
          c,
        ),
      );
    }
    lines.push(t.line);
    sections.push(lines);
  }

  if (j.backup && r.backup) {
    const b = j.backup;
    const lines = [
      c(
        ANSI.bold,
        `Backup coverage — ${b.projects.length} project${b.projects.length === 1 ? "" : "s"}`,
      ) +
        c(
          ANSI.dim,
          ` (${(["local-only", "partly-pushed", "pushed", "synced"] as const)
            .map((s) => `${b.summary.byState[s] ?? 0} ${s}`)
            .join(", ")})`,
        ),
    ];
    const shown = b.projects.filter(
      (p) => opts.all || p.state === "local-only" || p.state === "partly-pushed",
    );
    if (shown.length > 0) {
      lines.push(
        ...columns(
          shown.map((p) => {
            const risk: string[] = [];
            if (p.reason === "no-remote") risk.push("no remote");
            if (p.reason === "not-git") risk.push("not a git repo");
            if (p.unpushedCommits > 0) {
              risk.push(
                `${p.unpushedCommits} unpushed commit${p.unpushedCommits === 1 ? "" : "s"}` +
                  (p.unpushedBranches.length
                    ? ` (${p.unpushedBranches.slice(0, 3).join(", ")})`
                    : ""),
              );
            }
            if (p.uncommittedDays !== null) risk.push(`uncommitted for ${p.uncommittedDays} days`);
            if (p.gitUnknown) risk.push("git state unknown");
            return [
              p.state,
              p.bytes === null ? "—" : `${p.partial ? "≥" : ""}${formatBytes(p.bytes)}`,
              p.lastTouched ? ago(Date.parse(p.lastTouched), now) : "—",
              p.path,
              risk.join("; "),
            ];
          }),
          ["STATE", "SOURCE", "LAST TOUCHED", "PROJECT", "AT RISK"],
          c,
        ),
      );
    }
    lines.push(b.line);
    sections.push(lines);
  }

  return sections.map((s) => s.join("\n")).join("\n\n");
}

/** The short block a full sweep prints after its findings table (no toolchain probes). */
export function renderInsightsSummary(r: InsightsResult, opts: { color: boolean }): string {
  const c = (code: string, s: string) => (opts.color ? code + s + ANSI.reset : s);
  const now = Date.parse(r.collectedAt);
  const lines: string[] = [];
  if (r.git) lines.push(describeGitSummary(r.git.summary));
  if (r.backup) lines.push(describeBackupSummary(r.backup.summary, now));
  if (r.disk) lines.push(describeDisk(r.disk));
  if (lines.length === 0) return "";
  const label = "Insights  ";
  return [
    ...lines.map((l, i) => (i === 0 ? c(ANSI.bold, label) : " ".repeat(label.length)) + l),
    c(
      ANSI.dim,
      `${" ".repeat(label.length)}details: repo-wrapped-sweep insights · --no-insights hides this`,
    ),
  ].join("\n");
}

/** Machine Insights as a self-contained HTML page (same stylesheet as the sweep report). */
export function renderInsightsHtml(
  r: InsightsResult,
  ctx: { version: string; os: string },
  env: Pick<SweepEnv, "home" | "platform">,
): string {
  const j = buildInsightsJson(r, ctx, env);
  const now = Date.parse(r.collectedAt);
  const e = escapeHtml;
  const table = (head: string[], rows: string[][]) =>
    rows.length === 0
      ? ""
      : `<table><thead><tr>${head.map((h) => `<th>${e(h)}</th>`).join("")}</tr></thead><tbody>
${rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("\n")}
</tbody></table>`;
  const when = (s: string | null | undefined) => e(s ? ago(Date.parse(s), now) : "—");
  const parts: string[] = [];
  const cards: string[] = [];

  if (j.git) {
    const g = j.git;
    cards.push(
      `<div class="card"><b>${g.summary.localOnlyRepos}</b>repos with local-only work</div>`,
    );
    parts.push(`<h2>Local git</h2>
<p>${e(g.line)} <span class="muted">· ${g.fetched ? "fetched just now" : "behind = as of the last fetch"}</span></p>
${table(
  ["State", "Unpushed", "Stashes", "Behind", "Last commit", "Repo"],
  g.repos.map((x) => [
    e(x.failure ? `unknown (${x.failure})` : x.states.join(", ")),
    String(x.unpushedCommits ?? "—"),
    String(x.stashes ?? "—"),
    String(x.behind ?? "—"),
    when(x.lastCommitAt),
    `<code>${e(x.path)}</code>`,
  ]),
)}`);
  }
  if (j.disk) {
    const d = j.disk;
    cards.push(
      `<div class="card"><b>${e(formatBytes(d.totals.staleReclaimableBytes))}</b>reclaimable (untouched ${d.staleDays}+ days)</div>`,
    );
    parts.push(`<h2>Disk</h2>
<p>${e(d.line)}</p>
${table(
  ["Size", "Class", "Last touched", "Folder"],
  d.folders.map((f) => [
    `${f.partial ? "≥" : ""}${e(formatBytes(f.bytes))}`,
    e(f.class),
    when(f.lastTouched) + (f.stale ? ' <span class="muted">stale</span>' : ""),
    `<code>${e(f.path)}</code>`,
  ]),
)}
${d.packageCaches.map((pc) => `<p>${e(pc.label)}: ${e(formatBytes(pc.bytes))} <code class="muted">${e(pc.path)}</code></p>`).join("\n")}
${d.dockerBytes !== null ? `<p>Docker: ${e(formatBytes(d.dockerBytes))} <span class="muted">(report only)</span></p>` : ""}`);
  }
  if (j.toolchain) {
    const t = j.toolchain;
    const drift = t.repos.flatMap((rd) =>
      rd.drift.map((d) => [`<code>${e(rd.path)}</code>`, e(d.text)]),
    );
    cards.push(
      `<div class="card"><b>${t.repos.filter((x) => x.drift.length > 0).length}</b>repos with toolchain drift</div>`,
    );
    parts.push(`<h2>Toolchain</h2>
<p>${e(t.line)}${t.managers.length ? ` <span class="muted">· version managers: ${e(t.managers.join(", "))}</span>` : ""}</p>
${table(
  ["Tool", "Version", "Status"],
  t.tools
    .filter((x) => x.status !== "absent")
    .map((x) => [e(x.tool), e(x.version ?? "—"), e(x.status)]),
)}
${table(["Repo", "Drift"], drift)}`);
  }
  if (j.backup) {
    const b = j.backup;
    cards.push(
      `<div class="card"><b>${b.summary.byState["local-only"] ?? 0}</b>local-only projects</div>`,
    );
    parts.push(`<h2>Backup coverage</h2>
<p>${e(b.line)}</p>
${table(
  ["State", "Source", "Last touched", "Project"],
  b.projects.map((p) => [
    e(p.state),
    p.bytes === null ? "—" : e(formatBytes(p.bytes)),
    when(p.lastTouched),
    `<code>${e(p.path)}</code>`,
  ]),
)}`);
  }

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Machine insights</title>
<style>
${REPORT_CSS}
h2{font-size:16px;margin:28px 0 8px}
</style>
</head>
<body>
<main>
<h1>Machine insights</h1>
<p class="muted">${e(j.scope)} · ${e(j.collectedAt)} · repo-wrapped-sweep ${e(j.version)} · collected locally, nothing uploaded</p>
<div class="cards">
${cards.join("\n")}
</div>
${parts.join("\n")}
</main>
</body>
</html>
`;
}
