// Reports (§ A2.4): terminal table, stable --json (schemaVersion 1) and a
// self-contained --html. Every renderer works from `EndpointGroup`s, which carry
// a fingerprint and a MASKED preview and nothing else — there is no raw secret
// anywhere in this module's reach.

import { SEVERITY_ORDER } from "@/lib/charts/palette";
import type { EndpointGroup, EndpointLocation } from "@/lib/native-scan/fingerprint";
import { LOCATION_CLASSES, rotationUrl, type LocationClass } from "@/lib/native-scan/path-rules";
import type { Severity } from "@/lib/org-security";
import type { BaselineDiff } from "./baseline";
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
:root{color-scheme:dark light;--bg:40 6% 10%;--fg:40 14% 90%;--card:40 5% 13%;--border:40 4% 22%;--muted:42 7% 62%;
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
.live{font-size:11px;font-weight:700;color:hsl(var(--sev-critical))}.new{font-size:11px;font-weight:600;color:hsl(142 60% 50%)}summary{cursor:pointer}ul{margin:6px 0;padding-left:18px}a{color:inherit}
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
