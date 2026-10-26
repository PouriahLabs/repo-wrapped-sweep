// `repo-wrapped-sweep ai` reports (ENDPOINT-MACHINE-INSIGHTS § C2.4): fold the stored usage
// events with the shared `foldUsage`, group them by repo / day / model, and print a table or
// --json. Every output names its cost "API-equivalent" and carries PRICES_AS_OF — the number
// is what the same tokens would cost on the pay-as-you-go API, never an invoice.
//
// Built only from UsageEvents (tokens, model, time, session, directory) — there is no message
// text anywhere in this module's reach.

import {
  foldUsage,
  usageDay,
  type AiTool,
  type UsageEvent,
  type UsageRow,
} from "@/lib/endpoint/insights/ai-usage";
import { PRICES_AS_OF } from "@/lib/endpoint/insights/model-prices";
import type { AiScanStats } from "./ai-usage";

export const AI_GROUP_BYS = ["repo", "day", "model"] as const;
export type AiGroupBy = (typeof AI_GROUP_BYS)[number];

export const COST_LABEL = "API-equivalent cost";
export const COST_FOOTNOTE =
  "API-equivalent cost = what these tokens would cost on the pay-as-you-go API. A Pro/Max/Team subscription is not billed this; it is not an invoice.";
export const OVERSIZE_NOTE =
  "Transcript lines over 64 KB are skipped unparsed (about 0.3% of tokens on a typical machine).";

const DAY_MS = 86_400_000;

/** `30d` → now − 30 days; `2026-01-01` → that UTC midnight. Null when unparseable. */
export function parseSince(value: string | undefined, now: number): number | null {
  const v = (value ?? "30d").trim();
  const days = /^(\d{1,4})d$/i.exec(v);
  if (days) return now - Number(days[1]) * DAY_MS;
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) {
    const t = Date.parse(`${v}T00:00:00Z`);
    return Number.isFinite(t) && t <= now ? t : null;
  }
  return null;
}

export interface AiGroupRow {
  /** Repo (home-relative), day, or model — null is `(no repo)`; the totals row has key null too. */
  key: string | null;
  /** For `--by model`: which tool ran it. */
  tool?: AiTool;
  sessions: number;
  turns: number;
  activeMinutes: number;
  inputTokens: number;
  outputTokens: number;
  cacheWriteTokens: number;
  cacheReadTokens: number;
  tokens: number;
  /** API-equivalent USD of the priced part; null when nothing in the group is priced. */
  costUsd: number | null;
  /** Tokens of unpriced models (counted, not costed). */
  unpricedTokens: number;
}

export interface AiReport {
  since: number;
  until: number;
  by: AiGroupBy;
  rows: UsageRow[];
  groups: AiGroupRow[];
  totals: AiGroupRow;
  unpriced: string[];
  pricesAsOf: string;
}

const emptyGroup = (key: string | null, tool?: AiTool): AiGroupRow => ({
  key,
  ...(tool ? { tool } : {}),
  sessions: 0,
  turns: 0,
  activeMinutes: 0,
  inputTokens: 0,
  outputTokens: 0,
  cacheWriteTokens: 0,
  cacheReadTokens: 0,
  tokens: 0,
  costUsd: null,
  unpricedTokens: 0,
});

function addRow(g: AiGroupRow, r: UsageRow): void {
  const tokens = r.inputTokens + r.outputTokens + r.cacheWriteTokens + r.cacheReadTokens;
  g.turns += r.turns;
  g.activeMinutes += r.activeMinutes;
  g.inputTokens += r.inputTokens;
  g.outputTokens += r.outputTokens;
  g.cacheWriteTokens += r.cacheWriteTokens;
  g.cacheReadTokens += r.cacheReadTokens;
  g.tokens += tokens;
  if (r.costUsd === null) g.unpricedTokens += tokens;
  else g.costUsd = Math.round(((g.costUsd ?? 0) + r.costUsd) * 10_000) / 10_000;
}

/**
 * Fold the events in [since, until) and group them. Sessions are counted DISTINCT per group
 * (a session spanning two days or models is one session in a repo group), so they come from
 * the events; everything else is additive over the fold's rows.
 */
export function buildAiReport(
  events: readonly UsageEvent[],
  opts: {
    since: number;
    until: number;
    by: AiGroupBy;
    repoOf: (cwd: string | null) => string | null;
  },
): AiReport {
  const inRange = events.filter((e) => e.at >= opts.since && e.at < opts.until);
  const fold = foldUsage(inRange, { repoOf: opts.repoOf });

  const keyOfRow = (r: UsageRow): string =>
    JSON.stringify(opts.by === "repo" ? [r.repo] : opts.by === "day" ? [r.day] : [r.tool, r.model]);
  const keyOfEvent = (e: UsageEvent): string =>
    JSON.stringify(
      opts.by === "repo"
        ? [opts.repoOf(e.cwd)]
        : opts.by === "day"
          ? [usageDay(e.at)]
          : [e.tool, e.model],
    );

  const groups = new Map<string, AiGroupRow>();
  const totals = emptyGroup(null);
  for (const r of fold.rows) {
    const k = keyOfRow(r);
    let g = groups.get(k);
    if (!g) {
      g =
        opts.by === "repo"
          ? emptyGroup(r.repo)
          : opts.by === "day"
            ? emptyGroup(r.day)
            : emptyGroup(r.model, r.tool);
      groups.set(k, g);
    }
    addRow(g, r);
    addRow(totals, r);
  }
  const sessions = new Map<string, Set<string>>();
  for (const e of inRange) {
    const k = keyOfEvent(e);
    let s = sessions.get(k);
    if (!s) sessions.set(k, (s = new Set()));
    s.add(`${e.tool}:${e.sessionId}`);
  }
  for (const [k, g] of groups) g.sessions = sessions.get(k)?.size ?? 0;
  totals.sessions = new Set(inRange.map((e) => `${e.tool}:${e.sessionId}`)).size;

  const out = [...groups.values()];
  if (opts.by === "day") out.sort((a, b) => (a.key ?? "").localeCompare(b.key ?? ""));
  else {
    out.sort(
      (a, b) =>
        (b.costUsd ?? 0) - (a.costUsd ?? 0) ||
        b.tokens - a.tokens ||
        Number(a.key === null) - Number(b.key === null) ||
        (a.key ?? "").localeCompare(b.key ?? ""),
    );
  }
  return {
    since: opts.since,
    until: opts.until,
    by: opts.by,
    rows: fold.rows,
    groups: out,
    totals,
    unpriced: fold.unpriced,
    pricesAsOf: PRICES_AS_OF,
  };
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/** 950 → `950`, 12_300 → `12.3k`, 4_560_000 → `4.56M`, 1.2e9 → `1.20B`. */
export function formatTokens(n: number): string {
  if (n < 1_000) return String(n);
  if (n < 1_000_000) return `${(n / 1_000).toFixed(n < 10_000 ? 2 : 1)}k`;
  if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(n < 10_000_000 ? 2 : 1)}M`;
  return `${(n / 1_000_000_000).toFixed(2)}B`;
}

export function formatUsd(n: number | null): string {
  if (n === null) return "unpriced";
  return `$${n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

/** 0 → `0m`, 75 → `1h 15m`. */
export function formatMinutes(m: number): string {
  if (m < 60) return `${m}m`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

const isoDay = (ms: number) => new Date(ms).toISOString().slice(0, 10);

export interface AiReportContext {
  version: string;
  os: string;
  collectedAt: string;
  scan: AiScanStats;
}

/** Lines for the footer: always the cost basis and price date; the scan caveats when they apply. */
export function aiNotes(r: AiReport, scan: AiScanStats): string[] {
  const notes = [`${COST_FOOTNOTE} Prices as of ${r.pricesAsOf}.`];
  if (r.unpriced.length > 0) {
    notes.push(`Unpriced models (tokens counted, no cost): ${r.unpriced.join(", ")}.`);
  }
  if (scan.oversizeLines > 0) {
    notes.push(
      `${scan.oversizeLines.toLocaleString("en-US")} ${OVERSIZE_NOTE.charAt(0).toLowerCase()}${OVERSIZE_NOTE.slice(1)}`,
    );
  }
  if (scan.zstdSkipped > 0) {
    notes.push(
      `${scan.zstdSkipped} compressed Codex session${scan.zstdSkipped === 1 ? "" : "s"} (.jsonl.zst) skipped: this Node (${process.version}) has no zstd decoder — Node 22.15+ reads them.`,
    );
  }
  if (scan.unreadable > 0) {
    notes.push(
      `${scan.unreadable} transcript${scan.unreadable === 1 ? "" : "s"} could not be read (retried next run).`,
    );
  }
  return notes;
}

export interface AiJson {
  schemaVersion: 1;
  tool: "repo-wrapped-sweep";
  kind: "ai-usage";
  version: string;
  os: string;
  collectedAt: string;
  since: string;
  until: string;
  by: AiGroupBy;
  costBasis: typeof COST_LABEL;
  pricesAsOf: string;
  totals: AiGroupRow;
  groups: AiGroupRow[];
  /** One row per (UTC day, repo, tool, model) — the shape an upload carries. */
  rows: UsageRow[];
  unpriced: string[];
  scan: AiScanStats;
  notes: string[];
}

export function buildAiJson(r: AiReport, ctx: AiReportContext): AiJson {
  return {
    schemaVersion: 1,
    tool: "repo-wrapped-sweep",
    kind: "ai-usage",
    version: ctx.version,
    os: ctx.os,
    collectedAt: ctx.collectedAt,
    since: new Date(r.since).toISOString(),
    until: new Date(r.until).toISOString(),
    by: r.by,
    costBasis: COST_LABEL,
    pricesAsOf: r.pricesAsOf,
    totals: r.totals,
    groups: r.groups,
    rows: r.rows,
    unpriced: r.unpriced,
    scan: ctx.scan,
    notes: aiNotes(r, ctx.scan),
  };
}

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

export function renderAiText(
  r: AiReport,
  ctx: Pick<AiReportContext, "scan">,
  opts: { color: boolean; periodLabel: string },
): string {
  const c = (code: string, s: string) => (opts.color ? code + s + RESET : s);
  const label = r.by === "repo" ? "REPO" : r.by === "day" ? "DAY" : "MODEL";
  const head = [
    label,
    "SESSIONS",
    "ACTIVE",
    "INPUT",
    "OUTPUT",
    "CACHE WRITE",
    "CACHE READ",
    COST_LABEL.toUpperCase(),
  ];
  const cells = (g: AiGroupRow, name: string) => [
    name,
    String(g.sessions),
    formatMinutes(g.activeMinutes),
    formatTokens(g.inputTokens),
    formatTokens(g.outputTokens),
    formatTokens(g.cacheWriteTokens),
    formatTokens(g.cacheReadTokens),
    formatUsd(g.costUsd) + (g.costUsd !== null && g.unpricedTokens > 0 ? "*" : ""),
  ];
  const nameOf = (g: AiGroupRow) =>
    r.by === "repo"
      ? (g.key ?? "(no repo)")
      : r.by === "model"
        ? `${g.key} (${g.tool})`
        : (g.key ?? "");
  const body = r.groups.map((g) => cells(g, nameOf(g)));
  const total = cells(r.totals, "TOTAL");
  const all = [head, ...body, total];
  const widths = head.map((_, i) => Math.max(...all.map((row) => row[i]!.length)));
  const line = (row: string[]) =>
    row
      .map((cell, i) => (i === 0 ? cell.padEnd(widths[i]!) : cell.padStart(widths[i]!)))
      .join("  ");

  const out: string[] = [
    c(BOLD, `AI usage — ${opts.periodLabel}`) +
      c(DIM, ` (${isoDay(r.since)} → ${isoDay(r.until)}, UTC days)`),
  ];
  if (r.groups.length === 0) {
    out.push("No Claude Code or Codex usage in this period.");
  } else {
    out.push(c(BOLD, line(head)), ...body.map(line), c(BOLD, line(total)));
    out.push(
      `${r.totals.sessions} session${r.totals.sessions === 1 ? "" : "s"} · ${formatMinutes(r.totals.activeMinutes)} active · ${formatTokens(r.totals.tokens)} tokens · ${formatUsd(r.totals.costUsd)} ${COST_LABEL}` +
        (r.totals.unpricedTokens > 0
          ? ` (* excludes ${formatTokens(r.totals.unpricedTokens)} unpriced tokens)`
          : ""),
    );
  }
  out.push("", ...aiNotes(r, ctx.scan).map((n) => c(DIM, n)));
  return out.join("\n");
}
