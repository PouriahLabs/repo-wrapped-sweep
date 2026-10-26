// AI-usage parsing and fold for Machine Insights (ENDPOINT-MACHINE-INSIGHTS § C2.4) — PURE:
// no fs, no clock. The CLI streams transcript lines in; this module turns each into a
// UsageEvent (or null) and folds events into per-(day, repo, tool, model) rows.
//
// PRIVACY — the parser reads an explicit allow-list of fields and drops the line:
//   Claude Code  type, timestamp, sessionId, cwd, requestId, message.{id, model, usage.*}
//   Codex        type, timestamp, payload.{type, id, cwd, model, info.*_token_usage.*}
// A UsageEvent is built field by field from those, never by spreading the parsed object, so
// no message text, tool input or file content can reach it (a test plants a sentinel in every
// text-bearing slot and greps the output). `cwd` is a path and is the one identifying field —
// callers attribute it to a repo and send a salted id, not the path.
//
// Costs are API-EQUIVALENT (model-prices.ts), never an invoice.

import {
  PRICES_AS_OF,
  apiEquivalentCostUsd,
  type TokenCounts,
} from "@/lib/endpoint/insights/model-prices";

export type AiTool = "claude-code" | "codex";

/** Same cap as the secret scanner's line reader (`LINE_CAP_CHARS` in cli/sweep/src/scan.ts). */
export const USAGE_LINE_CAP_CHARS = 64 * 1024;

/** A gap longer than this ends an active stretch. */
export const ACTIVE_GAP_MINUTES = 15;

const MINUTE_MS = 60_000;

export interface UsageEvent {
  tool: AiTool;
  model: string;
  /** Epoch ms. */
  at: number;
  sessionId: string;
  /** Working directory of the session; null when the line didn't carry one. */
  cwd: string | null;
  inputTokens: number;
  outputTokens: number;
  cacheWriteTokens: number;
  cacheReadTokens: number;
  /**
   * Identity of the API response, for de-duplication. Claude Code writes one transcript line
   * per content block of a response, each repeating the same usage block, and a resumed
   * session copies earlier lines into its new file. Null when the line has no id.
   */
  dedupeKey: string | null;
}

/**
 * State carried between lines of ONE Codex rollout file: its `session_meta` and `turn_context`
 * lines name the session, directory and model, which its `token_count` lines omit. Plain
 * JSON, so a collector can persist it next to a file cursor and resume mid-file. Claude Code
 * lines are self-contained; the context only supplies a fallback session id.
 */
export interface UsageParseContext {
  sessionId: string | null;
  cwd: string | null;
  model: string | null;
  /** `total_token_usage.total_tokens` of the last token_count seen (repeat events are dropped). */
  lastTotal: number | null;
}

export function newUsageContext(seed: Partial<UsageParseContext> = {}): UsageParseContext {
  return { sessionId: null, cwd: null, model: null, lastTotal: null, ...seed };
}

const str = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);

/** A token count: a finite, non-negative number, floored; anything else is 0. */
const count = (v: unknown): number =>
  typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.floor(v) : 0;

const obj = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

const timeOf = (v: unknown): number | null => {
  const s = str(v);
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
};

const SYNTHETIC_MODEL = "<synthetic>";

function parseClaudeCode(o: Record<string, unknown>, ctx: UsageParseContext): UsageEvent | null {
  if (o.type !== "assistant") return null;
  const message = obj(o.message);
  const usage = obj(message?.usage);
  const model = str(message?.model);
  const at = timeOf(o.timestamp);
  if (!message || !usage || !model || model === SYNTHETIC_MODEL || at === null) return null;

  const inputTokens = count(usage.input_tokens);
  const outputTokens = count(usage.output_tokens);
  const cacheWriteTokens = count(usage.cache_creation_input_tokens);
  const cacheReadTokens = count(usage.cache_read_input_tokens);
  if (inputTokens + outputTokens + cacheWriteTokens + cacheReadTokens === 0) return null;

  const id = str(message.id);
  return {
    tool: "claude-code",
    model,
    at,
    sessionId: str(o.sessionId) ?? str(o.session_id) ?? ctx.sessionId ?? "unknown",
    cwd: str(o.cwd),
    inputTokens,
    outputTokens,
    cacheWriteTokens,
    cacheReadTokens,
    dedupeKey: id ? `${id}:${str(o.requestId) ?? ""}` : null,
  };
}

function parseCodex(o: Record<string, unknown>, ctx: UsageParseContext): UsageEvent | null {
  const payload = obj(o.payload);
  if (!payload) return null;

  if (o.type === "session_meta") {
    ctx.sessionId = str(payload.id) ?? str(payload.session_id) ?? ctx.sessionId;
    ctx.cwd = str(payload.cwd) ?? ctx.cwd;
    return null;
  }
  if (o.type === "turn_context") {
    const settings = obj(obj(payload.collaboration_mode)?.settings);
    ctx.model = str(payload.model) ?? str(settings?.model) ?? ctx.model;
    ctx.cwd = str(payload.cwd) ?? ctx.cwd;
    return null;
  }
  if (o.type !== "event_msg" || payload.type !== "token_count") return null;

  const info = obj(payload.info);
  const last = obj(info?.last_token_usage);
  if (!info || !last) return null;

  // The same cumulative total can be reported again (a rate-limit refresh); count a response once.
  const total = count(obj(info.total_token_usage)?.total_tokens);
  if (total > 0 && total === ctx.lastTotal) return null;
  if (total > 0) ctx.lastTotal = total;

  const at = timeOf(o.timestamp);
  if (at === null) return null;

  // Codex reports `input_tokens` INCLUDING the cached part (and any cache write); split it so
  // each bucket is priced once. `output_tokens` already includes reasoning tokens.
  const cacheReadTokens = count(last.cached_input_tokens);
  const cacheWriteTokens = count(last.cache_write_input_tokens);
  const inputTokens = Math.max(0, count(last.input_tokens) - cacheReadTokens - cacheWriteTokens);
  const outputTokens = count(last.output_tokens);
  if (inputTokens + outputTokens + cacheWriteTokens + cacheReadTokens === 0) return null;

  return {
    tool: "codex",
    model: ctx.model ?? "unknown",
    at,
    sessionId: ctx.sessionId ?? "unknown",
    cwd: ctx.cwd,
    inputTokens,
    outputTokens,
    cacheWriteTokens,
    cacheReadTokens,
    dedupeKey: null,
  };
}

/**
 * One transcript line → a UsageEvent, or null (not a usage line, malformed, over the line cap,
 * a synthetic or zero-token turn). Never throws. Codex session/turn lines update `ctx` and
 * return null, so feed a Codex file's lines through one context, in order.
 */
export function parseUsageLine(line: string, ctx: UsageParseContext): UsageEvent | null {
  if (line.length === 0 || line.length > USAGE_LINE_CAP_CHARS) return null;
  // Cheap reject before JSON.parse: most transcript lines are not usage lines.
  if (
    !line.includes('"usage"') &&
    !line.includes('"token_count"') &&
    !line.includes('"session_meta"') &&
    !line.includes('"turn_context"')
  ) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return null;
  }
  const o = obj(parsed);
  if (!o) return null;
  return "payload" in o ? parseCodex(o, ctx) : parseClaudeCode(o, ctx);
}

// --- fold ---------------------------------------------------------------------------------

/** UTC day key (YYYY-MM-DD), the same bucket the spend ledger uses. */
export const usageDay = (at: number): string => new Date(at).toISOString().slice(0, 10);

/**
 * Collapse repeated API responses (same `dedupeKey`) to one event. A streamed response is
 * logged several times with a growing `output_tokens`, so each token field takes its MAXIMUM
 * across the repeats; the first occurrence supplies the time, session and directory.
 */
export function dedupeUsageEvents(events: readonly UsageEvent[]): UsageEvent[] {
  const out: UsageEvent[] = [];
  const byKey = new Map<string, UsageEvent>();
  for (const e of events) {
    if (e.dedupeKey === null) {
      out.push(e);
      continue;
    }
    const seen = byKey.get(e.dedupeKey);
    if (!seen) {
      const copy = { ...e };
      byKey.set(e.dedupeKey, copy);
      out.push(copy);
      continue;
    }
    seen.inputTokens = Math.max(seen.inputTokens, e.inputTokens);
    seen.outputTokens = Math.max(seen.outputTokens, e.outputTokens);
    seen.cacheWriteTokens = Math.max(seen.cacheWriteTokens, e.cacheWriteTokens);
    seen.cacheReadTokens = Math.max(seen.cacheReadTokens, e.cacheReadTokens);
  }
  return out;
}

const normPath = (p: string): string => p.replace(/\\/g, "/").replace(/\/+$/, "");

/**
 * The deepest of `roots` that contains `cwd` (or equals it), or null. Compares on a path
 * boundary (`/work/app` does not contain `/work/application`), treats `\` and `/` alike, and
 * ignores case for Windows-style paths (a drive letter or UNC prefix). Returns the root as
 * given, so callers can key a map by it.
 */
export function nearestRoot(cwd: string, roots: readonly string[]): string | null {
  const c = normPath(cwd);
  const windows = /^[a-z]:\//i.test(c) || c.startsWith("//");
  const fold = (s: string) => (windows ? s.toLowerCase() : s);
  const target = fold(c);
  let best: string | null = null;
  let bestLen = -1;
  for (const root of roots) {
    const r = fold(normPath(root));
    if (r === "") continue;
    if ((target === r || target.startsWith(`${r}/`)) && r.length > bestLen) {
      best = root;
      bestLen = r.length;
    }
  }
  return best;
}

export interface UsageRow {
  /** UTC day. */
  day: string;
  /** Whatever `repoOf` returned (a repo key); null = `(no repo)`. */
  repo: string | null;
  tool: AiTool;
  model: string;
  sessions: number;
  /** API responses (deduplicated). */
  turns: number;
  /** Minutes inside stretches of activity — gaps over 15 minutes end a stretch. */
  activeMinutes: number;
  inputTokens: number;
  outputTokens: number;
  cacheWriteTokens: number;
  cacheReadTokens: number;
  /** API-equivalent USD; null when the model is unpriced. */
  costUsd: number | null;
}

export interface UsageFold {
  rows: UsageRow[];
  /** Models seen with tokens but no price — listed so a report can say "unpriced". */
  unpriced: string[];
  pricesAsOf: string;
}

export interface FoldOptions {
  /** Attribute a session directory to a repo key; return null for `(no repo)`. Default: everything is `(no repo)`. */
  repoOf?: (cwd: string | null) => string | null;
  gapMinutes?: number;
}

interface Acc {
  day: string;
  repo: string | null;
  tool: AiTool;
  model: string;
  sessions: Set<string>;
  turns: number;
  activeMs: number;
  tokens: TokenCounts;
}

/**
 * Fold events into one row per (day, repo, tool, model).
 *
 * Active time: within a session, events are ordered by time; each event adds the gap since
 * the session's previous event when that gap is at most 15 minutes, and nothing when it is
 * longer (a new stretch starts). The gap is credited to the row of the event that CLOSES it,
 * so a stretch's minutes sum to its duration even when it crosses midnight or switches model.
 * A single-event stretch is zero minutes — we don't know how long the prompt took.
 *
 * Rows are sorted by day, then repo (`(no repo)` last), tool, model — deterministic.
 */
export function foldUsage(events: readonly UsageEvent[], opts: FoldOptions = {}): UsageFold {
  const repoOf = opts.repoOf ?? (() => null);
  const gapMs = (opts.gapMinutes ?? ACTIVE_GAP_MINUTES) * MINUTE_MS;

  const deduped = dedupeUsageEvents(events);
  const ordered = [...deduped].sort((a, b) => a.at - b.at);

  const rows = new Map<string, Acc>();
  const lastInSession = new Map<string, number>();

  for (const e of ordered) {
    const day = usageDay(e.at);
    const repo = repoOf(e.cwd);
    const key = JSON.stringify([day, repo, e.tool, e.model]);
    let acc = rows.get(key);
    if (!acc) {
      acc = {
        day,
        repo,
        tool: e.tool,
        model: e.model,
        sessions: new Set(),
        turns: 0,
        activeMs: 0,
        tokens: { inputTokens: 0, outputTokens: 0, cacheWriteTokens: 0, cacheReadTokens: 0 },
      };
      rows.set(key, acc);
    }
    acc.sessions.add(`${e.tool}:${e.sessionId}`);
    acc.turns++;
    acc.tokens.inputTokens += e.inputTokens;
    acc.tokens.outputTokens += e.outputTokens;
    acc.tokens.cacheWriteTokens += e.cacheWriteTokens;
    acc.tokens.cacheReadTokens += e.cacheReadTokens;

    const sessionKey = `${e.tool}:${e.sessionId}`;
    const prev = lastInSession.get(sessionKey);
    if (prev !== undefined && e.at - prev <= gapMs) acc.activeMs += e.at - prev;
    lastInSession.set(sessionKey, e.at);
  }

  const unpriced = new Set<string>();
  const out: UsageRow[] = [];
  for (const a of rows.values()) {
    const cost = apiEquivalentCostUsd(a.model, a.tokens);
    if (cost === null) unpriced.add(a.model);
    out.push({
      day: a.day,
      repo: a.repo,
      tool: a.tool,
      model: a.model,
      sessions: a.sessions.size,
      turns: a.turns,
      activeMinutes: Math.round(a.activeMs / MINUTE_MS),
      ...a.tokens,
      costUsd: cost === null ? null : Math.round(cost * 10_000) / 10_000,
    });
  }
  out.sort(
    (a, b) =>
      a.day.localeCompare(b.day) ||
      Number(a.repo === null) - Number(b.repo === null) ||
      (a.repo ?? "").localeCompare(b.repo ?? "") ||
      a.tool.localeCompare(b.tool) ||
      a.model.localeCompare(b.model),
  );
  return { rows: out, unpriced: [...unpriced].sort(), pricesAsOf: PRICES_AS_OF };
}
