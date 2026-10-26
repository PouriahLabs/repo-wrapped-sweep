// Machine Wrapped (ENDPOINT-MACHINE-INSIGHTS § C2.6, C-7) — PURE: no fs, no clock, no git.
// The CLI collects the year's commits (by the local `user.email`), the language mix of the
// files those commits touched and the AI-usage events, and this module folds them into the
// numbers on the card. The same fold will render the shared card server-side (Phase C6), so
// it takes plain data and returns plain data.
//
// Definitions (each one is what the card claims, so keep them honest):
//   - repos touched   distinct repos with at least one of your commits in the period.
//   - commits         distinct commit hashes (two clones of one repo count a commit once).
//   - languages       share of files changed by those commits, by language (top 6).
//   - AI sessions / hours / top model / cost   the AI-usage fold (`foldUsage`) over the
//                     period; hours are its active minutes; cost is API-EQUIVALENT.
//   - AI share        AI-active minutes ÷ (AI-active + commit-active minutes). Commit-active
//                     time credits each commit the 15 minutes before it, merged where commits
//                     are closer than that — the same 15-minute stretch rule as AI activity.
//   - busiest weekday / hour   counted in ACTIVE HOURS: each local (day, hour) with any
//                     commit or AI response counts once, so a burst of 300 AI responses in
//                     one hour weighs the same as a single commit in another.
//   - longest streak  consecutive local days with any commit or AI response.

import { LANG_COLORS } from "@/config/lang-colors";
import { languageShares, type LanguageShare } from "@/lib/charts/languages";
import { langFromPath } from "@/lib/code-quality/file-view";
import { ACTIVE_GAP_MINUTES, foldUsage, type UsageEvent } from "@/lib/endpoint/insights/ai-usage";
import { PRICES_AS_OF } from "@/lib/endpoint/insights/model-prices";

const MINUTE_MS = 60_000;
const DAY_MS = 86_400_000;

/** Shiki grammar id (file-view.ts) → the language name GitHub shows (and LANG_COLORS keys). */
const GRAMMAR_LANGUAGE: Readonly<Record<string, string>> = {
  typescript: "TypeScript",
  tsx: "TypeScript",
  javascript: "JavaScript",
  jsx: "JavaScript",
  python: "Python",
  ruby: "Ruby",
  go: "Go",
  rust: "Rust",
  java: "Java",
  c: "C",
  cpp: "C++",
  php: "PHP",
  css: "CSS",
  scss: "SCSS",
  html: "HTML",
  shellscript: "Shell",
  sql: "SQL",
  kotlin: "Kotlin",
  swift: "Swift",
  csharp: "C#",
};

/** Extensions file-view.ts doesn't ship a grammar for but that are clearly a language. */
const EXTRA_EXTENSIONS: Readonly<Record<string, string>> = {
  vue: "Vue",
  svelte: "Svelte",
  dart: "Dart",
  lua: "Lua",
  scala: "Scala",
  ex: "Elixir",
  exs: "Elixir",
};

/**
 * The language of a changed file, or null for data/docs/config (JSON, YAML, Markdown, TOML,
 * XML) and anything unrecognised — those aren't a "language you wrote".
 */
export function languageOfPath(p: string): string | null {
  const grammar = langFromPath(p.replace(/\\/g, "/"));
  if (grammar) return GRAMMAR_LANGUAGE[grammar] ?? null;
  const base = p.slice(Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\")) + 1);
  const dot = base.lastIndexOf(".");
  return dot <= 0 ? null : (EXTRA_EXTENSIONS[base.slice(dot + 1).toLowerCase()] ?? null);
}

/** Local calendar parts of an instant. The CLI passes the machine's zone; tests pass UTC. */
export interface LocalParts {
  /** `YYYY-MM-DD` in local time. */
  day: string;
  /** 0 = Sunday … 6 = Saturday. */
  weekday: number;
  /** 0–23. */
  hour: number;
}

export const utcParts = (at: number): LocalParts => {
  const d = new Date(at);
  return { day: d.toISOString().slice(0, 10), weekday: d.getUTCDay(), hour: d.getUTCHours() };
};

export interface WrappedCommit {
  /** Epoch ms (commit time). */
  at: number;
  /** Commit hash — the de-duplication key across clones. */
  hash: string;
  /** Repo key (a path or id; never shown on the card). */
  repo: string;
}

export interface MachineWrappedInput {
  year: number;
  /** Period bounds, epoch ms, [start, end). The CLI passes the local calendar year. */
  start: number;
  end: number;
  commits: readonly WrappedCommit[];
  /** Files changed by those commits, per language (see `languageOfPath`). */
  languageFiles: Readonly<Record<string, number>>;
  aiEvents: readonly UsageEvent[];
  /** Bytes freed by `disk clean` in the period; null when there is no clean log. */
  diskReclaimedBytes: number | null;
  local?: (at: number) => LocalParts;
}

export interface MachineWrapped {
  year: number;
  reposTouched: number;
  commits: number;
  /** Top languages by files changed; percentages of the full total. */
  languages: Array<LanguageShare & { color: string | null }>;
  ai: {
    sessions: number;
    turns: number;
    activeMinutes: number;
    tokens: number;
    /** API-equivalent USD for the priced models; null when nothing was priced. */
    costUsd: number | null;
    topModel: string | null;
    unpriced: string[];
    pricesAsOf: string;
  };
  commitActiveMinutes: number;
  /** 0–1, or null when there was no activity of either kind. */
  aiShare: number | null;
  /** Active hours per weekday (index 0 = Sunday). */
  weekdayActivity: number[];
  /** Active days per hour of day (index 0 = midnight). */
  hourActivity: number[];
  busiestWeekday: number | null;
  busiestHour: number | null;
  activeDays: number;
  longestStreakDays: number;
  diskReclaimedBytes: number | null;
}

/**
 * Minutes of commit activity: each commit is credited the window of `gapMinutes` before it,
 * and overlapping windows merge — so commits 5 minutes apart add 5 minutes, a lone commit adds 15.
 */
export function commitActiveMinutes(
  times: readonly number[],
  gapMinutes = ACTIVE_GAP_MINUTES,
): number {
  const gap = gapMinutes * MINUTE_MS;
  const sorted = [...times].sort((a, b) => a - b);
  let ms = 0;
  for (let i = 0; i < sorted.length; i++) {
    ms += i === 0 ? gap : Math.min(gap, sorted[i]! - sorted[i - 1]!);
  }
  return Math.round(ms / MINUTE_MS);
}

/** Longest run of consecutive `YYYY-MM-DD` days. */
export function longestStreak(days: Iterable<string>): number {
  const sorted = [...new Set(days)].sort();
  let best = 0;
  let run = 0;
  let prev: number | null = null;
  for (const d of sorted) {
    const t = Date.parse(`${d}T00:00:00Z`);
    run = prev !== null && t - prev === DAY_MS ? run + 1 : 1;
    if (run > best) best = run;
    prev = t;
  }
  return best;
}

const argMax = (xs: readonly number[]): number | null => {
  let best: number | null = null;
  for (let i = 0; i < xs.length; i++) {
    if (xs[i]! > 0 && (best === null || xs[i]! > xs[best]!)) best = i;
  }
  return best;
};

export function buildMachineWrapped(input: MachineWrappedInput): MachineWrapped {
  const local = input.local ?? utcParts;
  const inPeriod = (at: number) => at >= input.start && at < input.end;

  const byHash = new Map<string, WrappedCommit>();
  for (const c of input.commits) if (inPeriod(c.at) && !byHash.has(c.hash)) byHash.set(c.hash, c);
  const commits = [...byHash.values()];

  const aiEvents = input.aiEvents.filter((e) => inPeriod(e.at));
  const fold = foldUsage(aiEvents);
  let tokens = 0;
  let cost = 0;
  let priced = false;
  let activeMinutes = 0;
  let turns = 0;
  const turnsByModel = new Map<string, number>();
  for (const r of fold.rows) {
    tokens += r.inputTokens + r.outputTokens + r.cacheWriteTokens + r.cacheReadTokens;
    if (r.costUsd !== null) {
      cost += r.costUsd;
      priced = true;
    }
    activeMinutes += r.activeMinutes;
    turns += r.turns;
    turnsByModel.set(r.model, (turnsByModel.get(r.model) ?? 0) + r.turns);
  }
  const sessions = new Set(aiEvents.map((e) => `${e.tool}:${e.sessionId}`)).size;
  let topModel: string | null = null;
  for (const [model, n] of turnsByModel) {
    if (
      topModel === null ||
      n > turnsByModel.get(topModel)! ||
      (n === turnsByModel.get(topModel) && model < topModel)
    ) {
      topModel = model;
    }
  }

  // Activity grid: distinct local (day, hour) slots with any commit or AI response.
  const slots = new Map<string, LocalParts>();
  for (const at of [...commits.map((c) => c.at), ...aiEvents.map((e) => e.at)]) {
    const p = local(at);
    slots.set(`${p.day}|${p.hour}`, p);
  }
  const weekdayActivity = Array<number>(7).fill(0);
  const hourActivity = Array<number>(24).fill(0);
  const days = new Set<string>();
  for (const p of slots.values()) {
    weekdayActivity[p.weekday]!++;
    hourActivity[p.hour]!++;
    days.add(p.day);
  }

  const commitMinutes = commitActiveMinutes(commits.map((c) => c.at));
  const denominator = activeMinutes + commitMinutes;

  const languages = languageShares({ ...input.languageFiles }).map((l) => ({
    ...l,
    color: LANG_COLORS[l.name] ?? null,
  }));

  return {
    year: input.year,
    reposTouched: new Set(commits.map((c) => c.repo)).size,
    commits: commits.length,
    languages,
    ai: {
      sessions,
      turns,
      activeMinutes,
      tokens,
      costUsd: priced ? Math.round(cost * 100) / 100 : null,
      topModel,
      unpriced: fold.unpriced,
      pricesAsOf: PRICES_AS_OF,
    },
    commitActiveMinutes: commitMinutes,
    aiShare: denominator > 0 ? activeMinutes / denominator : null,
    weekdayActivity,
    hourActivity,
    busiestWeekday: argMax(weekdayActivity),
    busiestHour: argMax(hourActivity),
    activeDays: days.size,
    longestStreakDays: longestStreak(days),
    diskReclaimedBytes: input.diskReclaimedBytes,
  };
}
