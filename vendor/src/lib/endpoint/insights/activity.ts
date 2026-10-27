// Local coding rhythm (CLI 0.3 / Machine Insights) — PURE. The CLI reads commit timestamps
// for this machine's git identity from local repos; this folds them into counts. The
// identity, messages and file names never reach this function.

export interface CommitTime {
  /** Opaque repo key (the CLI's absolute path) — mapped to a RepoRef afterwards. */
  repo: string;
  /** Unix seconds. */
  ts: number;
}

/** Local-time parts of a timestamp — injected so tests don't depend on the host zone. */
export interface LocalTime {
  hour: number;
  /** 0 = Sunday. */
  weekday: number;
  /** `YYYY-MM-DD` in local time. */
  day: string;
}

export interface ActivityFold {
  commits7d: number;
  commits365d: number;
  activeDays365d: number;
  longestStreakDays: number;
  byHour: number[];
  byWeekday: number[];
  topRepo: { repo: string; commits: number } | null;
}

const DAY_S = 86_400;

/** Consecutive-day runs over a set of `YYYY-MM-DD` days. */
function longestStreak(days: ReadonlySet<string>): number {
  const sorted = [...days].sort();
  let best = 0;
  let run = 0;
  let prev: number | null = null;
  for (const d of sorted) {
    const t = Date.parse(`${d}T00:00:00Z`) / 1000;
    run = prev !== null && t - prev === DAY_S ? run + 1 : 1;
    best = Math.max(best, run);
    prev = t;
  }
  return best;
}

/** Fold the last year of commit times. Duplicate (repo, ts) pairs count once. PURE. */
export function foldActivity(
  commits: readonly CommitTime[],
  nowS: number,
  local: (ts: number) => LocalTime,
): ActivityFold {
  const seen = new Set<string>();
  const byHour = new Array<number>(24).fill(0);
  const byWeekday = new Array<number>(7).fill(0);
  const days = new Set<string>();
  const perRepo = new Map<string, number>();
  let commits7d = 0;
  let commits365d = 0;
  for (const c of commits) {
    const age = nowS - c.ts;
    if (age < 0 || age > 365 * DAY_S) continue;
    const key = `${c.repo}\0${c.ts}`;
    if (seen.has(key)) continue;
    seen.add(key);
    commits365d++;
    if (age <= 7 * DAY_S) commits7d++;
    const t = local(c.ts);
    byHour[t.hour] = (byHour[t.hour] ?? 0) + 1;
    byWeekday[t.weekday] = (byWeekday[t.weekday] ?? 0) + 1;
    days.add(t.day);
    perRepo.set(c.repo, (perRepo.get(c.repo) ?? 0) + 1);
  }
  let topRepo: ActivityFold["topRepo"] = null;
  for (const [repo, n] of [...perRepo.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (!topRepo || n > topRepo.commits) topRepo = { repo, commits: n };
  }
  return {
    commits7d,
    commits365d,
    activeDays365d: days.size,
    longestStreakDays: longestStreak(days),
    byHour,
    byWeekday,
    topRepo,
  };
}

/** The busiest index of a histogram, or null when it is all zeros. PURE. */
export function peakIndex(counts: readonly number[]): number | null {
  let best: number | null = null;
  counts.forEach((n, i) => {
    if (n > 0 && (best === null || n > counts[best]!)) best = i;
  });
  return best;
}
