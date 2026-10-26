// The shared Machine Wrapped card (ENDPOINT-MACHINE-INSIGHTS § C2.6, Phase C6) — the wire shape
// `wrapped --share` uploads and the public /dev/<login> page renders. PURE: types, caps and an
// allow-list builder; no zod, no I/O, so the CLI bundle can import it (the Zod schema that
// enforces it lives server-side in `src/lib/endpoint/wrapped-share.ts`).
//
// AGGREGATES ONLY. The card is built field by field from `MachineWrapped` — counts, shares,
// token totals, a model id — and never carries a repo name, a path, an email, a commit hash or
// message text. `MachineWrapped` itself holds none (`repos touched` is a count), so there is
// nothing for `sharePaths` to unlock: the shared card has no names even for a device that shares
// paths. (The plan's "no repo names unless sharePaths" is satisfied at its strictest setting.)

import type { MachineWrapped } from "./machine-wrapped";

/** Version of the share body. Bump when the card shape changes incompatibly. */
export const WRAPPED_SHARE_SCHEMA_VERSION = 1;

/** Caps — the server's strict schema rejects a body over any of them. */
export const MAX_SHARE_LANGUAGES = 6;
export const MAX_SHARE_UNPRICED = 20;
export const MAX_SHARE_NAME_LENGTH = 40;
export const MAX_SHARE_MODEL_LENGTH = 100;
/** Seconds-level sanity bounds: a year has at most 366 days and 8,784 hours. */
export const MAX_YEAR_ACTIVE_HOURS = 8_784;

export interface MachineWrappedShareCard {
  reposTouched: number;
  commits: number;
  /** Top languages by files changed; colours are looked up from the site's table at render. */
  languages: Array<{ name: string; pct: number }>;
  ai: {
    sessions: number;
    turns: number;
    activeMinutes: number;
    tokens: number;
    /** API-equivalent USD, never an invoice; null when nothing was priced. */
    costUsd: number | null;
    topModel: string | null;
    unpriced: string[];
    /** `YYYY-MM-DD` — the price table the cost was computed from. */
    pricesAsOf: string;
  };
  commitActiveMinutes: number;
  /** 0–1, or null when there was no activity of either kind. */
  aiShare: number | null;
  /** Active hours per weekday (index 0 = Sunday), 7 entries. */
  weekdayActivity: number[];
  /** Active days per hour of day (index 0 = midnight), 24 entries. */
  hourActivity: number[];
  busiestWeekday: number | null;
  busiestHour: number | null;
  activeDays: number;
  longestStreakDays: number;
  diskReclaimedBytes: number | null;
}

/** `POST /api/endpoint/wrapped-share` */
export interface WrappedShareBody {
  schemaVersion: typeof WRAPPED_SHARE_SCHEMA_VERSION;
  year: number;
  card: MachineWrappedShareCard;
}

/**
 * Pick the shareable fields of a Machine Wrapped, by name. An allow-list, not a spread: a field
 * added to `MachineWrapped` later (say, a repo list) stays on the device until it is deliberately
 * added here AND to the server schema.
 */
export function buildShareBody(w: MachineWrapped): WrappedShareBody {
  return {
    schemaVersion: WRAPPED_SHARE_SCHEMA_VERSION,
    year: w.year,
    card: {
      reposTouched: w.reposTouched,
      commits: w.commits,
      languages: w.languages
        .slice(0, MAX_SHARE_LANGUAGES)
        .map((l) => ({ name: l.name, pct: l.pct })),
      ai: {
        sessions: w.ai.sessions,
        turns: w.ai.turns,
        activeMinutes: w.ai.activeMinutes,
        tokens: w.ai.tokens,
        costUsd: w.ai.costUsd,
        topModel: w.ai.topModel,
        unpriced: w.ai.unpriced.slice(0, MAX_SHARE_UNPRICED),
        pricesAsOf: w.ai.pricesAsOf,
      },
      commitActiveMinutes: w.commitActiveMinutes,
      aiShare: w.aiShare,
      weekdayActivity: [...w.weekdayActivity],
      hourActivity: [...w.hourActivity],
      busiestWeekday: w.busiestWeekday,
      busiestHour: w.busiestHour,
      activeDays: w.activeDays,
      longestStreakDays: w.longestStreakDays,
      diskReclaimedBytes: w.diskReclaimedBytes,
    },
  };
}
