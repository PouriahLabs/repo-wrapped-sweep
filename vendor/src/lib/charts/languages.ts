// ---------------------------------------------------------------------------
// Language mix → donut slices — pure, unit-tested.
//
// Languages keep their CANONICAL colors (LANG_COLORS — TypeScript blue, Go cyan,
// Rust rust) rather than taking generic categorical slots. Color follows the
// entity, and for languages the entity already has a color the reader knows from
// GitHub itself; overriding it with "slot 3" would destroy recognition, not aid
// it. The legend + per-slice percentage labels are the required relief, since
// this domain palette can't be re-validated for CVD.
//
// The upstream mixes are a TOP-5 (wrapped/facts.ts, dev-wrapped/facts.ts), so
// their percentages usually do NOT sum to 100. A donut whose arcs don't close is
// a lie about the whole — so the remainder is folded into an explicit "Other"
// slice rather than silently inflating the five we show.
// ---------------------------------------------------------------------------

import { LANG_COLORS, LANG_FALLBACK_COLOR } from "@/config/lang-colors";
import { OTHER_LABEL, type SeriesSlice } from "@/lib/charts/palette";

export interface LanguageShare {
  name: string;
  pct: number;
}

/** Below this, an "Other" wedge is rounding noise, not a fact worth a slice. */
const MIN_OTHER_PCT = 1;

/**
 * Turn a raw language→bytes map (GitHub's `/languages`) into a top-N share
 * list. Percentages are of the FULL byte total, so the shown languages plus the
 * remainder always add to 100 — `languageSlices` then folds that remainder into
 * an explicit "Other" slice. Pure; drops non-positive/non-finite byte counts.
 */
export function languageShares(
  bytes: Record<string, number>,
  opts: { topN?: number } = {},
): LanguageShare[] {
  const topN = opts.topN ?? 6;
  const entries = Object.entries(bytes).filter(([, v]) => Number.isFinite(v) && v > 0);
  const total = entries.reduce((sum, [, v]) => sum + v, 0);
  if (total <= 0) return [];
  return entries
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
    .map(([name, v]) => ({ name, pct: Math.round((v / total) * 1000) / 10 }));
}

export function languageSlices(mix: LanguageShare[]): SeriesSlice[] {
  const clean = mix
    .filter((l) => Number.isFinite(l.pct) && l.pct > 0)
    .map((l) => ({
      label: l.name,
      value: l.pct,
      pct: l.pct,
      color: LANG_COLORS[l.name] ?? LANG_FALLBACK_COLOR,
      isOther: false,
    }));

  if (clean.length === 0) return [];

  const shown = clean.reduce((sum, l) => sum + l.pct, 0);
  const remainder = Math.round((100 - shown) * 10) / 10;

  if (remainder >= MIN_OTHER_PCT) {
    clean.push({
      label: OTHER_LABEL,
      value: remainder,
      pct: remainder,
      color: "hsl(var(--chart-other))",
      isOther: true,
    });
  }

  return clean;
}
