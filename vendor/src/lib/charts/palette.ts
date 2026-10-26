// ---------------------------------------------------------------------------
// Data-viz palette helpers — pure, unit-tested.
//
// The colors themselves live in `src/styles/tokens.css` as `--chart-1..5` +
// `--chart-other`. They are DELIBERATELY not derived from `--brand`: that hue is
// user-swappable (data-brand=teal/blue/coral/pink), so a themed series color
// would (a) collide with a fixed neighbour — brand=blue vs the blue slot,
// brand=teal vs the aqua slot — and (b) repaint series identity when someone
// changes the site theme. Charts need stable, colorblind-safe identity.
//
// The 5-slot order (violet → aqua → yellow → blue → red) is the CVD-safety
// mechanism, not cosmetic: it was chosen by validating candidate orderings
// (worst adjacent ΔE 47.2 light / 41.3 dark). A 6th category is NEVER given a
// generated hue — it folds into a neutral "Other" via `foldSeries`.
// ---------------------------------------------------------------------------

/** Colored categorical slots. Anything beyond this folds into "Other". */
export const CHART_SLOTS = 5;

export const OTHER_LABEL = "Other";

/**
 * CSS color for categorical slot `i` (0-based). Out-of-range indices collapse to
 * the neutral "Other" gray rather than cycling — cycling would give two series
 * the same hue, which is the single worst thing a categorical palette can do.
 */
export function seriesColor(i: number): string {
  if (!Number.isInteger(i) || i < 0 || i >= CHART_SLOTS) return "hsl(var(--chart-other))";
  return `hsl(var(--chart-${i + 1}))`;
}

export interface SeriesInput {
  label: string;
  value: number;
}

export interface SeriesSlice extends SeriesInput {
  /** CSS color — a categorical slot, or the neutral gray for the folded tail. */
  color: string;
  /** Share of the total, 0–100 with one decimal (0 when the total is 0). */
  pct: number;
  /** True for the synthetic "Other" row folded from the tail. */
  isOther: boolean;
}

function share(part: number, whole: number): number {
  if (whole <= 0) return 0;
  return Math.round((part / whole) * 1000) / 10;
}

/**
 * Rank `items` by value and assign fixed categorical colors, folding everything
 * past `CHART_SLOTS` into a single neutral "Other" slice. Negative/non-finite
 * values are floored to 0 (a chart must never render a negative arc), and
 * zero-valued entries are dropped so an empty category can't claim a hue.
 *
 * Pure. Ties break on label for a stable, deterministic order across renders —
 * color must follow the entity, never the render.
 */
export function foldSeries(items: SeriesInput[], maxSlots: number = CHART_SLOTS): SeriesSlice[] {
  const clean = items
    .map((it) => ({
      label: it.label,
      value: Number.isFinite(it.value) && it.value > 0 ? it.value : 0,
    }))
    .filter((it) => it.value > 0)
    .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label));

  const total = clean.reduce((sum, it) => sum + it.value, 0);
  const head = clean.slice(0, maxSlots);
  const tail = clean.slice(maxSlots);

  const slices: SeriesSlice[] = head.map((it, i) => ({
    label: it.label,
    value: it.value,
    color: seriesColor(i),
    pct: share(it.value, total),
    isOther: false,
  }));

  if (tail.length > 0) {
    const value = tail.reduce((sum, it) => sum + it.value, 0);
    slices.push({
      label: OTHER_LABEL,
      value,
      color: "hsl(var(--chart-other))",
      pct: share(value, total),
      isOther: true,
    });
  }

  return slices;
}

// --- Severity (reserved status palette — never a data series) ---------------

export type SeverityKey = "critical" | "high" | "medium" | "low";

/** Fixed, unthemed severity colors. Always rendered WITH a label, never alone. */
export const SEVERITY_COLOR: Record<SeverityKey, string> = {
  critical: "hsl(var(--sev-critical))",
  high: "hsl(var(--sev-high))",
  medium: "hsl(var(--sev-medium))",
  low: "hsl(var(--sev-low))",
};

/** Display order: worst first — the order the board reads in. */
export const SEVERITY_ORDER: SeverityKey[] = ["critical", "high", "medium", "low"];
