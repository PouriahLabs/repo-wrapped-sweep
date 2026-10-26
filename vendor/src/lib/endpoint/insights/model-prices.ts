// Pinned model price table for Machine Insights AI usage (ENDPOINT-MACHINE-INSIGHTS § C2.4,
// decision C9.3) — PURE data. Same $/MTok shape as the ledger in `src/lib/spend.ts`, plus
// the two cache rates a transcript's usage block carries.
//
// These are API-EQUIVALENT rates: what the same tokens would cost on the pay-as-you-go API.
// A Pro/Max/Team subscriber is not billed this; the number is never an invoice. The table is
// PINNED (no network call from a local tool), so every report shows `PRICES_AS_OF` — bump the
// date whenever a rate below is re-checked against the vendors' price pages.
//
// The Claude input/output rates are copied from `spend.ts` (it imports the DB client, so the
// CLI bundle can't import it; a test keeps the two tables in step). Cache rates are derived:
//   Anthropic — cache write (5-minute TTL) = 1.25 × input, cache read = 0.10 × input.
//   OpenAI    — cached input = 0.10 × input; there is no separate cache-write charge (= input).
// The 1-hour Anthropic cache TTL bills 2 × input for writes; a transcript's single
// `cache_creation_input_tokens` total doesn't say which TTL it was, so writes price at the 5-minute rate.

/** When these rates were last checked. Shown in every AI-usage report. */
export const PRICES_AS_OF = "2026-10-26";

/** USD per million tokens. */
export interface ModelPrice {
  input: number;
  output: number;
  cacheWrite: number;
  cacheRead: number;
}

const anthropic = (input: number, output: number): ModelPrice => ({
  input,
  output,
  cacheWrite: round6(input * 1.25),
  cacheRead: round6(input * 0.1),
});

const openai = (input: number, output: number): ModelPrice => ({
  input,
  output,
  cacheWrite: input,
  cacheRead: round6(input * 0.1),
});

function round6(n: number): number {
  return Math.round(n * 1e6) / 1e6;
}

/**
 * Keyed by model family id. A concrete id resolves by exact key, or by the longest family
 * followed by a `-` (so `claude-opus-5-5` and `claude-haiku-4-5-20251001` find their family,
 * while `gpt-5.6-sol` — a different version — does NOT fall back to `gpt-5`).
 * A model with no entry is "unpriced": its tokens are counted, its cost is null.
 */
export const MODEL_PRICES: Readonly<Record<string, ModelPrice>> = {
  // Anthropic
  "claude-fable-5": anthropic(10, 50),
  "claude-opus-5": anthropic(5, 25),
  "claude-opus-4-8": anthropic(5, 25),
  "claude-opus-4-6": anthropic(5, 25),
  "claude-opus-4-5": anthropic(5, 25),
  "claude-opus-4-1": anthropic(15, 75),
  "claude-opus-4-20250514": anthropic(15, 75),
  "claude-sonnet-5": anthropic(3, 15),
  "claude-sonnet-4-6": anthropic(3, 15),
  "claude-sonnet-4-5": anthropic(3, 15),
  "claude-sonnet-4-20250514": anthropic(3, 15),
  "claude-haiku-4-5": anthropic(1, 5),
  // OpenAI / Codex — GPT-5 family list pricing, as in spend.ts.
  "gpt-5-nano": openai(0.05, 0.4),
  "gpt-5-mini": openai(0.25, 2),
  "gpt-5": openai(1.25, 10),
  "gpt-5.1": openai(1.25, 10),
  "gpt-5.2": openai(1.75, 14),
  "gpt-5.4-nano": openai(0.2, 1.25),
  "gpt-5.4-mini": openai(0.75, 4.5),
  "gpt-5.4": openai(2.5, 15),
  "gpt-5.5": openai(5, 30),
};

/** The price for a model id, or null when it's unpriced. */
export function resolveModelPrice(model: string): ModelPrice | null {
  const exact = MODEL_PRICES[model];
  if (exact) return exact;
  let best: ModelPrice | null = null;
  let bestLen = -1;
  for (const [family, price] of Object.entries(MODEL_PRICES)) {
    if (model.startsWith(`${family}-`) && family.length > bestLen) {
      best = price;
      bestLen = family.length;
    }
  }
  return best;
}

export interface TokenCounts {
  inputTokens: number;
  outputTokens: number;
  cacheWriteTokens: number;
  cacheReadTokens: number;
}

/** API-equivalent USD for a token bundle; null when the model is unpriced. */
export function apiEquivalentCostUsd(model: string, t: TokenCounts): number | null {
  const p = resolveModelPrice(model);
  if (!p) return null;
  return (
    (t.inputTokens * p.input +
      t.outputTokens * p.output +
      t.cacheWriteTokens * p.cacheWrite +
      t.cacheReadTokens * p.cacheRead) /
    1_000_000
  );
}
