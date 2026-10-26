// Validity checks (§ A2.6, opt-in `--validate`): is a found key still LIVE?
// Ranks working keys above dead ones.
//
// This is the one place the tool sends a secret anywhere — and only to that
// secret's OWN provider, over HTTPS, interactively. Decision E3: never in
// scheduled or MDM runs (a background job that mails every secret it finds to a
// provider is the wrong default for a security tool).
//
//   • 5 s timeout, never retried, nothing logged, the secret never printed
//   • AWS keys and private keys are `unknown` in v1 (SigV4 signing / no endpoint)
//   • the provider is picked from the SECRET'S SHAPE, not the rule id — the
//     content rules have no Anthropic/OpenAI rule, those arrive via the generic one

export type Validity = "live" | "revoked" | "unknown";

export type Provider = "github" | "anthropic" | "openai" | "stripe" | "slack";

export const PROVIDER_LABEL: Record<Provider, string> = {
  github: "GitHub",
  anthropic: "Anthropic",
  openai: "OpenAI",
  stripe: "Stripe",
  slack: "Slack",
};

/** Which provider does this secret belong to? Pure; null = no endpoint to ask. */
export function providerFor(secret: string): Provider | null {
  if (
    /^(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}$/.test(secret) ||
    /^github_pat_[A-Za-z0-9_]{50,}$/.test(secret)
  ) {
    return "github";
  }
  if (/^sk-ant-[A-Za-z0-9_-]{20,}$/.test(secret)) return "anthropic";
  if (/^(?:sk|rk)_live_[A-Za-z0-9]{24,}$/.test(secret)) return "stripe";
  if (/^xox[baprs]-[A-Za-z0-9-]{10,}$/.test(secret)) return "slack";
  // OpenAI: sk-… / sk-proj-… / sk-svcacct-… (anything not Anthropic's sk-ant-).
  if (/^sk-(?!ant-)[A-Za-z0-9_-]{20,}$/.test(secret)) return "openai";
  return null;
}

export interface CheckRequest {
  url: string;
  method: "GET" | "POST";
  headers: Record<string, string>;
}

/** The request that asks a provider whether this secret works. Pure. */
export function buildRequest(provider: Provider, secret: string): CheckRequest {
  switch (provider) {
    case "github":
      return {
        url: "https://api.github.com/user",
        method: "GET",
        headers: {
          authorization: `Bearer ${secret}`,
          accept: "application/vnd.github+json",
          "x-github-api-version": "2022-11-28",
        },
      };
    case "anthropic":
      return {
        url: "https://api.anthropic.com/v1/models",
        method: "GET",
        headers: { "x-api-key": secret, "anthropic-version": "2023-06-01" },
      };
    case "openai":
      return {
        url: "https://api.openai.com/v1/models",
        method: "GET",
        headers: { authorization: `Bearer ${secret}` },
      };
    case "stripe":
      return {
        url: "https://api.stripe.com/v1/balance",
        method: "GET",
        headers: { authorization: `Bearer ${secret}` },
      };
    case "slack":
      return {
        url: "https://slack.com/api/auth.test",
        method: "POST",
        headers: {
          authorization: `Bearer ${secret}`,
          "content-type": "application/x-www-form-urlencoded",
        },
      };
  }
}

/** Slack answers 200 either way; the verdict is in the body. */
const SLACK_DEAD = new Set([
  "invalid_auth",
  "token_revoked",
  "account_inactive",
  "token_expired",
  "not_authed",
]);

/**
 * Map a provider's answer to a verdict. Conservative: only an explicit success is
 * `live` and only an explicit "this credential is bad" is `revoked`; a 403 (could
 * be a rate limit or a suspended account), a 429 or a 5xx is `unknown`.
 */
export function interpretStatus(
  provider: Provider,
  status: number,
  body?: { ok?: boolean; error?: string } | null,
): Validity {
  if (provider === "slack") {
    if (status !== 200 || !body) return "unknown";
    if (body.ok === true) return "live";
    return body.error && SLACK_DEAD.has(body.error) ? "revoked" : "unknown";
  }
  if (status === 200) return "live";
  if (status === 401) return "revoked";
  return "unknown";
}

export type HttpFetch = (
  url: string,
  init: { method: string; headers: Record<string, string>; signal?: AbortSignal },
) => Promise<{ status: number; json(): Promise<unknown> }>;

export const VALIDATE_TIMEOUT_MS = 5_000;

/** One check: a single attempt, 5 s timeout, no retry, nothing logged. */
export async function checkSecret(
  secret: string,
  fetchImpl: HttpFetch = globalThis.fetch as unknown as HttpFetch,
): Promise<{ provider: Provider | null; validity: Validity }> {
  const provider = providerFor(secret);
  if (!provider) return { provider: null, validity: "unknown" };
  const req = buildRequest(provider, secret);
  try {
    const res = await fetchImpl(req.url, {
      method: req.method,
      headers: req.headers,
      signal: AbortSignal.timeout(VALIDATE_TIMEOUT_MS),
    });
    let body: { ok?: boolean; error?: string } | null = null;
    if (provider === "slack") {
      body = (await res.json().catch(() => null)) as typeof body;
    }
    return { provider, validity: interpretStatus(provider, res.status, body) };
  } catch {
    return { provider, validity: "unknown" };
  }
}

/** The one-line warning printed before the FIRST outbound call. */
export const VALIDATE_WARNING =
  "--validate sends each recognised key to its own provider (GitHub, Anthropic, OpenAI, Stripe, Slack) " +
  "to check whether it still works. Nothing is logged; AWS keys and private keys are not checked.";

/**
 * Live keys first (a working leaked key outranks a dead critical), then the
 * report's existing order (severity, copies, rule). Stable; does not mutate.
 */
export function rankByValidity<T extends { fingerprint: string }>(
  groups: readonly T[],
  validity: ReadonlyMap<string, Validity>,
): T[] {
  return groups
    .map((g, i) => ({ g, i }))
    .sort((a, b) => {
      const la = validity.get(a.g.fingerprint) === "live" ? 0 : 1;
      const lb = validity.get(b.g.fingerprint) === "live" ? 0 : 1;
      return la - lb || a.i - b.i;
    })
    .map((x) => x.g);
}
