import { afterEach, describe, expect, it, vi } from "vitest";
import {
  VALIDATE_TIMEOUT_MS,
  VALIDATE_WARNING,
  buildRequest,
  checkSecret,
  interpretStatus,
  providerFor,
  rankByValidity,
  type HttpFetch,
  type Provider,
} from "../src/validate";
import { pemHeader, scramble } from "./helpers";

afterEach(() => vi.restoreAllMocks());

// Provider-shaped secrets assembled from fragments (no committed literal looks real).
const github = () => "gh" + "p_" + scramble(36);
const fineGrained = () => "github_" + "pat_" + scramble(22) + "_" + scramble(59);
const anthropic = () => "sk-" + "ant-" + "api03-" + scramble(40);
const openai = () => "sk-" + "proj-" + scramble(40);
const stripe = () => "sk_" + "live_" + scramble(24);
const slack = () => "xo" + "xb-" + scramble(20);

describe("providerFor", () => {
  it("picks the provider from the secret's shape", () => {
    expect(providerFor(github())).toBe("github");
    expect(providerFor(fineGrained())).toBe("github");
    expect(providerFor(anthropic())).toBe("anthropic");
    expect(providerFor(openai())).toBe("openai");
    expect(providerFor(stripe())).toBe("stripe");
    expect(providerFor(slack())).toBe("slack");
  });
  it("does not mistake Anthropic for OpenAI, and gives AWS/private keys/unknown nothing", () => {
    expect(providerFor(anthropic())).not.toBe("openai");
    expect(providerFor("AKI" + "A" + "B9D2F7H4K6N1Q8S3")).toBeNull();
    expect(providerFor(pemHeader("RSA PRIVATE KEY"))).toBeNull();
    expect(providerFor("hunter2")).toBeNull();
    expect(providerFor("ghr_" + scramble(40))).toBeNull(); // refresh tokens have no endpoint
  });
});

describe("buildRequest — the § A2.6 endpoints", () => {
  const cases: [Provider, string, string, string][] = [
    ["github", "https://api.github.com/user", "GET", github()],
    ["anthropic", "https://api.anthropic.com/v1/models", "GET", anthropic()],
    ["openai", "https://api.openai.com/v1/models", "GET", openai()],
    ["stripe", "https://api.stripe.com/v1/balance", "GET", stripe()],
    ["slack", "https://slack.com/api/auth.test", "POST", slack()],
  ];
  for (const [provider, url, method, secret] of cases) {
    it(`${provider} → ${method} ${url}`, () => {
      const req = buildRequest(provider, secret);
      expect(req.url).toBe(url);
      expect(req.method).toBe(method);
      // the secret travels in a header, never in the URL
      expect(req.url).not.toContain(secret);
      expect(JSON.stringify(req.headers)).toContain(secret);
    });
  }
  it("Anthropic uses x-api-key + a version header", () => {
    const h = buildRequest("anthropic", anthropic()).headers;
    expect(h["x-api-key"]).toBeTruthy();
    expect(h["anthropic-version"]).toBe("2023-06-01");
  });
});

describe("interpretStatus — HTTP → live / revoked / unknown", () => {
  it("200 is live and 401 is revoked for the bearer-style providers", () => {
    for (const p of ["github", "anthropic", "openai", "stripe"] as const) {
      expect(interpretStatus(p, 200)).toBe("live");
      expect(interpretStatus(p, 401)).toBe("revoked");
    }
  });
  it("anything ambiguous is unknown: 403, 404, 429, 5xx", () => {
    for (const p of ["github", "anthropic", "openai", "stripe"] as const) {
      for (const status of [400, 403, 404, 429, 500, 502, 503]) {
        expect(interpretStatus(p, status), `${p} ${status}`).toBe("unknown");
      }
    }
  });
  it("Slack answers 200 either way — the body decides", () => {
    expect(interpretStatus("slack", 200, { ok: true })).toBe("live");
    for (const error of [
      "invalid_auth",
      "token_revoked",
      "account_inactive",
      "token_expired",
      "not_authed",
    ]) {
      expect(interpretStatus("slack", 200, { ok: false, error })).toBe("revoked");
    }
    expect(interpretStatus("slack", 200, { ok: false, error: "ratelimited" })).toBe("unknown");
    expect(interpretStatus("slack", 200, null)).toBe("unknown");
    expect(interpretStatus("slack", 500, { ok: true })).toBe("unknown");
  });
});

function fakeFetch(status: number, body?: unknown): HttpFetch & { calls: Parameters<HttpFetch>[] } {
  const calls: Parameters<HttpFetch>[] = [];
  const f = (async (...args: Parameters<HttpFetch>) => {
    calls.push(args);
    return { status, json: async () => body ?? {} };
  }) as HttpFetch & { calls: typeof calls };
  f.calls = calls;
  return f;
}

describe("checkSecret", () => {
  it("makes exactly ONE attempt with a 5 s timeout signal, and no retry on a bad answer", async () => {
    const f = fakeFetch(503);
    const r = await checkSecret(github(), f);
    expect(r).toEqual({ provider: "github", validity: "unknown" });
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]![1].signal).toBeInstanceOf(AbortSignal);
    expect(VALIDATE_TIMEOUT_MS).toBe(5000);
  });

  it("maps a live and a revoked key", async () => {
    expect((await checkSecret(github(), fakeFetch(200))).validity).toBe("live");
    expect((await checkSecret(github(), fakeFetch(401))).validity).toBe("revoked");
    expect((await checkSecret(slack(), fakeFetch(200, { ok: true }))).validity).toBe("live");
  });

  it("a network error or abort is unknown — and is not retried", async () => {
    let n = 0;
    const throwing = (async () => {
      n++;
      throw new Error("ETIMEDOUT");
    }) as unknown as HttpFetch;
    expect(await checkSecret(github(), throwing)).toEqual({
      provider: "github",
      validity: "unknown",
    });
    expect(n).toBe(1);
  });

  it("never contacts anyone for AWS keys, private keys or unrecognised secrets", async () => {
    const f = fakeFetch(200);
    for (const s of [
      "AKI" + "A" + "B9D2F7H4K6N1Q8S3",
      pemHeader("RSA PRIVATE KEY"),
      scramble(40),
    ]) {
      expect(await checkSecret(s, f)).toEqual({ provider: null, validity: "unknown" });
    }
    expect(f.calls).toHaveLength(0);
  });

  it("logs nothing: no console output, ever, even on failure", async () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation(() => {}),
    );
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    await checkSecret(github(), fakeFetch(401));
    await checkSecret(github(), (async () => {
      throw new Error("boom");
    }) as unknown as HttpFetch);
    for (const s of spies) expect(s).not.toHaveBeenCalled();
    expect(stderr).not.toHaveBeenCalled();
    expect(stdout).not.toHaveBeenCalled();
  });
});

describe("rankByValidity", () => {
  const g = (fp: string) => ({ fingerprint: fp });
  it("floats live keys above dead ones, keeping the original order otherwise", () => {
    const groups = [
      g("critical-dead"),
      g("high-unknown"),
      g("medium-live"),
      g("low-live"),
      g("low-revoked"),
    ];
    const v = new Map([
      ["critical-dead", "revoked" as const],
      ["medium-live", "live" as const],
      ["low-live", "live" as const],
      ["low-revoked", "revoked" as const],
    ]);
    expect(rankByValidity(groups, v).map((x) => x.fingerprint)).toEqual([
      "medium-live",
      "low-live",
      "critical-dead",
      "high-unknown",
      "low-revoked",
    ]);
    expect(groups.map((x) => x.fingerprint)[0]).toBe("critical-dead"); // not mutated
  });
  it("is the identity with no validity data", () => {
    const groups = [g("a"), g("b")];
    expect(rankByValidity(groups, new Map())).toEqual(groups);
  });
});

describe("warning", () => {
  it("states that keys are sent to their own provider", () => {
    expect(VALIDATE_WARNING).toMatch(/sends each recognised key to its own provider/);
    expect(VALIDATE_WARNING.split("\n")).toHaveLength(1);
  });
});
