import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PRICES_AS_OF } from "@/lib/endpoint/insights/model-prices";
import { main, type CliIO } from "../src/cli";
import { AI_CURSOR_FILE, AI_STORE_FILE } from "../src/insights/ai-usage";
import {
  SENTINEL,
  ccLine,
  ccUserLine,
  codexMeta,
  codexText,
  codexTokens,
  writeLines,
} from "./ai-fixture";
import { captureIO, makeFixture, type Fixture } from "./helpers";
import { gitIn, put } from "./insights-fixture";

let fx: Fixture;
afterEach(() => fx?.cleanup());

const HOUR = 3_600_000;
const MIN = 60_000;

async function run(args: string[], extra: Partial<CliIO> = {}) {
  const io = { ...captureIO(), ...extra };
  const code = await main(args, io, fx.env, fx.root);
  return { code, out: io.out(), err: io.err() };
}

/**
 * A home with one repo (`~/code/app`: a commit of a .ts and a .py file this year by the
 * fixture identity), Claude Code turns inside it (one by an unpriced model), a Claude turn
 * outside any repo, and a Codex session — every text slot carrying the SENTINEL.
 */
function setup() {
  fx = makeFixture();
  const now = Date.now();
  const yearStart = new Date(new Date(now).getFullYear(), 0, 1).getTime();
  const at = Math.max(now - 2 * HOUR, yearStart + HOUR);

  const repo = path.join(fx.home, "code", "app");
  put(path.join(repo, "src", "index.ts"), "export const a = 1;\n");
  put(path.join(repo, "tool.py"), "print(1)\n");
  put(path.join(repo, "README.md"), "# app\n");
  fs.mkdirSync(repo, { recursive: true });
  gitIn(fx, repo, ["init", "-q", "-b", "main"]);
  gitIn(fx, repo, ["config", "commit.gpgsign", "false"]);
  // The CLI's own git reads the repo config for the author to count.
  gitIn(fx, repo, ["config", "user.email", "fixture@example.invalid"]);
  gitIn(fx, repo, ["add", "-A"]);
  gitIn(fx, repo, ["commit", "-q", "-m", `${SENTINEL} commit message`], at);

  const cwd = path.join(repo, "src");
  const projects = path.join(fx.home, ".claude", "projects", "-code-app");
  writeLines(path.join(projects, "s1.jsonl"), [
    ccUserLine(at - MIN, "s1", cwd),
    ccLine({ id: "A", at, session: "s1", cwd, input: 1000, output: 2000 }),
    ccLine({ id: "B", at: at + 5 * MIN, session: "s1", cwd, input: 1000, output: 2000 }),
    ccLine({
      id: "C",
      at: at + 6 * MIN,
      session: "s1",
      cwd,
      model: "claude-mystery-9",
      output: 50,
    }),
  ]);
  writeLines(path.join(fx.home, ".claude", "projects", "-scratch", "s2.jsonl"), [
    ccLine({ id: "D", at: at + MIN, session: "s2", cwd: path.join(fx.home, "scratch") }),
  ]);
  writeLines(path.join(fx.home, ".codex", "sessions", "2026", "rollout-1.jsonl"), [
    ...codexMeta(at, "cx-1", repo, "gpt-5.5"),
    codexText(at + 1000),
    codexTokens(at + 2000, 1200, 1000, 600, 200),
  ]);
  return { repo, now };
}

const noSentinel = (s: string) => expect(s).not.toContain(SENTINEL);

describe("ai command", () => {
  it("--json: per-repo groups, API-equivalent cost, prices date, unpriced models — and no message text anywhere", async () => {
    setup();
    const r = await run(["ai", "--since", "30d", "--json"]);
    expect(r.code).toBe(0);
    const j = JSON.parse(r.out);
    expect(j).toMatchObject({
      schemaVersion: 1,
      kind: "ai-usage",
      by: "repo",
      costBasis: "API-equivalent cost",
      pricesAsOf: PRICES_AS_OF,
      unpriced: ["claude-mystery-9"],
    });
    const byRepo = Object.fromEntries(
      j.groups.map((g: { key: string | null }) => [String(g.key), g]),
    );
    expect(Object.keys(byRepo).sort()).toEqual(["null", "~/code/app"]);
    expect(byRepo["~/code/app"]).toMatchObject({ sessions: 2, turns: 4 });
    expect(byRepo["~/code/app"].unpricedTokens).toBe(10 + 50);
    expect(j.totals.sessions).toBe(3);
    expect(j.notes.join(" ")).toContain(`Prices as of ${PRICES_AS_OF}`);
    expect(j.notes.join(" ")).toContain("not an invoice");

    // The privacy contract, end to end: the report, the store and the cursor hold no text.
    noSentinel(r.out);
    noSentinel(r.err);
    noSentinel(fs.readFileSync(path.join(fx.env.configDir, AI_STORE_FILE), "utf8"));
    noSentinel(fs.readFileSync(path.join(fx.env.configDir, AI_CURSOR_FILE), "utf8"));
    expect(r.out).not.toContain(JSON.stringify(fx.home).slice(1, -1));
  });

  it("text: always prints the cost basis and PRICES_AS_OF; --by model and --by day", async () => {
    setup();
    const r = await run(["ai"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("AI usage — last 30 days");
    expect(r.out).toContain("API-EQUIVALENT COST");
    expect(r.out).toContain(`Prices as of ${PRICES_AS_OF}`);
    expect(r.out).toContain("Unpriced models (tokens counted, no cost): claude-mystery-9");
    expect(r.out).toContain("~/code/app");
    expect(r.out).toContain("(no repo)");
    noSentinel(r.out);

    const m = await run(["ai", "--by", "model"]);
    expect(m.out).toContain("claude-opus-5-5 (claude-code)");
    expect(m.out).toContain("gpt-5.5 (codex)");
    const d = await run(["ai", "--by", "day", "--json"]);
    expect(JSON.parse(d.out).groups[0].key).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("an empty machine still prints the cost basis", async () => {
    fx = makeFixture();
    const r = await run(["ai"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("No Claude Code or Codex usage in this period.");
    expect(r.out).toContain(`Prices as of ${PRICES_AS_OF}`);
  });

  it("rejects a bad --by or --since", async () => {
    fx = makeFixture();
    expect((await run(["ai", "--by", "week"])).code).toBe(2);
    expect((await run(["ai", "--since", "yesterday"])).code).toBe(2);
  });

  it("--help documents ai, wrapped and the 64 KB line cap", async () => {
    fx = makeFixture();
    const h = await run(["--help"]);
    for (const s of [
      "repo-wrapped-sweep ai [--since",
      "repo-wrapped-sweep wrapped [--year",
      "64 KB",
      "--png",
    ]) {
      expect(h.out).toContain(s);
    }
  });
});

describe("wrapped command", () => {
  it("writes a self-contained card with aggregates only — no repo names, paths or message text", async () => {
    const { now } = setup();
    const out = path.join(fx.root, "card.html");
    const r = await run(["wrapped", "--out", out]);
    expect(r.code).toBe(0);
    expect(r.err).toContain(`wrote ${out}`);
    const html = fs.readFileSync(out, "utf8");
    const year = new Date(now).getFullYear();
    expect(html).toContain(`<title>Machine Wrapped ${year}</title>`);
    expect(html).toContain("API-equivalent cost");
    expect(html).toContain(PRICES_AS_OF);
    expect(html).toContain("--chart-1:");
    expect(html).not.toMatch(/<script|<link|src="http/); // self-contained, nothing loaded
    // One commit, one repo, languages from the changed files (Markdown is not a language).
    expect(r.out).toContain("1 commit across 1 repo");
    expect(r.out).toMatch(/languages: (Python 50%, TypeScript 50%|TypeScript 50%, Python 50%)\n/);
    expect(r.out).toContain("3 AI sessions");

    noSentinel(html);
    noSentinel(r.out);
    expect(html).not.toContain("code/app");
    expect(html).not.toContain("fixture@example.invalid");
    expect(html).not.toContain(fx.home.replace(/\\/g, "/"));
    expect(html).not.toContain(fx.home);
  });

  it("--png without Chrome/Edge says so and keeps the HTML", async () => {
    setup();
    const out = path.join(fx.root, "card.html");
    const r = await run(["wrapped", "--out", out, "--png"], { findBrowser: () => null });
    expect(r.code).toBe(0);
    expect(fs.existsSync(out)).toBe(true);
    expect(r.err).toContain("no PNG: Chrome or Edge was not found");
  });

  it("rejects a future --year", async () => {
    fx = makeFixture();
    expect((await run(["wrapped", "--year", "2999"])).code).toBe(2);
  });
});
