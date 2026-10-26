import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import type { UsageEvent } from "@/lib/endpoint/insights/ai-usage";
import {
  AI_CURSOR_FILE,
  AI_LINE_CAP_BYTES,
  AI_STORE_FILE,
  collectAiUsage,
  detectZstd,
  newReadStats,
  readByteLines,
  repoResolver,
} from "../src/insights/ai-usage";
import { buildAiReport, formatTokens, parseSince } from "../src/insights/ai-report";
import {
  SENTINEL,
  appendLines,
  ccLine,
  ccUserLine,
  codexMeta,
  codexText,
  codexTokens,
  writeLines,
} from "./ai-fixture";
import { makeFixture, type Fixture } from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

const HOUR = 3_600_000;
const MIN = 60_000;

async function* chunks(parts: string[]): AsyncGenerator<Buffer> {
  for (const p of parts) yield Buffer.from(p, "utf8");
}

async function lines(parts: string[], cap = 1024) {
  const stats = newReadStats();
  const out = [];
  for await (const l of readByteLines(chunks(parts), cap, stats)) out.push(l);
  return { out, stats };
}

describe("readByteLines", () => {
  it("splits on newline bytes, strips CR, and reports byte ends", async () => {
    const { out, stats } = await lines(["a\nbb\r", "\nccc"]);
    expect(out).toEqual([
      { line: "a", end: 2, complete: true },
      { line: "bb", end: 6, complete: true },
      { line: "ccc", end: 9, complete: false },
    ]);
    expect(stats.lines).toBe(2);
  });

  it("counts byte offsets, not characters, across 1-byte chunks", async () => {
    const text = "é\nx\n"; // é is two bytes
    const stats = newReadStats();
    const got = [];
    async function* bytes() {
      for (const b of Buffer.from(text)) yield Buffer.from([b]);
    }
    for await (const l of readByteLines(bytes(), 64, stats)) got.push(l);
    expect(got).toEqual([
      { line: "é", end: 3, complete: true },
      { line: "x", end: 5, complete: true },
    ]);
  });

  it("drops a line over the cap without buffering it, and carries on", async () => {
    const { out, stats } = await lines(["0123456789", "abc\nok\n"], 8);
    expect(out.map((l) => l.line)).toEqual([null, "ok"]);
    expect(stats.oversize).toBe(1);
    expect(stats.peakBufferedBytes).toBeLessThanOrEqual(8);
  });
});

describe("parseSince / formatTokens", () => {
  const now = Date.parse("2026-10-26T12:00:00Z");
  it("parses days and dates", () => {
    expect(parseSince("30d", now)).toBe(now - 30 * 86_400_000);
    expect(parseSince(undefined, now)).toBe(now - 30 * 86_400_000);
    expect(parseSince("2026-01-01", now)).toBe(Date.parse("2026-01-01T00:00:00Z"));
    expect(parseSince("soon", now)).toBeNull();
    expect(parseSince("2027-01-01", now)).toBeNull();
  });
  it("formats tokens compactly", () => {
    expect(formatTokens(950)).toBe("950");
    expect(formatTokens(12_300)).toBe("12.3k");
    expect(formatTokens(4_560_000)).toBe("4.56M");
    expect(formatTokens(1_200_000_000)).toBe("1.20B");
  });
});

/** A fixture home with one repo (`~/code/app`, has `.git`) and its Claude project folder. */
function claudeSetup() {
  fx = makeFixture();
  const repo = path.join(fx.home, "code", "app");
  fs.mkdirSync(path.join(repo, ".git"), { recursive: true });
  const cwd = path.join(repo, "packages", "web");
  fs.mkdirSync(cwd, { recursive: true });
  const projects = path.join(fx.home, ".claude", "projects", "-code-app");
  return { repo, cwd, projects };
}

const totalOf = (events: UsageEvent[]) =>
  buildAiReport(events, { since: 0, until: Date.now() + HOUR, by: "repo", repoOf: () => null })
    .totals;

describe("collectAiUsage — incremental and de-duplicated", () => {
  it("reads only appended lines, merges repeats across runs, and never double counts a resumed copy", async () => {
    const { cwd, projects } = claudeSetup();
    const now = Date.now();
    const t0 = now - 3 * HOUR;
    const s1 = path.join(projects, "s1.jsonl");
    const A = { id: "A", at: t0, session: "s1", cwd };
    const B = { id: "B", at: t0 + 5 * MIN, session: "s1", cwd };
    writeLines(s1, [
      ccUserLine(t0 - MIN, "s1", cwd),
      ccLine({ ...A, output: 50 }), // streamed: the same response logged twice…
      ccLine({ ...A, output: 100 }), // …with a growing output count
      ccLine({ ...B, output: 200 }),
    ]);

    const r1 = await collectAiUsage({ env: fx.env, now });
    expect(r1.scan).toMatchObject({ files: 1, filesRead: 1, linesRead: 4, newEvents: 2 });
    expect(r1.events.map((e) => e.outputTokens)).toEqual([100, 200]);

    // Run 2: B repeats (bigger), C is new, and D is half-written (no newline yet).
    const C = { id: "C", at: t0 + 10 * MIN, session: "s1", cwd };
    const D = { id: "D", at: t0 + 12 * MIN, session: "s1", cwd };
    const dLine = ccLine(D);
    appendLines(s1, [ccLine({ ...B, output: 300 }), ccLine(C)], dLine.slice(0, 40));
    const r2 = await collectAiUsage({ env: fx.env, now });
    expect(r2.scan).toMatchObject({ filesRead: 1, linesRead: 2, newEvents: 1 });
    expect(r2.events.map((e) => [e.dedupeKey !== null, e.outputTokens])).toEqual([
      [true, 100],
      [true, 300],
      [true, 100],
    ]);

    // Run 3: the half-written line completes; only it is read.
    fs.appendFileSync(s1, `${dLine.slice(40)}\n`);
    const r3 = await collectAiUsage({ env: fx.env, now });
    expect(r3.scan).toMatchObject({ linesRead: 1, newEvents: 1 });

    // Run 4: a resumed session copies the whole history into a new file, then adds E.
    const E = { id: "E", at: t0 + 20 * MIN, session: "s2", cwd };
    writeLines(path.join(projects, "s2.jsonl"), [
      ccLine({ ...A, session: "s2", output: 100 }),
      ccLine({ ...B, session: "s2", output: 300 }),
      ccLine({ ...C, session: "s2" }),
      ccLine({ ...D, session: "s2" }),
      ccLine(E),
    ]);
    const r4 = await collectAiUsage({ env: fx.env, now });
    expect(r4.scan).toMatchObject({ filesRead: 1, linesRead: 5, newEvents: 1 });
    const t4 = totalOf(r4.events);
    expect(t4.turns).toBe(5);
    expect(t4.outputTokens).toBe(100 + 300 + 100 + 100 + 100);
    // The first occurrence keeps its session: s1 for A–D, s2 only for E.
    expect(t4.sessions).toBe(2);

    // Run 5: s1 is rewritten smaller (shrunk) → re-read from the start, still no double count.
    writeLines(s1, [ccLine({ ...A, output: 100 })]);
    const r5 = await collectAiUsage({ env: fx.env, now });
    expect(r5.scan).toMatchObject({ filesRead: 1, linesRead: 1, newEvents: 0 });
    expect(totalOf(r5.events)).toEqual(t4);

    // Losing the store resets the cursor too: a full re-read lands on the same totals.
    fs.rmSync(path.join(fx.env.configDir, AI_STORE_FILE));
    const r6 = await collectAiUsage({ env: fx.env, now });
    expect(r6.scan.filesRead).toBe(2);
    expect(totalOf(r6.events).turns).toBe(5);
  });

  it("resumes a Codex rollout mid-file with the persisted session context", async () => {
    fx = makeFixture();
    const now = Date.now();
    const t0 = now - 2 * HOUR;
    const cwd = path.join(fx.home, "work");
    const day = path.join(fx.home, ".codex", "sessions", "2026", "10", "26");
    const file = path.join(day, "rollout-a.jsonl");
    writeLines(file, [
      ...codexMeta(t0, "cx-1", cwd, "gpt-5.5"),
      codexText(t0 + 1000),
      codexTokens(t0 + 2000, 1200, 1000, 600, 200),
      codexTokens(t0 + 3000, 1200, 1000, 600, 200), // a repeat of the same total
    ]);
    const r1 = await collectAiUsage({ env: fx.env, now });
    expect(r1.events).toHaveLength(1);
    expect(r1.events[0]).toMatchObject({
      inputTokens: 400,
      cacheReadTokens: 600,
      outputTokens: 200,
    });

    // Only token_count lines are appended: model, session and cwd come from the cursor's context.
    appendLines(file, [codexTokens(t0 + 60_000, 2000, 500, 0, 300)]);
    const r2 = await collectAiUsage({ env: fx.env, now });
    expect(r2.scan.linesRead).toBe(1);
    expect(r2.events[1]).toMatchObject({
      tool: "codex",
      model: "gpt-5.5",
      sessionId: "cx-1",
      cwd,
      inputTokens: 500,
      outputTokens: 300,
    });
    const cursor = JSON.parse(fs.readFileSync(path.join(fx.env.configDir, AI_CURSOR_FILE), "utf8"));
    expect(cursor.files[file].ctx).toMatchObject({
      sessionId: "cx-1",
      model: "gpt-5.5",
      lastTotal: 2000,
    });

    // Archiving moves the rollout: a new path, the same events, no double count.
    const archived = path.join(fx.home, ".codex", "archived_sessions", "rollout-a.jsonl");
    fs.mkdirSync(path.dirname(archived), { recursive: true });
    fs.renameSync(file, archived);
    const r3 = await collectAiUsage({ env: fx.env, now });
    expect(r3.scan).toMatchObject({ filesRead: 1, newEvents: 0 });
    expect(r3.events).toHaveLength(2);
  });

  it("reads .jsonl.zst when Node has zstd, and skips it (counted) when it doesn't", async () => {
    fx = makeFixture();
    const now = Date.now();
    const t0 = now - HOUR;
    const body = [
      ...codexMeta(t0, "cx-z", path.join(fx.home, "w"), "gpt-5.5"),
      codexTokens(t0 + 1000, 100, 80, 0, 20),
    ]
      .map((l) => `${l}\n`)
      .join("");
    const z = zlib as unknown as { zstdCompressSync?: (b: Buffer) => Buffer };
    const file = path.join(fx.home, ".codex", "sessions", "rollout-z.jsonl.zst");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (!z.zstdCompressSync || !detectZstd()) {
      // This Node can't make or read zstd: only the skip path can be exercised.
      fs.writeFileSync(file, "not really zstd");
    } else {
      fs.writeFileSync(file, z.zstdCompressSync(Buffer.from(body)));
    }

    const skipped = await collectAiUsage({ env: fx.env, now, zstd: null });
    expect(skipped.scan).toMatchObject({ files: 1, zstdSkipped: 1, filesRead: 0 });
    expect(skipped.events).toHaveLength(0);

    if (z.zstdCompressSync && detectZstd()) {
      // Not recorded in the cursor while skipped, so a Node with zstd reads it next time.
      const read = await collectAiUsage({ env: fx.env, now });
      expect(read.scan).toMatchObject({ zstdSkipped: 0, filesRead: 1, newEvents: 1 });
      expect(read.events[0]).toMatchObject({
        model: "gpt-5.5",
        sessionId: "cx-z",
        outputTokens: 20,
      });
    }
  });

  it("streams a 200k-line transcript in bounded memory", async () => {
    const { cwd, projects } = claudeSetup();
    const now = Date.now();
    const t0 = now - 24 * HOUR;
    const file = path.join(projects, "big.jsonl");
    fs.mkdirSync(projects, { recursive: true });
    const fd = fs.openSync(file, "w");
    const LINES = 200_000;
    const pad = "x".repeat(400);
    let batch: string[] = [];
    for (let i = 0; i < LINES; i++) {
      batch.push(
        i % 10 === 0
          ? // each response is logged three times (one line per content block)
            ccLine({
              id: `R${Math.floor(i / 30)}`,
              at: t0 + i * 100,
              session: "big",
              cwd,
              output: 10,
            })
          : JSON.stringify({
              type: "user",
              message: { content: `${SENTINEL} ${pad}` },
              sessionId: "big",
            }),
      );
      if (batch.length === 10_000) {
        fs.writeSync(fd, `${batch.join("\n")}\n`);
        batch = [];
      }
    }
    // One line far over the 64 KB cap.
    fs.writeSync(
      fd,
      `${JSON.stringify({ type: "user", message: { content: "y".repeat(200_000) } })}\n`,
    );
    fs.closeSync(fd);
    const fileBytes = fs.statSync(file).size;

    const heapBefore = process.memoryUsage().heapUsed;
    const r = await collectAiUsage({ env: fx.env, now, readOnly: true });
    const heapGrowth = process.memoryUsage().heapUsed - heapBefore;

    expect(r.scan.linesRead).toBe(LINES + 1);
    expect(r.scan.oversizeLines).toBe(1);
    expect(r.events).toHaveLength(Math.ceil(LINES / 30));
    // The reader never holds more than one capped line…
    expect(r.scan.peakBufferedBytes).toBeLessThanOrEqual(AI_LINE_CAP_BYTES);
    // …and the heap does not grow with the file (it is ~90 MB; reading it whole would be ≥ 2×).
    expect(heapGrowth).toBeLessThan(fileBytes / 2);
  });
});

describe("repoResolver", () => {
  it("maps a cwd to the nearest repo root (home-relative), never the home itself", () => {
    const { repo, cwd } = claudeSetup();
    const resolve = repoResolver(fx.env);
    expect(resolve(cwd)).toBe("~/code/app");
    expect(resolve(repo)).toBe("~/code/app");
    expect(resolve(fx.home)).toBeNull();
    fs.mkdirSync(path.join(fx.home, "scratch"), { recursive: true });
    expect(resolve(path.join(fx.home, "scratch"))).toBeNull();
    expect(resolve(null)).toBeNull();
    // A git worktree's `.git` FILE counts too.
    const wt = path.join(fx.home, "wt");
    fs.mkdirSync(wt, { recursive: true });
    fs.writeFileSync(path.join(wt, ".git"), "gitdir: ../code/app/.git/worktrees/wt\n");
    expect(resolve(path.join(wt))).toBe("~/wt");
  });

  it("prefers roots a discovery walk already found", () => {
    const { cwd } = claudeSetup();
    const known = path.join(fx.home, "code");
    expect(repoResolver(fx.env, [known])(cwd)).toBe("~/code");
  });
});
