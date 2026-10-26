import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { defaultBaselinePath, loadBaseline, saveBaseline, type Baseline } from "../src/baseline";
import {
  keychainLabel,
  planFix,
  planRemoval,
  resolveFingerprint,
  runFix,
  type FixDeps,
} from "../src/fix";
import type { KeychainAdapter, Prompter, TrashAdapter } from "../src/platform";
import { recoverSecret, scan } from "../src/scan";
import { githubToken, makeFixture, pemKey, scramble, type Fixture } from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

const SALT = new Uint8Array(32).fill(5);
const T0 = "2026-06-01T00:00:00.000Z";

describe("resolveFingerprint", () => {
  const baseline: Baseline = {
    schemaVersion: 1,
    updatedAt: T0,
    findings: {
      ["ab12cd34" + "0".repeat(24)]: {
        ruleId: "jwt",
        copies: 1,
        locations: [],
        firstSeen: T0,
        lastSeen: T0,
      },
      ["ab99cd34" + "0".repeat(24)]: {
        ruleId: "jwt",
        copies: 1,
        locations: [],
        firstSeen: T0,
        lastSeen: T0,
      },
    },
  };
  it("resolves a unique prefix (≥ 6 hex) and rejects ambiguity, junk and no baseline", () => {
    expect(resolveFingerprint("ab12cd", baseline)).toMatchObject({
      ok: true,
      fingerprint: "ab12cd34" + "0".repeat(24),
    });
    expect(resolveFingerprint("AB12CD34", baseline).ok).toBe(true);
    expect(resolveFingerprint("ab", baseline)).toMatchObject({ ok: false });
    expect(resolveFingerprint("zzzzzz", baseline)).toMatchObject({ ok: false });
    expect(resolveFingerprint("ab99cd", baseline)).toMatchObject({ ok: true });
    expect(resolveFingerprint("abcdef", baseline)).toMatchObject({
      ok: false,
      error: expect.stringContaining("no finding"),
    });
    expect(resolveFingerprint("ab", baseline).ok).toBe(false);
    expect(resolveFingerprint("ab12cd", null)).toMatchObject({
      ok: false,
      error: expect.stringContaining("no baseline"),
    });
    const dup: Baseline = {
      ...baseline,
      findings: {
        ...baseline.findings,
        ["ab12cd35" + "0".repeat(24)]: baseline.findings["ab12cd34" + "0".repeat(24)]!,
      },
    };
    expect(resolveFingerprint("ab12cd", dup)).toMatchObject({
      ok: false,
      error: expect.stringContaining("matches 2"),
    });
  });
});

describe("planRemoval — only pure secret holders are ever trashed", () => {
  it("trashes key/env/cookie files, editor-history copies and backups", () => {
    expect(planRemoval("/h/docs/server.pem", "documents").action).toBe("trash");
    expect(planRemoval("/h/app/.env", "documents").action).toBe("trash");
    expect(planRemoval("/h/dl/cookies.txt", "downloads-desktop").action).toBe("trash");
    expect(planRemoval("/h/gcp/my-service-account.json", "documents").action).toBe("trash");
    expect(planRemoval("/h/.config/Code/User/History/ab/x.ts", "editor-history").action).toBe(
      "trash",
    );
    expect(planRemoval("/h/old_backup/notes.txt", "documents").action).toBe("trash");
  });
  it("NEVER trashes a source file with an inline secret, a transcript, a history or an expected store", () => {
    expect(planRemoval("/h/code/config.ts", "documents").action).toBe("manual");
    expect(planRemoval("/h/.claude/projects/p/s.jsonl", "agent-transcript").action).toBe("manual");
    expect(planRemoval("/h/.zsh_history", "shell-history").action).toBe("manual");
    expect(planRemoval("/h/.aws/credentials", "credential-store").action).toBe("manual");
    expect(planRemoval("/h/.npmrc", "credential-store").action).toBe("manual");
    expect(planRemoval("/h/.ssh/id_ed25519", "ssh").action).toBe("manual");
  });
  it("explains why a copy is left to the user", () => {
    expect(planRemoval("/h/code/config.ts", "documents").reason).toMatch(/inline/);
  });
  it("keychainLabel is safe and tied to the finding", () => {
    expect(keychainLabel("github-personal-access-token", "ab12cd34ef")).toBe(
      "github-personal-access-token-ab12cd34",
    );
    expect(keychainLabel("path.env file", "ab12cd34ef")).toBe("path.env-file-ab12cd34");
  });
});

// ---------------------------------------------------------------------------
// The flow, against real files in a temp home, with mocked trash / keychain / prompts
// ---------------------------------------------------------------------------

interface Harness {
  deps: FixDeps;
  out: () => string;
  err: () => string;
  trashed: string[];
  stored: { label: string; secret: string }[];
  asked: string[];
}

function harness(
  opts: {
    answers?: (q: string) => boolean;
    yes?: boolean;
    trashFails?: string[];
    keychainOk?: boolean;
  } = {},
): Harness {
  let out = "";
  let err = "";
  const trashed: string[] = [];
  const stored: { label: string; secret: string }[] = [];
  const asked: string[] = [];
  const prompt: Prompter = {
    async confirm(q) {
      asked.push(q);
      return (opts.answers ?? (() => true))(q);
    },
  };
  const trash: TrashAdapter = {
    destination: "the Test Trash",
    async trash(file) {
      if (opts.trashFails?.includes(file)) return { ok: false, message: "locked" };
      trashed.push(file);
      fs.rmSync(file); // the REAL move is the adapter's job; here the file just leaves
      return { ok: true };
    },
  };
  const keychain: KeychainAdapter = {
    name: "Test Keychain",
    async store(label, secret) {
      stored.push({ label, secret });
      return opts.keychainOk === false ? { ok: false, message: "denied" } : { ok: true };
    },
  };
  const deps: FixDeps = {
    env: fx.env,
    io: {
      stdout: { write: (s) => ((out += s), true) },
      stderr: { write: (s) => ((err += s), true) },
    },
    baselinePath: defaultBaselinePath(fx.env),
    prompt,
    trash,
    keychain,
    yes: opts.yes === true,
    now: () => new Date("2026-06-02T00:00:00.000Z"),
    recover: (abs, cls, fingerprint) => recoverSecret(abs, cls, fingerprint, SALT),
    rescan: (paths) =>
      scan({
        env: fx.env,
        roots: paths,
        quick: false,
        excludeGlobs: [],
        includeCloud: true,
        concurrency: 2,
        salt: SALT,
      }),
  };
  return { deps, out: () => out, err: () => err, trashed, stored, asked };
}

/** Sweep the fixture and persist the baseline, like a real run would. */
async function sweepToBaseline(): Promise<{ fingerprint: string; ruleId: string }> {
  const { updateBaseline } = await import("../src/baseline");
  const result = await scan({
    env: fx.env,
    roots: [fx.home],
    quick: false,
    excludeGlobs: [],
    includeCloud: false,
    concurrency: 2,
    salt: SALT,
  });
  saveBaseline(defaultBaselinePath(fx.env), updateBaseline(result.groups, null, "full", T0));
  const g = result.groups[0]!;
  return { fingerprint: g.fingerprint, ruleId: g.ruleId };
}

describe("runFix — happy path", () => {
  it("stores, trashes the copies, prints the rotation link, re-sweeps and marks resolved", async () => {
    fx = makeFixture();
    const key = pemKey(3);
    fx.write("keys/server.pem", key);
    fx.write("keys/old_backup/server.pem", key);
    fx.write(".config/Code/User/History/aa/bb.pem", key);
    const { fingerprint } = await sweepToBaseline();
    const h = harness();

    const code = await runFix(fingerprint.slice(0, 10), h.deps);
    expect(code).toBe(0);
    expect(h.trashed).toHaveLength(3);
    for (const f of h.trashed) expect(fs.existsSync(f)).toBe(false);
    expect(h.stored).toHaveLength(1);
    expect(h.stored[0]!.label).toMatch(/^path.private-key-[0-9a-f]{8}$/);
    expect(h.stored[0]!.secret).toContain("PRIVATE KEY"); // the key block was read back locally

    const out = h.out();
    expect(out).toContain("Test Keychain");
    expect(out).toContain("op item create");
    expect(out).toContain("https://"); // rotation link
    expect(out).toContain("never calls a provider");
    expect(out).toContain("marked resolved");

    const baseline = loadBaseline(defaultBaselinePath(fx.env))!;
    expect(baseline.findings[fingerprint]!.resolvedAt).toBe("2026-06-02T00:00:00.000Z");
    expect(baseline.findings[fingerprint]!.locations).toEqual([]);
  });

  it("asks ONE batch question for editor-history copies and one per other file", async () => {
    fx = makeFixture();
    const tok = githubToken(2);
    fx.write("a/.env", `API_TOKEN=${tok}\n`);
    fx.write("b/.env.bak", `API_TOKEN=${tok}\n`);
    for (let i = 0; i < 4; i++)
      fx.write(`.config/Code/User/History/h${i}/x.env`, `API_TOKEN=${tok}\n`);
    const { fingerprint } = await sweepToBaseline();
    const h = harness();
    await runFix(fingerprint, h.deps);
    const moveQs = h.asked.filter((q) => /Move/.test(q));
    expect(moveQs.filter((q) => /editor-history/.test(q))).toHaveLength(1);
    expect(moveQs.filter((q) => /\.env/.test(q))).toHaveLength(2);
    expect(h.trashed).toHaveLength(6);
  });
});

describe("runFix — safety", () => {
  it("--yes skips the Trash confirms but STILL asks about the keychain", async () => {
    fx = makeFixture();
    const tok = githubToken(4);
    fx.write("a/.env", `API_TOKEN=${tok}\n`);
    fx.write("b/.env.bak", `API_TOKEN=${tok}\n`);
    const { fingerprint } = await sweepToBaseline();
    const h = harness({ yes: true, answers: () => false }); // user declines everything asked
    const code = await runFix(fingerprint, h.deps);
    expect(code).toBe(0);
    expect(h.asked).toHaveLength(1);
    expect(h.asked[0]).toMatch(/Store this secret in Test Keychain/);
    expect(h.stored).toHaveLength(0); // declined
    expect(h.trashed).toHaveLength(2); // --yes covered the moves
  });

  it("with every answer NO (or no TTY) nothing is moved or stored, and nothing is marked resolved", async () => {
    fx = makeFixture();
    fx.write("a/.env", `API_TOKEN=${githubToken(5)}\n`);
    const { fingerprint } = await sweepToBaseline();
    const h = harness({ answers: () => false });
    const code = await runFix(fingerprint, h.deps);
    expect(code).toBe(1);
    expect(h.trashed).toHaveLength(0);
    expect(h.stored).toHaveLength(0);
    expect(fs.existsSync(path.join(fx.home, "a", ".env"))).toBe(true);
    const e = loadBaseline(defaultBaselinePath(fx.env))!.findings[fingerprint]!;
    expect(e.resolvedAt).toBeUndefined();
    expect(e.copies).toBe(1);
  });

  it("never prints the secret, in any output stream", async () => {
    fx = makeFixture();
    const tok = githubToken(6);
    fx.write("a/.env", `API_TOKEN=${tok}\n`);
    const { fingerprint } = await sweepToBaseline();
    const h = harness();
    await runFix(fingerprint, h.deps);
    const all = h.out() + h.err();
    expect(all.includes(tok)).toBe(false);
    expect(all.includes(tok.slice(4, -4))).toBe(false);
    expect(h.stored[0]!.secret).toBe(tok);
  });

  it("leaves a source file with the secret inline for the user, and exits 1", async () => {
    fx = makeFixture();
    const tok = githubToken(7);
    fx.write("code/config.ts", `export const t = "${tok}";\nexport const other = 1;\n`);
    fx.write("a/.env", `API_TOKEN=${tok}\n`);
    const { fingerprint } = await sweepToBaseline();
    const h = harness();
    const code = await runFix(fingerprint, h.deps);
    expect(code).toBe(1);
    expect(fs.existsSync(path.join(fx.home, "code", "config.ts"))).toBe(true);
    expect(h.trashed.map((p) => path.basename(p))).toEqual([".env"]);
    expect(h.out()).toContain("Needs your hands");
    expect(h.out()).toContain("code/config.ts");
    expect(h.out()).toContain("still contain it");
    const e = loadBaseline(defaultBaselinePath(fx.env))!.findings[fingerprint]!;
    expect(e.resolvedAt).toBeUndefined();
    expect(e.locations).toEqual(["~/code/config.ts"]);
  });

  it("reports a trash failure and keeps the finding open", async () => {
    fx = makeFixture();
    const f = fx.write("a/.env", `API_TOKEN=${githubToken(8)}\n`);
    const { fingerprint } = await sweepToBaseline();
    const h = harness({ trashFails: [f] });
    // The adapter fails, so the file stays and the re-sweep still finds it.
    const code = await runFix(fingerprint, h.deps);
    expect(h.out()).toContain("locked");
    expect(code).toBe(1);
    expect(fs.existsSync(f)).toBe(true);
  });

  it("a keychain refusal is reported but does not abort the cleanup", async () => {
    fx = makeFixture();
    fx.write("a/.env", `API_TOKEN=${githubToken(9)}\n`);
    const { fingerprint } = await sweepToBaseline();
    const h = harness({ keychainOk: false });
    const code = await runFix(fingerprint, h.deps);
    expect(h.out()).toContain("not stored: denied");
    expect(code).toBe(0);
  });

  it("says so when the secret can no longer be read back for the keychain", async () => {
    fx = makeFixture();
    const f = fx.write("a/.env", `API_TOKEN=${githubToken(1)}\n`);
    const { fingerprint } = await sweepToBaseline();
    fs.writeFileSync(f, "nothing here anymore\n"); // edited since the sweep
    const h = harness();
    await runFix(fingerprint, h.deps);
    expect(h.out()).toMatch(/could not read it back/);
    expect(h.stored).toHaveLength(0);
  });
});

describe("runFix — bad input", () => {
  it("exits 2 for an unknown fingerprint, a missing baseline or junk", async () => {
    fx = makeFixture();
    const h = harness();
    expect(await runFix("abcdef", h.deps)).toBe(2);
    expect(h.err()).toContain("no baseline");
    fx.write("a/.env", `API_TOKEN=${githubToken()}\n`);
    await sweepToBaseline();
    const h2 = harness();
    expect(await runFix("ffffff", h2.deps)).toBe(2);
    expect(await runFix("not-hex", h2.deps)).toBe(2);
  });

  it("an already-resolved finding is a no-op", async () => {
    fx = makeFixture();
    fx.write("a/.env", `API_TOKEN=${githubToken()}\n`);
    const { fingerprint } = await sweepToBaseline();
    const b = loadBaseline(defaultBaselinePath(fx.env))!;
    b.findings[fingerprint]!.resolvedAt = T0;
    saveBaseline(defaultBaselinePath(fx.env), b);
    const h = harness();
    expect(await runFix(fingerprint, h.deps)).toBe(0);
    expect(h.out()).toContain("already marked resolved");
    expect(h.asked).toHaveLength(0);
  });
});

describe("planFix + recoverSecret", () => {
  it("plans every baseline location with an action and recovers the secret locally", async () => {
    fx = makeFixture();
    const tok = githubToken(3);
    const f = fx.write("a/.env", `X=1\nAPI_TOKEN=${tok}\n`);
    const { fingerprint } = await sweepToBaseline();
    const entry = loadBaseline(defaultBaselinePath(fx.env))!.findings[fingerprint]!;
    const items = planFix(entry, fx.env);
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      path: "~/a/.env",
      action: "trash",
      locationClass: "documents",
    });
    expect(await recoverSecret(f, "documents", fingerprint, SALT)).toBe(tok);
    expect(await recoverSecret(f, "documents", "0".repeat(32), SALT)).toBeNull();
    expect(
      await recoverSecret(path.join(fx.home, "missing"), "documents", fingerprint, SALT),
    ).toBeNull();
    expect(scramble(1)).toBeTruthy();
  });

  it("recovers a secret from a jsonl transcript line", async () => {
    fx = makeFixture();
    const tok = githubToken(5);
    const f = fx.write(".claude/projects/p/s.jsonl", `{"a":1}\n{"text":"export T=${tok}"}\n`);
    const { fingerprint } = await sweepToBaseline();
    expect(await recoverSecret(f, "agent-transcript", fingerprint, SALT)).toBe(tok);
  });
});
