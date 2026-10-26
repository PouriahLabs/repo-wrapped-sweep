import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../src/cli";
import { saveDevice } from "../src/device";
import { scheduledArgs } from "../src/schedule";
import { shareRefusal } from "../src/wrapped";
import type { FetchLike } from "../src/upload";
import { SENTINEL, ccLine, writeLines } from "./ai-fixture";
import { captureIO, makeFixture, type Fixture } from "./helpers";
import { gitIn, put } from "./insights-fixture";

let fx: Fixture;
afterEach(() => fx?.cleanup());

const HOUR = 3_600_000;

type Seen = { url: string; headers: Record<string, string>; body: Record<string, any> };

function server(
  reply: { status: number; json: unknown } = {
    status: 200,
    json: {
      ok: true,
      data: {
        shared: true,
        url: "https://x.test/dev/me",
        manageUrl: "https://x.test/workspace/endpoints?tab=machine",
      },
    },
  },
) {
  const seen: Seen[] = [];
  const fetchImpl = (async (url: string, init: Parameters<FetchLike>[1]) => {
    seen.push({ url, headers: init.headers, body: JSON.parse(init.body) });
    return { status: reply.status, json: async () => reply.json };
  }) as FetchLike;
  return { fetch: fetchImpl, seen };
}

function enrol(f: Fixture, orgLogin: string | null = null) {
  saveDevice(f.env, {
    apiBase: "https://x.test",
    deviceId: "dev-1",
    deviceToken: "rwd_" + "z".repeat(43),
    saltHex: "ab".repeat(32),
    orgLogin,
    sharePaths: true, // even a device that shares paths must not put a name on the card
    enrolledAt: "2026-06-01T00:00:00.000Z",
  });
}

/** A home with a repo (named with the SENTINEL) holding a commit this year, and Claude turns in it. */
function home(f: Fixture) {
  f.env.processEnv = { PATH: process.env.PATH ?? "" };
  const now = Date.now();
  const yearStart = new Date(new Date(now).getFullYear(), 0, 1).getTime();
  const at = Math.max(now - 2 * HOUR, yearStart + HOUR);
  const repo = path.join(f.home, "code", `${SENTINEL}-client`);
  put(path.join(repo, "src", "index.ts"), "export const a = 1;\n");
  gitIn(f, repo, ["init", "-q", "-b", "main"]);
  gitIn(f, repo, ["config", "commit.gpgsign", "false"]);
  gitIn(f, repo, ["config", "user.email", "fixture@example.invalid"]);
  gitIn(f, repo, ["add", "-A"]);
  gitIn(f, repo, ["commit", "-q", "-m", `${SENTINEL} message`], at);
  const cwd = path.join(repo, "src");
  writeLines(path.join(f.home, ".claude", "projects", "-code-x", "s1.jsonl"), [
    ccLine({ id: "A", at, session: "s1", cwd, input: 1000, output: 2000 }),
  ]);
}

async function run(args: string[], srv: ReturnType<typeof server>) {
  const io = captureIO();
  io.fetch = srv.fetch;
  io.sleep = async () => {};
  const code = await main(["wrapped", ...args], io, fx.env, fx.root);
  return { code, out: io.out(), err: io.err() };
}

describe("wrapped --share", () => {
  it("publishes aggregates only — no repo name, path, email or message text — to the share route", async () => {
    fx = makeFixture();
    home(fx);
    enrol(fx);
    const srv = server();
    const r = await run(["--out", path.join(fx.root, "w.html"), "--share"], srv);
    expect(r.code).toBe(0);
    expect(srv.seen).toHaveLength(1);
    const call = srv.seen[0]!;
    expect(call.url).toBe("https://x.test/api/endpoint/wrapped-share");
    expect(call.headers.authorization).toBe("Bearer rwd_" + "z".repeat(43));

    const wire = JSON.stringify(call.body);
    expect(wire).not.toContain(SENTINEL);
    expect(wire).not.toContain(fx.home.replace(/\\/g, "/"));
    expect(wire).not.toContain("example.invalid");
    // exactly the allow-listed card (the server's strict schema, tested at the monorepo root,
    // rejects anything else)
    expect(call.body.schemaVersion).toBe(1);
    expect(Object.keys(call.body).sort()).toEqual(["card", "schemaVersion", "year"]);
    expect(Object.keys(call.body.card).sort()).toEqual(
      [
        "activeDays",
        "ai",
        "aiShare",
        "busiestHour",
        "busiestWeekday",
        "commitActiveMinutes",
        "commits",
        "diskReclaimedBytes",
        "hourActivity",
        "languages",
        "longestStreakDays",
        "reposTouched",
        "weekdayActivity",
      ].sort(),
    );
    expect(call.body.card.commits).toBe(1);
    expect(call.body.card.ai.sessions).toBe(1);

    expect(r.out).toContain("Shared: https://x.test/dev/me");
    expect(r.out).toContain("Unpublish any time: https://x.test/workspace/endpoints?tab=machine");
    expect(r.err).toContain("aggregates only");
  }, 60_000);

  it("uploads nothing without --share, even from an enrolled device", async () => {
    fx = makeFixture();
    home(fx);
    enrol(fx);
    const srv = server();
    const r = await run(["--out", path.join(fx.root, "w.html")], srv);
    expect(r.code).toBe(0);
    expect(srv.seen).toHaveLength(0);
    expect(fs.existsSync(path.join(fx.root, "w.html"))).toBe(true);
  }, 60_000);

  it("a stored card with no Contributor Wrapped yet is reported, with where to make it", async () => {
    fx = makeFixture();
    home(fx);
    enrol(fx);
    const srv = server({
      status: 200,
      json: {
        ok: true,
        data: { shared: true, url: null, generateUrl: "https://x.test/workspace/wrapped" },
      },
    });
    const r = await run(["--out", path.join(fx.root, "w.html"), "--share"], srv);
    expect(r.code).toBe(0);
    expect(r.out).toContain(
      "once you generate your Contributor Wrapped at https://x.test/workspace/wrapped",
    );
  }, 60_000);

  it("a 402 (not Pro) fails the command with the upgrade link", async () => {
    fx = makeFixture();
    home(fx);
    enrol(fx);
    const srv = server({
      status: 402,
      json: {
        ok: false,
        error: "Sharing is part of Pro.",
        upgradeUrl: "https://x.test/settings/billing",
      },
    });
    const r = await run(["--out", path.join(fx.root, "w.html"), "--share"], srv);
    expect(r.code).toBe(2);
    expect(r.err).toContain("share failed: Sharing is part of Pro.");
    expect(r.err).toContain("Upgrade: https://x.test/settings/billing");
  }, 60_000);

  describe("refusals happen BEFORE any collection or network", () => {
    it("not enrolled", async () => {
      fx = makeFixture();
      const srv = server();
      const r = await run(["--share"], srv);
      expect(r.code).toBe(2);
      expect(r.err).toContain("needs an enrolled device");
      expect(srv.seen).toHaveLength(0);
    });

    it("an organization's device", async () => {
      fx = makeFixture();
      enrol(fx, "acme");
      const srv = server();
      const r = await run(["--share"], srv);
      expect(r.code).toBe(2);
      expect(r.err).toContain("personal devices");
      expect(r.err).toContain("acme");
      expect(srv.seen).toHaveLength(0);
    });

    it("a scheduled run", async () => {
      fx = makeFixture();
      enrol(fx);
      const srv = server();
      const r = await run(["--share", "--scheduled"], srv);
      expect(r.code).toBe(2);
      expect(r.err).toContain("cannot be used in a scheduled run");
      expect(srv.seen).toHaveLength(0);
    });

    it("MDM insights:false", async () => {
      fx = makeFixture();
      enrol(fx);
      const mdm = path.join(fx.root, "mdm.json");
      fs.writeFileSync(mdm, JSON.stringify({ insights: false }));
      fx.env.mdmConfigPath = mdm;
      const srv = server();
      const r = await run(["--share"], srv);
      expect(r.code).toBe(2);
      expect(r.err).toContain("administrator disabled machine insights");
      expect(srv.seen).toHaveLength(0);
    });
  });

  it("shareRefusal is a pure decision (precedence: scheduled, MDM, not enrolled, org)", () => {
    const personal = {
      apiBase: "https://x.test",
      deviceId: "d",
      deviceToken: "t",
      saltHex: "ab".repeat(32),
      orgLogin: null,
      sharePaths: false,
      enrolledAt: "2026-01-01T00:00:00.000Z",
    };
    expect(shareRefusal({ scheduled: false, mdmInsights: undefined, device: personal })).toBeNull();
    expect(shareRefusal({ scheduled: false, mdmInsights: true, device: personal })).toBeNull();
    expect(shareRefusal({ scheduled: true, mdmInsights: undefined, device: personal })).toMatch(
      /scheduled/,
    );
    expect(shareRefusal({ scheduled: false, mdmInsights: false, device: personal })).toMatch(
      /administrator/,
    );
    expect(shareRefusal({ scheduled: false, mdmInsights: undefined, device: null })).toMatch(
      /enrolled/,
    );
    expect(
      shareRefusal({
        scheduled: false,
        mdmInsights: undefined,
        device: { ...personal, orgLogin: "acme" },
      }),
    ).toMatch(/personal devices/);
  });
});

describe("the scheduler's surface", () => {
  it("scheduled arguments can reach no destructive, key-sending or publishing mode", () => {
    for (const upload of [false, true]) {
      const args = scheduledArgs({ upload });
      for (const forbidden of [
        "disk",
        "clean",
        "--yes",
        "-y",
        "--validate",
        "--share",
        "wrapped",
        "fix",
        "--include-venv",
      ]) {
        expect(args).not.toContain(forbidden);
      }
      expect(args).toContain("--scheduled");
      expect(args).toContain("--quiet");
    }
  });
});
