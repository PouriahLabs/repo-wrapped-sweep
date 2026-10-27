import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { repoRefId } from "@/lib/endpoint/insights/repo-ref";
import type { UsageRow } from "@/lib/endpoint/insights/ai-usage";
import {
  MAX_AI_ROWS,
  MAX_BACKUP_TOP,
  MAX_DRIFT_ROWS,
  MAX_GIT_TOP,
} from "@/lib/endpoint/insights/wire";
import { main } from "../src/cli";
import { saveDevice } from "../src/device";
import type { FetchLike } from "../src/upload";
import {
  UPLOAD_CURSOR_FILE,
  buildInsightsBlock,
  loadUploadCursor,
  machineInfo,
  makeRepoRef,
  pickRemoteUrl,
  referencedFolders,
  saveUploadCursor,
  selectAiDays,
  type BlockInput,
} from "../src/insights/upload";
import type { GitCollection, RepoReport } from "../src/insights/git";
import type { ToolchainCollection } from "../src/insights/toolchain";
import type { BackupCollection, BackupProject } from "../src/insights/backup";
import { SENTINEL, ccLine, writeLines } from "./ai-fixture";
import { captureIO, makeFixture, type Fixture } from "./helpers";
import { gitIn, initRepo, put } from "./insights-fixture";

let fx: Fixture | undefined;
let fx2: Fixture | undefined;
afterEach(() => {
  fx?.cleanup();
  fx2?.cleanup();
  fx = fx2 = undefined;
});

const ORG_SALT = Buffer.from("ab".repeat(32), "hex");
const OTHER_SALT = Buffer.from("cd".repeat(32), "hex");
const DAY = 86_400_000;
const NOW = Date.parse("2026-10-26T12:00:00Z");
const env = (home: string) => ({ home, platform: "linux" as NodeJS.Platform });

describe("pickRemoteUrl", () => {
  it("prefers origin, else the first remote, else null", () => {
    expect(
      pickRemoteUrl(
        "remote.upstream.url https://github.com/up/app\nremote.origin.url git@github.com:me/app.git\n",
      ),
    ).toBe("git@github.com:me/app.git");
    expect(pickRemoteUrl("remote.fork.url https://x.test/a/b\r\n")).toBe("https://x.test/a/b");
    expect(pickRemoteUrl("")).toBeNull();
  });
});

describe("RepoRef ids — the org-salt fold", () => {
  it("two org devices' clones of one remote (ssh vs https, different folders) get ONE id", () => {
    const a = makeRepoRef("/home/ana/code/app", {
      env: env("/home/ana"),
      salt: ORG_SALT,
      sharePaths: false,
      remotes: new Map([["/home/ana/code/app", "git@github.com:Acme/App.git"]]),
    });
    const b = makeRepoRef("/Users/bo/work/acme-app", {
      env: env("/Users/bo"),
      salt: ORG_SALT,
      sharePaths: false,
      remotes: new Map([["/Users/bo/work/acme-app", "https://github.com/acme/app"]]),
    });
    expect(a.id).toMatch(/^[0-9a-f]{16}$/);
    expect(a.id).toBe(b.id);
    expect(a).toEqual({ id: a.id }); // no name without sharePaths
  });

  it("shareRepoNames names a repo owner/repo (wins over a path), with the same id", () => {
    const ctx = {
      env: env("/home/ana"),
      salt: ORG_SALT,
      sharePaths: true,
      remotes: new Map([["/home/ana/code/app", "git@github.com:Acme/App.git"]]),
    };
    const plain = makeRepoRef("/home/ana/code/app", ctx);
    const named = makeRepoRef("/home/ana/code/app", { ...ctx, shareRepoNames: true });
    expect(plain.name).toBe("~/code/app");
    expect(named).toEqual({ id: plain.id, name: "acme/app" });
  });

  it("a different (personal) salt gives a different id for the same repo", () => {
    const remotes = new Map([["/h/code/app", "https://github.com/acme/app"]]);
    const org = makeRepoRef("/h/code/app", {
      env: env("/h"),
      salt: ORG_SALT,
      sharePaths: false,
      remotes,
    });
    const mine = makeRepoRef("/h/code/app", {
      env: env("/h"),
      salt: OTHER_SALT,
      sharePaths: false,
      remotes,
    });
    expect(org.id).not.toBe(mine.id);
  });

  it("no remote → the home-relative path is the identity; the name only with sharePaths", () => {
    const ctx = { env: env("/h"), salt: ORG_SALT, remotes: new Map<string, string | null>() };
    const r = makeRepoRef("/h/code/local", { ...ctx, sharePaths: true });
    expect(r).toEqual({
      id: repoRefId(ORG_SALT, { remoteUrl: null, homeRelativePath: "code/local" }),
      name: "~/code/local",
    });
    // Outside the home: never a name (it would be an absolute path).
    expect(makeRepoRef("/srv/x", { ...ctx, sharePaths: true }).name).toBeUndefined();
  });
});

describe("selectAiDays", () => {
  const rows = (days: Record<string, number>) =>
    Object.entries(days).flatMap(([day, n]) =>
      Array.from({ length: n }, (_, i) => ({ day, model: `m${i}` })),
    );

  it("sends only days on/after the cursor; a complete send moves the cursor to yesterday", () => {
    const r = selectAiDays(
      rows({ "2026-10-20": 2, "2026-10-25": 1, "2026-10-26": 1 }),
      "2026-10-25",
      NOW,
    );
    expect(r.rows.map((x) => x.day)).toEqual(["2026-10-25", "2026-10-26"]);
    expect(r.nextCursor).toBe("2026-10-25");
  });

  it("no cursor = backfill everything; over the cap it pages by whole days", () => {
    const r = selectAiDays(
      rows({ "2026-01-01": 3, "2026-01-02": 3, "2026-01-03": 3 }),
      null,
      NOW,
      7,
    );
    expect(r.rows.map((x) => x.day)).toEqual([
      "2026-01-01",
      "2026-01-01",
      "2026-01-01",
      "2026-01-02",
      "2026-01-02",
      "2026-01-02",
    ]);
    expect(r.nextCursor).toBe("2026-01-03");
  });

  it("a single day over the cap still advances the cursor", () => {
    const r = selectAiDays(rows({ "2026-01-01": 9, "2026-01-02": 1 }), null, NOW, 4);
    expect(r.rows).toHaveLength(4);
    expect(r.nextCursor).toBe("2026-01-02");
  });
});

describe("upload cursor file", () => {
  it("round-trips per device and ignores another enrolment's cursor", () => {
    fx = makeFixture();
    expect(loadUploadCursor(fx.env, "dev-1")).toBeNull();
    saveUploadCursor(fx.env, "dev-1", "2026-10-25");
    expect(loadUploadCursor(fx.env, "dev-1")).toBe("2026-10-25");
    expect(loadUploadCursor(fx.env, "dev-2")).toBeNull();
    fs.writeFileSync(path.join(fx.env.configDir, UPLOAD_CURSOR_FILE), "{bad");
    expect(loadUploadCursor(fx.env, "dev-1")).toBeNull();
  });
});

describe("machineInfo", () => {
  it("reads os facts and the home volume; an unreadable volume is 0 GB", () => {
    const probe = {
      release: () => "10.0.26100",
      arch: () => "x64",
      cpus: () => 16,
      totalmem: () => 32 * 2 ** 30,
      disk: () => ({ total: 1e12, free: 2.5e11 }),
    };
    expect(machineInfo({ home: "/h" }, probe)).toEqual({
      osVersion: "10.0.26100",
      arch: "x64",
      cpuCount: 16,
      memGb: 32,
      diskTotalGb: 1000,
      diskFreeGb: 250,
    });
    expect(machineInfo({ home: "/h" }, { ...probe, disk: () => null })).toMatchObject({
      diskTotalGb: 0,
      diskFreeGb: 0,
    });
  });
});

describe("buildInsightsBlock", () => {
  const machine = {
    osVersion: "6.8",
    arch: "arm64",
    cpuCount: 8,
    memGb: 16,
    diskTotalGb: 500,
    diskFreeGb: 50,
  };
  const ref = (abs: string) => ({ id: abs.length.toString(16).padStart(16, "0") });

  function repo(i: number, states: RepoReport["states"]): RepoReport {
    return {
      path: `/h/r${i}`,
      states,
      risk: 100 - i,
      state: {
        branch: "main",
        upstream: null,
        ahead: 0,
        behind: 0,
        staged: 0,
        modified: 2,
        untracked: 1,
        conflicted: 0,
        changed: 3,
        stashTimes: [1],
        unpushedBranches: [],
        unpushedCommits: 4,
        hasRemote: true,
        lastCommitAt: 1,
        dirtySince: null,
      },
    };
  }

  it("applies every § C3 cap and keeps clean repos out of the top list", () => {
    const git: GitCollection = {
      repos: [
        ...Array.from({ length: 30 }, (_, i) => repo(i, ["uncommitted", "unpushed"])),
        repo(99, ["clean"]),
      ],
      summary: {
        repos: 31,
        byState: { uncommitted: 30, unpushed: 30, clean: 1 },
        localOnlyRepos: 30,
        unpushedCommits: 120,
        stashes: 30,
        staleStashes: 0,
      },
      unknown: 0,
      gitMissing: false,
    };
    const toolchain: ToolchainCollection = {
      tools: [
        { tool: "node", version: "20.11.0", status: "present" },
        { tool: "go", version: null, status: "absent" },
        { tool: "python", version: "3.12", status: "timeout" },
      ],
      managers: ["fnm"],
      repos: Array.from({ length: 30 }, (_, i) => ({
        path: `/h/p${i}`,
        pins: [],
        drift: [
          {
            tool: "node" as const,
            source: ".nvmrc",
            wanted: "22",
            installed: "20.11.0",
            reason: "mismatch" as const,
          },
          {
            tool: "pnpm" as const,
            source: "packageManager",
            wanted: "9",
            installed: null,
            reason: "missing" as const,
          },
        ],
      })),
    };
    const projects: BackupProject[] = Array.from({ length: 25 }, (_, i) => ({
      path: `/h/b${i}`,
      state: i < 24 ? ("local-only" as const) : ("pushed" as const),
      reason: "no-git" as BackupProject["reason"],
      atRisk: undefined as unknown as BackupProject["atRisk"],
      bytes: i === 0 ? null : 1000,
      partial: false,
      lastTouched: i === 0 ? null : NOW,
    }));
    const backup: BackupCollection = {
      projects,
      summary: {
        projects: 25,
        byState: { "local-only": 24, pushed: 1 },
        localOnlyBytes: 23_000,
        localOnlyNewestTouched: NOW,
      },
    };
    const aiRow = (i: number): UsageRow => ({
      day: "2026-10-26",
      repo: i % 2 ? `/h/r${i}` : null,
      tool: "claude-code",
      model: "claude-opus-5-5",
      sessions: 1,
      turns: 2,
      activeMinutes: 3,
      inputTokens: 10,
      outputTokens: 20,
      cacheWriteTokens: 0,
      cacheReadTokens: 5,
      costUsd: 0.01,
    });
    const input: BlockInput = {
      collectedAt: new Date(NOW).toISOString(),
      machine,
      git,
      toolchain,
      backup,
      disk: {
        folders: [],
        reportOnly: [],
        packageCaches: [],
        dockerBytes: null,
        totals: {
          reclaimableBytes: 3.2e9,
          staleReclaimableBytes: 1e9,
          staleProjects: 1,
          projects: 2,
          byClass: { "node-modules": 3.2e9, "rust-target": 0 },
        },
        partial: false,
        staleDays: 30,
      },
      ai: { rows: Array.from({ length: 450 }, (_, i) => aiRow(i)), pricesAsOf: "2026-10-26" },
      ref,
    };
    const b = buildInsightsBlock(input);
    expect(b.git!.top).toHaveLength(MAX_GIT_TOP);
    expect(b.git!.top!.every((t) => !t.states.includes("clean"))).toBe(true);
    expect(b.git!.top![0]).toEqual({
      repo: ref("/h/r0"),
      states: ["uncommitted", "unpushed"],
      ahead: 4,
      uncommitted: 3,
      stashes: 1,
    });
    expect(b.toolchain!.drift).toHaveLength(MAX_DRIFT_ROWS);
    // Unknown (timed out) and absent tools are both null; present ones carry the version.
    expect(b.toolchain!.tools).toEqual({ node: "20.11.0", go: null, python: null });
    expect(b.ai!.days).toHaveLength(MAX_AI_ROWS);
    expect(b.ai!.days[0]!.repo).toBeNull();
    expect(b.ai!.days[1]!.repo).toEqual(ref("/h/r1"));
    expect(b.backup!.top).toHaveLength(MAX_BACKUP_TOP);
    expect(b.backup!.top![0]).toMatchObject({ bytes: 0, lastTouched: null, state: "local-only" });
    expect(b.disk).toEqual({
      reclaimableGb: 3.2,
      staleReclaimableGb: 1,
      byClass: { "node-modules": 3.2 },
    });
    // Only folders the block references get a remote lookup.
    const folders = referencedFolders(input);
    expect(folders).toContain("/h/r1");
    expect(folders).not.toContain("/h/p0".replace("p0", "zzz"));
  });
});

// ---------------------------------------------------------------------------
// End to end through main()
// ---------------------------------------------------------------------------

function server() {
  const seen: Record<string, unknown>[] = [];
  const fetchImpl = (async (_url: string, init: Parameters<FetchLike>[1]) => {
    seen.push(JSON.parse(init.body) as Record<string, unknown>);
    return { status: 202, json: async () => ({ ok: true, data: { accepted: true } }) };
  }) as FetchLike;
  return { fetch: fetchImpl, seen };
}

function enrol(f: Fixture, sharePaths = false) {
  saveDevice(f.env, {
    apiBase: "https://x.test",
    deviceId: "dev-1",
    deviceToken: "rwd_" + "z".repeat(43),
    saltHex: "ab".repeat(32),
    orgLogin: "acme",
    sharePaths,
    enrolledAt: "2026-06-01T00:00:00.000Z",
  });
}

async function run(f: Fixture, args: string[], srv: ReturnType<typeof server>) {
  const io = captureIO();
  io.fetch = srv.fetch;
  io.sleep = async () => {};
  const code = await main(args, io, f.env, f.root);
  return { code, out: io.out(), err: io.err() };
}

/** A home with one repo whose origin is GitHub, a dirty file, and Claude turns inside it. */
function home(f: Fixture, now: number, folder = "client-acme") {
  f.env.processEnv = { PATH: "" }; // no real toolchain probes
  const repo = path.join(f.home, "code", folder);
  put(path.join(repo, "package.json"), "{}\n");
  initRepo(f, repo, now - 2 * DAY);
  gitIn(f, repo, ["remote", "add", "origin", "git@github.com:Acme/App.git"]);
  put(path.join(repo, "dirty.txt"), "x\n");
  const cwd = path.join(repo, "src");
  writeLines(path.join(f.home, ".claude", "projects", "-code-app", "s1.jsonl"), [
    ccLine({ id: "old", at: now - 3 * DAY, session: "s1", cwd }),
    ccLine({ id: "new", at: now - 60_000, session: "s1", cwd }),
  ]);
  return repo;
}

describe("--upload sends schema v2 with insights", () => {
  it("scheduled full sweep: machine, git, disk, toolchain, backup and AI — ids by remote, no names", async () => {
    fx = makeFixture();
    const now = Date.now();
    home(fx, now);
    enrol(fx, false);
    const srv = server();
    // exactly what the installed schedule runs (schedule.ts scheduledArgs)
    const r = await run(fx, ["--quiet", "--scheduled", "--upload", "--fail-on", "none"], srv);
    expect(r.code).toBe(0);
    const body = srv.seen[0]!;
    expect(body.schemaVersion).toBe(2);
    const ins = body.insights as Record<string, any>;
    const keys = Object.keys(ins);
    for (const k of [
      "ai",
      "aiTools",
      "backup",
      "collectedAt",
      "disk",
      "git",
      "machine",
      "posture",
      "toolchain",
    ]) {
      expect(keys).toContain(k);
    }
    // `activity` rides along only when the machine has a global git identity.
    expect(keys.filter((k) => k !== "activity")).toHaveLength(9);
    expect(ins.machine.cpuCount).toBeGreaterThan(0);
    expect(typeof ins.machine.uptimeHours).toBe("number");
    // The fake home has no ~/.ssh: zero keys, and the posture block is classifications only.
    expect(ins.posture.sshKeys.count).toBe(0);
    expect(["on", "off", "unknown"]).toContain(ins.posture.diskEncryption);
    // The repo's id is the ORG salt over its normalized REMOTE — what another laptop's
    // clone (anywhere on disk, ssh or https) produces too.
    const expected = repoRefId(ORG_SALT, {
      remoteUrl: "https://github.com/acme/app",
      homeRelativePath: "unused",
    });
    expect(ins.git.top[0].repo).toEqual({ id: expected });
    expect(ins.ai.days.map((d: { repo: unknown }) => d.repo)).toContainEqual({ id: expected });
    const wire = JSON.stringify(body);
    expect(wire).not.toContain("client-acme");
    expect(wire).not.toContain(SENTINEL);
    expect(wire).not.toContain(fx.home.replace(/\\/g, "/"));
    // The AI cursor moved only after the server accepted it.
    expect(loadUploadCursor(fx.env, "dev-1")).toBe(new Date(now - DAY).toISOString().slice(0, 10));
  }, 60_000);

  it("with sharePaths the RepoRef carries the home-relative name", async () => {
    fx = makeFixture();
    home(fx, Date.now());
    enrol(fx, true);
    const srv = server();
    await run(fx, ["--upload", "--quiet", "--fail-on", "none"], srv);
    const ins = srv.seen[0]!.insights as Record<string, any>;
    expect(ins.git.top[0].repo.name).toBe("~/code/client-acme");
  }, 60_000);

  it("sends only AI days since the last successful upload", async () => {
    fx = makeFixture();
    const now = Date.now();
    home(fx, now);
    enrol(fx);
    const today = new Date(now).toISOString().slice(0, 10);
    saveUploadCursor(fx.env, "dev-1", today);
    const srv = server();
    await run(fx, ["--root", fx.home, "--upload", "--quiet", "--fail-on", "none"], srv);
    const ins = srv.seen[0]!.insights as Record<string, any>;
    // a --root run: machine + toolchain + AI only
    expect(ins.git).toBeUndefined();
    expect(ins.toolchain).toBeDefined();
    expect(ins.ai.days.map((d: { day: string }) => d.day)).toEqual([today]);
  }, 60_000);

  it("does not move the AI cursor when the upload is rejected", async () => {
    fx = makeFixture();
    home(fx, Date.now());
    enrol(fx);
    saveUploadCursor(fx.env, "dev-1", "2026-01-01");
    const io = captureIO();
    io.fetch = (async () => ({ status: 503, json: async () => ({}) })) as FetchLike;
    io.sleep = async () => {};
    await main(["--root", fx.home, "--upload", "--quiet"], io, fx.env, fx.root);
    expect(loadUploadCursor(fx.env, "dev-1")).toBe("2026-01-01");
  }, 60_000);

  it("--no-insights and MDM insights:false send the unchanged v1 body", async () => {
    fx = makeFixture();
    home(fx, Date.now());
    enrol(fx);
    const srv = server();
    await run(fx, ["--root", fx.home, "--upload", "--no-insights", "--quiet"], srv);
    expect(srv.seen[0]!.schemaVersion).toBe(1);
    expect(srv.seen[0]!.insights).toBeUndefined();

    const mdm = path.join(fx.root, "mdm.json");
    fs.writeFileSync(mdm, JSON.stringify({ upload: true, insights: false }));
    fx.env.mdmConfigPath = mdm;
    await run(fx, ["--root", fx.home, "--quiet"], srv);
    expect(srv.seen[1]!.schemaVersion).toBe(1);
    expect(srv.seen[1]!.insights).toBeUndefined();
  }, 60_000);

  it("the SCHEDULED run honours MDM insights:false (v1 body) and never validates or cleans", async () => {
    fx = makeFixture();
    home(fx, Date.now());
    enrol(fx);
    const mdm = path.join(fx.root, "mdm.json");
    fs.writeFileSync(mdm, JSON.stringify({ upload: true, insights: false }));
    fx.env.mdmConfigPath = mdm;
    const srv = server();
    // exactly what the installed schedule runs (schedule.ts scheduledArgs), with the fixture's
    // roots narrowed so the run stays quick
    const r = await run(
      fx,
      ["--root", fx.home, "--quiet", "--scheduled", "--upload", "--fail-on", "none"],
      srv,
    );
    expect(r.code).toBe(0);
    expect(srv.seen).toHaveLength(1);
    expect(srv.seen[0]!.schemaVersion).toBe(1);
    expect(srv.seen[0]!.insights).toBeUndefined();
    // …and the same scheduled flags can neither validate nor clean
    const v = await run(fx, ["--root", fx.home, "--scheduled", "--validate"], srv);
    expect(v.code).toBe(2);
    expect(v.err).toContain("cannot be used in a scheduled run");
    const c = await run(fx, ["disk", "clean", "--yes", "--scheduled"], srv);
    expect(c.code).toBe(2);
    expect(c.err).toContain("never runs from a scheduled");
    expect(srv.seen).toHaveLength(1);
  }, 60_000);

  it("two org laptops with clones in different folders send the same repo id", async () => {
    fx = makeFixture();
    fx2 = makeFixture();
    const now = Date.now();
    home(fx, now, "client-acme");
    home(fx2, now, "acme-app-clone");
    // laptop 2 cloned over https
    gitIn(fx2, path.join(fx2.home, "code", "acme-app-clone"), [
      "remote",
      "set-url",
      "origin",
      "https://github.com/acme/app.git",
    ]);
    enrol(fx);
    enrol(fx2);
    const s1 = server();
    const s2 = server();
    await run(fx, ["--upload", "--quiet", "--fail-on", "none"], s1);
    await run(fx2, ["--upload", "--quiet", "--fail-on", "none"], s2);
    const id1 = (s1.seen[0]!.insights as any).git.top[0].repo.id;
    const id2 = (s2.seen[0]!.insights as any).git.top[0].repo.id;
    expect(id1).toBe(id2);
  }, 120_000);
});
