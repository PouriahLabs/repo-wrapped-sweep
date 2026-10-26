import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { collectInsights } from "../src/insights";
import { collectBackup } from "../src/insights/backup";
import { Discovery, discover } from "../src/insights/discover";
import { collectDisk, dirSize, parseDockerSize } from "../src/insights/disk";
import { changedPaths, collectGit } from "../src/insights/git";
import { commandFor, findOnPath, mapPool, runCommand } from "../src/insights/run";
import { collectToolchain } from "../src/insights/toolchain";
import { scan } from "../src/scan";
import { walk } from "../src/walk";
import { buildA10Tree } from "./a10-fixture";
import { githubToken, makeFixture, pemKey, type Fixture } from "./helpers";
import {
  DAY_MS,
  buildInsightsTree,
  gitIn,
  initRepo,
  put,
  stubBin,
  stubPathEnv,
} from "./insights-fixture";

let fx: Fixture;
afterEach(() => fx?.cleanup());

const NOW = Date.now();

async function discoverHome(over: Partial<Parameters<typeof discover>[0]> = {}) {
  return discover({
    env: fx.env,
    roots: [],
    excludeGlobs: [],
    includeCloud: false,
    concurrency: 4,
    placeholders: null,
    ...over,
  });
}

const rel = (abs: string) => path.relative(fx.home, abs).split(path.sep).join("/");

// ---------------------------------------------------------------------------
// The walk: insights ride along without changing a single finding
// ---------------------------------------------------------------------------

describe("walk observer", () => {
  it("the secret-finding set of a full sweep is identical with the insights observer", async () => {
    fx = makeFixture();
    buildA10Tree(fx.home, process.platform);
    buildInsightsTree(fx, NOW);
    // Secrets in places the observer looks at: next to a .git, inside node_modules,
    // in a project with a target/ folder, and in a gitdir FILE's folder.
    put(
      path.join(fx.home, "code", "pushed", ".env.production"),
      `GITHUB_TOKEN=${githubToken(7)}\n`,
    );
    put(path.join(fx.home, "code", "pushed", "node_modules", "x", ".env"), `T=${githubToken(8)}\n`);
    put(path.join(fx.home, "code", "rusty", "target", "id_rsa"), pemKey(3));
    put(path.join(fx.home, "code", "wt", ".git"), "gitdir: ../pushed/.git/worktrees/wt\n");
    put(path.join(fx.home, "code", "wt", "config.json"), `{"token":"${githubToken(9)}"}\n`);

    const run = (observer?: Discovery) =>
      scan({
        env: fx.env,
        roots: [],
        quick: false,
        excludeGlobs: [],
        includeCloud: false,
        concurrency: 4,
        salt: new Uint8Array(32).fill(7),
        placeholders: null,
        observer,
      });
    const canon = (r: Awaited<ReturnType<typeof run>>) =>
      JSON.stringify(
        r.groups
          .map((g) => ({
            fingerprint: g.fingerprint,
            ruleId: g.ruleId,
            severity: g.severity,
            preview: g.preview,
            copies: g.copies,
            locations: g.locations
              .map((l) => `${l.path}|${l.line ?? ""}|${l.locationClass}`)
              .sort(),
          }))
          .sort((a, b) => (a.fingerprint + a.ruleId).localeCompare(b.fingerprint + b.ruleId)),
      );
    const without = await run();
    const observer = new Discovery(fx.env);
    const withObs = await run(observer);
    expect(without.groups.length).toBeGreaterThan(0);
    expect(canon(withObs)).toBe(canon(without));
    expect(withObs.stats.files).toBe(without.stats.files);
    // …and the observer did see the repos, including the gitdir file.
    expect(observer.repos().map(rel)).toEqual(
      expect.arrayContaining(["code/pushed", "code/ahead", "code/local", "code/wt"]),
    );
  });

  it("dirsOnly lists folders without handing out a single file", async () => {
    fx = makeFixture();
    put(path.join(fx.home, "a", "b.txt"), "x");
    let files = 0;
    const seen: string[] = [];
    await walk({
      roots: [fx.home],
      env: fx.env,
      excludeGlobs: [],
      includeCloud: false,
      concurrency: 2,
      dirsOnly: true,
      observer: { onDirectory: (d) => seen.push(rel(d)) },
      onFile: async () => {
        files++;
      },
    });
    expect(files).toBe(0);
    expect(seen.sort()).toEqual(["", "a"]);
  });

  it("an observer that throws does not disturb the walk", async () => {
    fx = makeFixture();
    put(path.join(fx.home, "a", "b.txt"), "x");
    const seen: string[] = [];
    await walk({
      roots: [fx.home],
      env: fx.env,
      excludeGlobs: [],
      includeCloud: false,
      concurrency: 2,
      observer: {
        onDirectory: () => {
          throw new Error("boom");
        },
      },
      onFile: async (f) => {
        seen.push(rel(f.path));
      },
    });
    expect(seen).toEqual(["a/b.txt"]);
  });
});

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

describe("Discovery", () => {
  it("finds repos, top-level projects and regenerable folders next to their proof", async () => {
    fx = makeFixture();
    buildInsightsTree(fx, NOW);
    put(path.join(fx.home, "code", "pushed", "packages", "ui", "package.json"), "{}");
    put(path.join(fx.home, "code", "nolock", "package.json"), "{}");
    put(path.join(fx.home, "code", "nolock", "node_modules", "x.js"), "x");
    put(path.join(fx.home, "code", "nolock", "src", "i.js"), "x");
    put(path.join(fx.home, "code", "web", "package.json"), "{}");
    put(path.join(fx.home, "code", "web", "page.js"), "x");
    put(path.join(fx.home, "code", "web", ".vercel", "output", "x.json"), "{}");
    put(path.join(fx.home, "package.json"), "{}"); // a stray one at home is never a project

    const found = await discoverHome();
    expect(found.repos().map(rel)).toEqual(["code/ahead", "code/local", "code/pushed"]);
    expect(found.topProjects().map((p) => rel(p.path))).toEqual([
      "code/ahead",
      "code/local",
      "code/nolock",
      "code/plain",
      "code/pushed",
      "code/rusty",
      "code/web",
    ]);
    const classes = found
      .regenerable()
      .map((d) => `${rel(d.path)}=${d.cls}`)
      .sort();
    expect(classes).toEqual([
      "code/plain/__pycache__=python-cache",
      "code/pushed/node_modules=node-modules",
      "code/rusty/target=rust-target",
      "code/web/.vercel/output=next-build",
    ]);
    // dist/ is reported by size, never a class; node_modules without a lockfile is nothing.
    expect(found.reportOnly.map((d) => rel(d.path))).toEqual(["code/pushed/dist"]);
    expect(found.pinFilesIn(path.join(fx.home, "code", "ahead"))).toEqual([
      ".nvmrc",
      "package.json",
    ]);
  });

  it("a folder of nothing but an install is not a project worth backing up", async () => {
    fx = makeFixture();
    put(path.join(fx.home, "scratch", "package.json"), "{}");
    put(path.join(fx.home, "scratch", "package-lock.json"), "{}");
    put(path.join(fx.home, "scratch", "node_modules", "x.js"), "x");
    put(path.join(fx.home, "real", "package.json"), "{}");
    put(path.join(fx.home, "real", "index.js"), "x");
    const found = await discoverHome();
    expect(found.onlyRegenerable(path.join(fx.home, "scratch"))).toBe(true);
    expect(found.onlyRegenerable(path.join(fx.home, "real"))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// git
// ---------------------------------------------------------------------------

describe("git collector", () => {
  it("classifies real repos: unpushed + old stash, no-remote + stale untracked, clean", async () => {
    fx = makeFixture();
    const t = buildInsightsTree(fx, NOW);
    const found = await discoverHome();
    const g = await collectGit(found.repos(), { env: fx.env, now: NOW });
    const by = new Map(g.repos.map((r) => [rel(r.path), r]));

    const ahead = by.get("code/ahead")!;
    expect(ahead.states).toEqual(["unpushed", "stale-stash"]);
    expect(ahead.state!.unpushedCommits).toBe(1);
    expect(ahead.state!.unpushedBranches).toEqual([{ name: "main", unpushed: 1 }]);
    expect(ahead.state!.stashTimes).toHaveLength(1);
    expect(ahead.state!.upstream).toBe("origin/main");

    const local = by.get("code/local")!;
    expect(local.states).toEqual(["uncommitted", "no-remote"]);
    expect(local.state!.untracked).toBe(1);
    // dirtySince is the untracked file's mtime (10 days), not the commit (5 days).
    expect(Math.round((NOW - local.state!.dirtySince!) / DAY_MS)).toBe(10);

    expect(by.get("code/pushed")!.states).toEqual(["clean"]);
    // Most at risk first: unpushed commits outrank a remote-less repo.
    expect(g.repos.map((r) => rel(r.path))).toEqual(["code/ahead", "code/local", "code/pushed"]);
    expect(g.summary.localOnlyRepos).toBe(2);
    expect(g.summary.unpushedCommits).toBe(1);
    expect(g.summary.stashes).toBe(1);
    expect(t.ahead).toBeTruthy();
  });

  it("a repo with no commits yet is not a failure", async () => {
    fx = makeFixture();
    const dir = path.join(fx.home, "empty");
    fs.mkdirSync(dir, { recursive: true });
    gitIn(fx, dir, ["init", "-q", "-b", "main"]);
    const g = await collectGit([dir], { env: fx.env, now: NOW });
    expect(g.repos[0]!.failure).toBeUndefined();
    expect(g.repos[0]!.state!.lastCommitAt).toBeNull();
    expect(g.repos[0]!.states).toEqual(["clean"]);
  });

  it("git missing → every repo unknown, never clean", async () => {
    fx = makeFixture({ git: { bin: path.join("no", "such", "git-binary") } });
    const dir = path.join(fx.home, "r");
    fs.mkdirSync(dir, { recursive: true });
    const g = await collectGit([dir], { env: fx.env, now: NOW });
    expect(g.gitMissing).toBe(true);
    expect(g.repos[0]!.state).toBeNull();
    expect(g.repos[0]!.failure).toBe("unavailable");
    expect(g.summary.repos).toBe(0);
  });

  it("changedPaths reads every porcelain v2 entry kind", () => {
    const out = [
      "# branch.head main",
      "1 .M N... 100644 100644 100644 abc abc src/a b.ts",
      "2 R. N... 100644 100644 100644 abc abc R100 new.ts\told.ts",
      "u UU N... 100644 100644 100644 100644 a b c conflict.ts",
      "? notes/",
    ].join("\n");
    expect(changedPaths(out)).toEqual(["src/a b.ts", "new.ts", "conflict.ts", "notes/"]);
  });
});

// ---------------------------------------------------------------------------
// disk
// ---------------------------------------------------------------------------

describe("disk collector", () => {
  it("sizes class folders, dates projects and totals the stale ones", async () => {
    fx = makeFixture();
    const t = buildInsightsTree(fx, NOW);
    const found = await discoverHome();
    const g = await collectGit(found.repos(), { env: fx.env, now: NOW });
    const d = await collectDisk(found, {
      env: fx.env,
      lastCommitByRepo: new Map(g.repos.map((r) => [r.path, r.state?.lastCommitAt ?? null])),
      now: NOW,
    });
    const by = new Map(d.folders.map((f) => [rel(f.path), f]));
    const nm = by.get("code/pushed/node_modules")!;
    expect(nm.bytes).toBe(t.nodeModulesBytes);
    expect(nm.stale).toBe(true);
    expect(by.get("code/rusty/target")!.bytes).toBe(2048);
    expect(by.get("code/rusty/target")!.stale).toBe(false);
    expect(d.totals.staleReclaimableBytes).toBe(t.nodeModulesBytes);
    expect(d.totals.staleProjects).toBe(1);
    expect(d.totals.byClass["node-modules"]).toBe(t.nodeModulesBytes);
    expect(d.reportOnly.map((x) => [rel(x.path), x.bytes])).toEqual([["code/pushed/dist", 100]]);
    // No package caches or Docker unless asked for (a --root run).
    expect(d.packageCaches).toEqual([]);
    expect(d.dockerBytes).toBeNull();
  });

  it("dirSize never follows links and stops at its budget", async () => {
    fx = makeFixture();
    put(path.join(fx.home, "d", "a.bin"), Buffer.alloc(1000));
    put(path.join(fx.home, "d", "sub", "b.bin"), Buffer.alloc(24));
    put(path.join(fx.home, "big", "c.bin"), Buffer.alloc(5000));
    try {
      fs.symlinkSync(path.join(fx.home, "big"), path.join(fx.home, "d", "link"), "junction");
    } catch {
      // symlinks unavailable: the size still must not include `big`
    }
    expect(await dirSize(path.join(fx.home, "d"), { deadline: Date.now() + 10_000 })).toEqual({
      bytes: 1024,
      partial: false,
    });
    expect((await dirSize(path.join(fx.home, "d"), { deadline: 0 })).partial).toBe(true);
  });

  it("parses docker sizes", () => {
    expect(parseDockerSize("1.5GB")).toBe(1.5e9);
    expect(parseDockerSize("512.3MB")).toBe(512_300_000);
    expect(parseDockerSize("0B")).toBe(0);
    expect(parseDockerSize("12kB")).toBe(12_000);
    expect(parseDockerSize("n/a")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// toolchain — a fake PATH of stub binaries
// ---------------------------------------------------------------------------

describe("toolchain collector", () => {
  it("probes stubs on PATH, detects managers, and reports drift against repo pins", async () => {
    fx = makeFixture();
    const bin = path.join(fx.root, "bin");
    stubBin(bin, "node", "v20.11.0");
    stubBin(bin, "pnpm", "9.1.0");
    stubBin(bin, "git", "git version 2.43.0.windows.1");
    stubBin(bin, "java", 'openjdk version "21.0.1" 2023-10-17', true);
    stubBin(bin, "fnm", "fnm 1.35.1");
    fx.env.processEnv = stubPathEnv(bin);
    const t = buildInsightsTree(fx, NOW);
    put(path.join(t.plain, ".python-version"), "3.12\n");

    const found = await discoverHome();
    const r = await collectToolchain({
      env: fx.env,
      folders: found
        .topProjects()
        .map((p) => ({ path: p.path, pinFiles: found.pinFilesIn(p.path) })),
    });
    const v = Object.fromEntries(r.tools.map((x) => [x.tool, x.version]));
    expect(v.node).toBe("20.11.0");
    expect(v.pnpm).toBe("9.1.0");
    expect(v.git).toBe("2.43.0");
    expect(v.java).toBe("21.0.1");
    expect(v.docker).toBeNull();
    expect(r.tools.find((x) => x.tool === "docker")!.status).toBe("absent");
    expect(r.managers).toEqual(["fnm"]);

    const ahead = r.repos.find((x) => x.path === t.ahead)!;
    // .nvmrc disagrees; engines.node (>=20) is satisfied, so only one drift row.
    expect(ahead.drift).toEqual([
      { tool: "node", source: ".nvmrc", wanted: "22", installed: "20.11.0", reason: "mismatch" },
    ]);
    const plain = r.repos.find((x) => x.path === t.plain)!;
    expect(plain.drift).toEqual([
      {
        tool: "python",
        source: ".python-version",
        wanted: "3.12",
        installed: null,
        reason: "missing",
      },
    ]);
  });

  it("findOnPath resolves the platform's executable form and skips what is absent", () => {
    fx = makeFixture();
    const bin = path.join(fx.root, "bin");
    const node = stubBin(bin, "node", "v1.0.0");
    const lookup = {
      path: bin,
      pathext: ".COM;.EXE;.BAT;.CMD",
      platform: process.platform,
    };
    expect(findOnPath("node", lookup)).toBe(node);
    expect(findOnPath("deno", lookup)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// backup — including a synced root
// ---------------------------------------------------------------------------

describe("backup collector", () => {
  it("synced beats git; no remote and not-git are local-only; pushed is pushed", async () => {
    fx = makeFixture();
    const t = buildInsightsTree(fx, NOW);
    const cloud = path.join(fx.home, "OneDrive");
    fx.env.cloudRoots = [cloud];
    const syncedRepo = path.join(cloud, "Documents", "thesis");
    put(path.join(syncedRepo, "main.tex"), "x");
    put(path.join(syncedRepo, "package.json"), "{}");
    initRepo(fx, syncedRepo, NOW - DAY_MS);

    const found = await discoverHome({ includeCloud: true });
    const g = await collectGit(found.repos(), { env: fx.env, now: NOW });
    const b = await collectBackup(found, {
      env: fx.env,
      gitByRepo: new Map(g.repos.map((r) => [r.path, r.state])),
      now: NOW,
    });
    const by = new Map(b.projects.map((p) => [rel(p.path), p]));
    expect(by.get("OneDrive/Documents/thesis")!.state).toBe("synced");
    expect(by.get("code/pushed")!.state).toBe("pushed");
    expect(by.get("code/ahead")!.state).toBe("partly-pushed");
    expect(by.get("code/ahead")!.atRisk.unpushedCommits).toBe(1);
    expect(by.get("code/local")!).toMatchObject({ state: "local-only", reason: "no-remote" });
    expect(by.get("code/local")!.atRisk.uncommittedDays).toBe(10);
    expect(by.get("code/plain")!).toMatchObject({ state: "local-only", reason: "not-git" });
    // Source bytes leave regenerable folders out (plain's __pycache__ is 512 bytes).
    const plainBytes = by.get("code/plain")!.bytes!;
    expect(plainBytes).toBeGreaterThan(0);
    expect(plainBytes).toBeLessThan(512);
    // Synced and pushed projects are not measured.
    expect(by.get("code/pushed")!.bytes).toBeNull();
    expect(b.summary.byState["local-only"]).toBe(3); // local, plain, rusty
    expect(b.projects[0]!.state).toBe("local-only");
    expect(t.rusty).toBeTruthy();
  });

  it("a cloud root is not walked by default, so its projects are simply not seen", async () => {
    fx = makeFixture();
    const cloud = path.join(fx.home, "OneDrive");
    fx.env.cloudRoots = [cloud];
    put(path.join(cloud, "p", "package.json"), "{}");
    const found = await discoverHome();
    expect(found.topProjects()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// orchestration + the runner
// ---------------------------------------------------------------------------

describe("collectInsights", () => {
  it("disk alone dates projects from `git log` without the full status pass", async () => {
    fx = makeFixture();
    buildInsightsTree(fx, NOW);
    const found = await discoverHome({ roots: [path.join(fx.home, "code")] });
    const r = await collectInsights(found, ["disk"], { env: fx.env, scope: "paths", now: NOW });
    expect(r.git).toBeUndefined();
    expect(r.disk!.totals.staleProjects).toBe(1);
  });
});

describe("runCommand", () => {
  it("a deadline resolves as timeout; a missing binary as unavailable", async () => {
    const slow = await runCommand(process.execPath, ["-e", "setTimeout(() => {}, 10000)"], {
      timeoutMs: 300,
    });
    expect(slow).toEqual({ ok: false, failure: "timeout" });
    const missing = await runCommand(path.join("no", "such", "binary-xyz"), [], {
      timeoutMs: 2000,
    });
    expect(missing).toEqual({ ok: false, failure: "unavailable" });
    const ok = await runCommand(process.execPath, ["-e", "process.stdout.write('hi')"], {
      timeoutMs: 5000,
    });
    expect(ok).toMatchObject({ ok: true, code: 0, stdout: "hi" });
  });

  it("a Windows .cmd wrapper runs through cmd.exe; anything else runs directly", () => {
    expect(commandFor("C:\\t\\node.cmd", ["--version"], "win32", "C:\\cmd.exe")).toEqual({
      cmd: "C:\\cmd.exe",
      args: ["/d", "/s", "/c", '""C:\\t\\node.cmd" --version"'],
    });
    expect(commandFor("/usr/bin/node", ["--version"], "linux")).toEqual({
      cmd: "/usr/bin/node",
      args: ["--version"],
    });
  });

  it("mapPool keeps order and bounds concurrency", async () => {
    let inFlight = 0;
    let peak = 0;
    const out = await mapPool([5, 1, 4, 2, 3], 2, async (n) => {
      peak = Math.max(peak, ++inFlight);
      await new Promise((r) => setTimeout(r, n * 5));
      inFlight--;
      return n * 10;
    });
    expect(out).toEqual([50, 10, 40, 20, 30]);
    expect(peak).toBe(2);
  });
});
