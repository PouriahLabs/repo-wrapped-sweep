import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../src/cli";
import { captureIO, githubToken, makeFixture, type Fixture } from "./helpers";
import { buildInsightsTree, put, stubBin, stubPathEnv } from "./insights-fixture";

let fx: Fixture;
afterEach(() => fx?.cleanup());

async function run(args: string[]) {
  const io = captureIO();
  const code = await main(args, io, fx.env);
  return { code, out: io.out(), err: io.err() };
}

/** A fixture home with the standard tree and a PATH holding only a `node` stub. */
function setup() {
  fx = makeFixture();
  const bin = path.join(fx.root, "bin");
  stubBin(bin, "node", "v20.11.0");
  fx.env.processEnv = stubPathEnv(bin);
  return buildInsightsTree(fx, Date.now());
}

describe("insights commands", () => {
  it("--help lists the commands and --no-insights", async () => {
    fx = makeFixture();
    const h = await run(["--help"]);
    for (const s of [
      "Machine insights",
      "repo-wrapped-sweep git [--fetch]",
      "repo-wrapped-sweep disk",
      "repo-wrapped-sweep toolchain",
      "repo-wrapped-sweep backup",
      "repo-wrapped-sweep insights",
      "--no-insights",
    ]) {
      expect(h.out).toContain(s);
    }
  });

  it("git --json: home-relative paths, states, and the summary line", async () => {
    setup();
    const r = await run(["git", "--json"]);
    expect(r.code).toBe(0);
    const j = JSON.parse(r.out);
    expect(j).toMatchObject({ schemaVersion: 1, kind: "insights", scope: "full" });
    expect(j.disk).toBeUndefined();
    const by = Object.fromEntries(j.git.repos.map((x: { path: string }) => [x.path, x]));
    expect(by["~/code/ahead"].states).toEqual(["unpushed", "stale-stash"]);
    expect(by["~/code/local"].states).toEqual(["uncommitted", "no-remote"]);
    expect(by["~/code/pushed"].states).toEqual(["clean"]);
    expect(j.git.line).toBe(
      "2 repos have work that exists only on this machine (1 commit, 1 stash)",
    );
    expect(j.git.fetched).toBe(false);
    // Never the absolute home (it carries the username).
    expect(r.out).not.toContain(JSON.stringify(fx.home).slice(1, -1));
  });

  it("git (table) hides clean repos unless --all", async () => {
    setup();
    const plain = await run(["git"]);
    expect(plain.out).toContain("~/code/ahead");
    expect(plain.out).not.toContain("~/code/pushed");
    expect(plain.out).toContain("behind = as of the last fetch");
    const all = await run(["git", "--all"]);
    expect(all.out).toContain("~/code/pushed");
  });

  it("disk, toolchain and backup each report their own section", async () => {
    const t = setup();
    const d = await run(["disk", "--root", path.join(fx.home, "code")]);
    expect(d.code).toBe(0);
    expect(d.out).toContain("~/code/pushed/node_modules");
    expect(d.out).toMatch(/reclaim 8 KB from 1 project untouched for 30\+ days/);

    const tc = await run(["toolchain", "--json"]);
    const tj = JSON.parse(tc.out);
    expect(tj.toolchain.tools.find((x: { tool: string }) => x.tool === "node").version).toBe(
      "20.11.0",
    );
    expect(tj.toolchain.repos[0].drift[0].text).toBe("node 20.11.0 installed, .nvmrc wants 22");

    const b = await run(["backup"]);
    expect(b.out).toContain("Backup coverage — 5 projects");
    expect(b.out).toMatch(/3 projects exist only on this machine/);
    expect(b.out).toContain("no remote");
    expect(t.local).toBeTruthy();
  });

  it("insights --html writes all four sections; --json carries them all", async () => {
    setup();
    const file = path.join(fx.root, "insights.html");
    const r = await run(["insights", "--html", file]);
    expect(r.code).toBe(0);
    for (const h of ["Local git", "Disk", "Toolchain", "Backup coverage"])
      expect(r.out).toContain(h);
    const html = fs.readFileSync(file, "utf8");
    expect(html).toContain("<title>Machine insights</title>");
    expect(html).toContain("~/code/ahead");
    expect(html).not.toContain(fx.home);
    const j = JSON.parse((await run(["insights", "--json"])).out);
    expect(Object.keys(j)).toEqual(expect.arrayContaining(["git", "disk", "toolchain", "backup"]));
  });

  it("stray arguments are usage errors (`disk clean` has its own tests)", async () => {
    fx = makeFixture();
    expect((await run(["disk", "clean", "extra"])).code).toBe(2);
    expect((await run(["disk", "other"])).code).toBe(2);
    expect((await run(["git", "extra"])).code).toBe(2);
  });
});

describe("the full sweep's insights summary", () => {
  it("follows the findings table; --no-insights, --json and --root leave it out", async () => {
    setup();
    put(path.join(fx.home, "code", "plain", "settings.json"), `{"token":"${githubToken(3)}"}\n`);

    const full = await run(["--fail-on", "none", "--no-update"]);
    expect(full.code).toBe(0);
    const table = full.out.indexOf("finding");
    const summary = full.out.indexOf("Insights");
    expect(table).toBeGreaterThan(-1);
    expect(summary).toBeGreaterThan(table);
    expect(full.out).toContain(
      "2 repos have work that exists only on this machine (1 commit, 1 stash)",
    );
    expect(full.out).toMatch(/3 projects exist only on this machine/);
    expect(full.out).toMatch(/reclaim .* from 1 project untouched for 30\+ days/);

    const off = await run(["--fail-on", "none", "--no-update", "--no-insights"]);
    expect(off.out).not.toContain("Insights");
    // Same findings either way.
    expect(off.out.split("Insights")[0]!.trim()).toBe(full.out.split("\nInsights")[0]!.trim());

    const json = await run(["--fail-on", "none", "--no-update", "--json"]);
    const j = JSON.parse(json.out);
    expect(j.insights).toBeUndefined();
    expect(j.findings.length).toBeGreaterThan(0);

    const rooted = await run(["--fail-on", "none", "--no-update", "--root", fx.home]);
    expect(rooted.out).not.toContain("Insights");
  });
});
