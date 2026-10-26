import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { VERSION, main } from "../src/cli";
import { captureIO, githubToken, makeFixture, pemKey, scramble, type Fixture } from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

async function run(args: string[]) {
  const io = captureIO();
  const code = await main(args, io, fx.env);
  return { code, out: io.out(), err: io.err() };
}

describe("main", () => {
  it("prints help and version", async () => {
    fx = makeFixture();
    const h = await run(["--help"]);
    expect(h.code).toBe(0);
    expect(h.out).toContain("Usage");
    expect(h.out).toContain("--fail-on");
    const v = await run(["--version"]);
    expect(v.out.trim()).toBe(VERSION);
  });

  it("rejects bad flags and unknown commands with exit 2", async () => {
    fx = makeFixture();
    expect((await run(["--bogus"])).code).toBe(2);
    expect((await run(["frobnicate"])).code).toBe(2);
    expect((await run(["--fail-on", "sometimes"])).code).toBe(2);
    expect((await run(["--concurrency", "0"])).code).toBe(2);
  });

  it("exits 0 on a clean tree and 1 when a high-severity finding exists", async () => {
    fx = makeFixture();
    fx.write("a.txt", "nothing to see\n");
    const clean = await run(["--root", fx.home]);
    expect(clean.code).toBe(0);
    expect(clean.out).toContain("No plaintext secrets found");
    fx.write("b/.env", `API_TOKEN=${githubToken()}\n`);
    const dirty = await run(["--root", fx.home]);
    expect(dirty.code).toBe(1);
    expect(dirty.out).toContain("github-personal-access-token");
  });

  it("--fail-on critical / none changes the exit code, not the report", async () => {
    fx = makeFixture();
    const jwt = `eyJ${scramble(15)}.eyJ${scramble(15, 5)}.${scramble(20)}`; // medium
    fx.write("a/t.txt", `t=${jwt}\n`);
    expect((await run(["--root", fx.home, "--fail-on", "high"])).code).toBe(0);
    expect((await run(["--root", fx.home, "--fail-on", "medium"])).code).toBe(1);
    expect((await run(["--root", fx.home, "--fail-on", "none"])).code).toBe(0);
  });

  it("--fail-on new compares against the baseline across runs", async () => {
    fx = makeFixture();
    fx.write("a/.env", `API_TOKEN=${githubToken()}\n`);
    // first run: no baseline → everything is new
    expect((await run(["--root", fx.home, "--fail-on", "new"])).code).toBe(1);
    // second run: baseline written by the first → nothing new
    expect((await run(["--root", fx.home, "--fail-on", "new"])).code).toBe(0);
    fx.write("b/.env", `API_TOKEN=${githubToken(5)}\n`);
    const third = await run(["--root", fx.home, "--fail-on", "new"]);
    expect(third.code).toBe(1);
    expect(third.out).toContain("NEW");
  });

  it("--no-update leaves the baseline alone; the default writes it", async () => {
    fx = makeFixture();
    fx.write("a/.env", `API_TOKEN=${githubToken()}\n`);
    const baseline = path.join(fx.env.configDir, "sweep-baseline.json");
    await run(["--root", fx.home, "--no-update"]);
    expect(fs.existsSync(baseline)).toBe(false);
    await run(["--root", fx.home]);
    expect(fs.existsSync(baseline)).toBe(true);
  });

  it("--baseline points at an explicit file", async () => {
    fx = makeFixture();
    fx.write("a/.env", `API_TOKEN=${githubToken()}\n`);
    const custom = path.join(fx.root, "ci-baseline.json");
    await run(["--root", fx.home, "--baseline", custom]);
    expect(fs.existsSync(custom)).toBe(true);
    expect(fs.existsSync(path.join(fx.env.configDir, "sweep-baseline.json"))).toBe(false);
  });

  it("--json emits the schemaVersion 1 report and no raw secret anywhere", async () => {
    fx = makeFixture();
    const tok = githubToken(6);
    const key = pemKey(2);
    fx.write("a/.env", `API_TOKEN=${tok}\n`);
    fx.write("a/server.pem", key);
    fx.write("b/notes.txt", key);
    const r = await run(["--root", fx.home, "--json", "--html", path.join(fx.root, "r.html")]);
    expect(r.code).toBe(1);
    const j = JSON.parse(r.out);
    expect(j.schemaVersion).toBe(1);
    expect(j.findings.length).toBe(2);
    const keyFinding = j.findings.find((f: { copies: number }) => f.copies === 2);
    expect(keyFinding).toBeTruthy();

    const everything = [
      r.out,
      r.err,
      fs.readFileSync(path.join(fx.root, "r.html"), "utf8"),
      fs.readFileSync(path.join(fx.env.configDir, "sweep-baseline.json"), "utf8"),
    ].join("\n");
    const secrets = [tok, scramble(64, 7 + 4), scramble(64, 5 + 4), scramble(40, 9)];
    for (const s of secrets) {
      expect(everything.includes(s), `leaked ${s.slice(0, 6)}…`).toBe(false);
      expect(everything.includes(s.slice(3, -3))).toBe(false);
    }
  });

  it("falls back to sweep.json roots and excludes", async () => {
    fx = makeFixture();
    fs.mkdirSync(fx.env.configDir, { recursive: true });
    fs.writeFileSync(
      path.join(fx.env.configDir, "sweep.json"),
      JSON.stringify({ roots: [path.join(fx.home, "scanme")], exclude: ["skipme"] }),
    );
    fx.write("scanme/.env", `API_TOKEN=${githubToken()}\n`);
    fx.write("scanme/skipme/.env", `API_TOKEN=${githubToken(1)}\n`);
    fx.write("other/.env", `API_TOKEN=${githubToken(2)}\n`);
    const r = await run(["--json"]);
    const j = JSON.parse(r.out);
    expect(j.scope).toBe("paths");
    expect(j.findings).toHaveLength(1);
  });

  it("--quiet prints nothing but still sets the exit code", async () => {
    fx = makeFixture();
    fx.write("a/.env", `API_TOKEN=${githubToken()}\n`);
    const r = await run(["--root", fx.home, "--quiet"]);
    expect(r.code).toBe(1);
    expect(r.out).toBe("");
  });

  it("--quick scans the high-risk locations only", async () => {
    fx = makeFixture();
    fx.write(".claude/projects/p/s.jsonl", `{"t":"${githubToken()}"}\n`);
    fx.write("Documents/.env", `API_TOKEN=${githubToken(1)}\n`);
    const r = await run(["--quick", "--json"]);
    const j = JSON.parse(r.out);
    expect(j.scope).toBe("quick");
    expect(j.findings).toHaveLength(1);
    expect(j.findings[0].locationClasses).toEqual({ "agent-transcript": 1 });
  });

  it("warns about a missing root but still completes", async () => {
    fx = makeFixture();
    const r = await run(["--root", path.join(fx.home, "nope")]);
    expect(r.code).toBe(0);
    expect(r.err).toContain("root not found");
  });
});
