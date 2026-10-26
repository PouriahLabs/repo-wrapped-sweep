import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { defaultBaselinePath, saveBaseline, updateBaseline } from "../src/baseline";
import {
  HOOK_MATCHER,
  installHook,
  resolveVariants,
  runHookCheck,
  settingsPath,
} from "../src/hook";
import { GIT_TIMEOUT_MS, SEARCH_MAX_ENTRIES, makeFilter } from "../src/hook-search";
import {
  detectShellSearches,
  expandBraces,
  grepToolRequest,
  splitGlobs,
  tokenizeSegments,
} from "../src/hook-shell";
import type { SweepEnv } from "../src/env";
import { makeFixture, type Fixture } from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

function call(tool: string, toolInput: Record<string, unknown>, cwd?: string) {
  return JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: tool,
    tool_input: toolInput,
    cwd,
  });
}
const check = (stdin: string, cwd = fx.home) => runHookCheck(stdin, fx.env, cwd);
const proj = () => path.join(fx.home, "proj");
const bash = (command: string, cwd = fx.home) => check(call("Bash", { command }, cwd), cwd);
const grepTool = (input: Record<string, unknown>, cwd = fx.home) =>
  check(call("Grep", { pattern: "x", ...input }, cwd), cwd);

/** `n` empty files `f0000.txt…` directly under `dir`. */
function bulk(dir: string, n: number, prefix = "f") {
  fs.mkdirSync(dir, { recursive: true });
  for (let i = 0; i < n; i++) {
    fs.writeFileSync(path.join(dir, `${prefix}${String(i).padStart(4, "0")}.txt`), "x");
  }
}

function saveBaselineFor(env: SweepEnv, locations: string[]) {
  const baseline = updateBaseline(
    [
      {
        fingerprint: "f1",
        ruleId: "github-personal-access-token",
        severity: "high",
        preview: "",
        copies: locations.length,
        locations: locations.map((p) => ({ path: p, locationClass: "documents" as const })),
        locationClasses: { documents: locations.length },
      },
    ],
    null,
    "full",
    "2026-01-01T00:00:00.000Z",
  );
  saveBaseline(defaultBaselinePath(env), baseline);
}

// ---------------------------------------------------------------------------
// 1. Windows paths and PowerShell/cmd readers
// ---------------------------------------------------------------------------

describe("hook check — Windows paths and readers", () => {
  it("denies the reported repro: `type proj\\.env.local`", () => {
    fx = makeFixture();
    fx.write("proj/.env.local", "X=1\n");
    const r = check(
      JSON.stringify({
        tool_name: "Bash",
        tool_input: { command: "type proj\\.env.local" },
        cwd: fx.home,
      }),
    );
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("environment file");
  });

  it("denies every reader that is handed a backslash path", () => {
    fx = makeFixture();
    fx.write("proj/.env.local", "X=1\n");
    fx.write("proj/notes.txt", "hello\n");
    const readers = [
      "type proj\\.env.local",
      'type "proj\\.env.local"',
      "type .\\proj\\.env.local",
      "Get-Content proj\\.env.local",
      "gc proj\\.env.local",
      "cat proj\\.env.local",
      "Get-Content -Path proj\\.env.local",
      "Get-Content -Path:proj\\.env.local",
      "Get-Content -LiteralPath proj\\.env.local",
      "Get-Content proj\\notes.txt,proj\\.env.local",
      "Select-String -Path proj\\.env.local -Pattern token",
      "sls token proj\\.env.local",
      "gc proj\\.env.local | sls token",
      "more proj\\.env.local",
      "more < proj\\.env.local",
      "findstr token proj\\.env.local",
      "findstr /c:token proj\\.env.local",
      "findstr /f:proj\\.env.local token",
      "type %USERPROFILE%\\proj\\.env.local",
      "type $env:USERPROFILE\\proj\\.env.local",
      "type $HOME\\proj\\.env.local",
      "cat proj/.env.local",
    ];
    for (const cmd of readers) expect(bash(cmd).code, cmd).toBe(2);
    for (const cmd of [
      "type proj\\notes.txt",
      "gc proj\\notes.txt",
      "findstr token proj\\notes.txt",
    ]) {
      expect(bash(cmd).code, cmd).toBe(0);
    }
  });

  it("denies the editing tools, including MultiEdit and NotebookEdit", () => {
    fx = makeFixture();
    const target = fx.write("proj/.env", "X=1\n");
    for (const [tool, input] of [
      ["Read", { file_path: target }],
      ["Edit", { file_path: target }],
      ["MultiEdit", { file_path: target, edits: [] }],
      ["NotebookEdit", { notebook_path: target }],
    ] as const) {
      expect(check(call(tool, { ...input })).code, tool).toBe(2);
    }
  });

  it("checks the PowerShell tool's `command` like Bash's", () => {
    fx = makeFixture();
    fx.write("proj/.env", "X=1\n");
    expect(check(call("PowerShell", { command: "Get-Content proj\\.env" }, fx.home)).code).toBe(2);
    expect(
      check(call("PowerShell", { command: "Get-Content proj\\nothing.txt" }, fx.home)).code,
    ).toBe(0);
  });

  describe("on a Windows environment (drive letters, case, MSYS paths)", () => {
    // Simulated Windows paths exist nowhere on disk; every named file "exists".
    const winEnv = () =>
      makeFixture({ platform: "win32", home: "C:\\Users\\me", fileExists: () => true });
    const win = (cmd: string, cwd = "C:\\Users\\me\\proj") =>
      runHookCheck(call("Bash", { command: cmd }, cwd), fx.env, cwd);

    it("resolves relative, drive-letter, forward-slash, MSYS and UNC-prefixed paths", () => {
      fx = winEnv();
      for (const cmd of [
        "type .\\.env.local",
        "type .env.local",
        "type ..\\proj\\.env.local",
        "type C:\\Users\\me\\proj\\.env",
        "Get-Content C:/Users/me/proj/.env",
        "cat /c/Users/me/proj/.env",
        "cat /mnt/c/Users/me/proj/.env",
        "cat /cygdrive/c/Users/me/proj/.env",
        "type \\\\?\\C:\\Users\\me\\proj\\.env",
        "type %USERPROFILE%\\proj\\.env",
        "type $env:USERPROFILE\\proj\\.env",
        "type ~\\proj\\.env",
      ]) {
        expect(win(cmd).code, cmd).toBe(2);
      }
    });

    it("compares case-insensitively and sees through trailing dots and alternate data streams", () => {
      fx = winEnv();
      for (const cmd of [
        "TYPE C:\\USERS\\ME\\PROJ\\.ENV",
        "type .ENV.LOCAL",
        "type .env.",
        "type .env::$DATA",
        "type .env:secret",
      ]) {
        expect(win(cmd).code, cmd).toBe(2);
      }
    });

    it("still allows ordinary files, and the example env file", () => {
      fx = winEnv();
      for (const cmd of [
        "type C:\\Users\\me\\proj\\readme.md",
        "type .env.example",
        "type ..\\proj\\src\\app.ts",
        "cd C:",
        "type C:",
      ]) {
        expect(win(cmd).code, cmd).toBe(0);
      }
    });

    it("matches the baseline location list case-insensitively", () => {
      fx = winEnv();
      saveBaselineFor(fx.env, ["~/code/config.ts"]);
      const r = check(
        call("Read", { file_path: "C:\\USERS\\ME\\CODE\\CONFIG.TS" }),
        "C:\\Users\\me",
      );
      expect(r.code).toBe(2);
      expect(r.stderr).toContain("previous sweep");
      expect(
        check(call("Read", { file_path: "C:\\Users\\me\\code\\other.ts" }), "C:\\Users\\me").code,
      ).toBe(0);
    });
  });

  it("reads a backslash both as a separator and as a bash escape on POSIX", () => {
    const posix = { platform: "linux", home: "/h", cloudRoots: [], configDir: "/c" } as SweepEnv;
    expect(resolveVariants("proj\\.env.local", "/w", posix)).toEqual(
      expect.arrayContaining(["/w/proj/.env.local", "/w/proj.env.local"]),
    );
    expect(resolveVariants("\\.env", "/w", posix)).toEqual(expect.arrayContaining(["/w/.env"]));
    expect(resolveVariants("~/x", "/w", posix)).toEqual(["/h/x"]);
  });
});

// ---------------------------------------------------------------------------
// 2. Directory searches
// ---------------------------------------------------------------------------

describe("hook check — Grep tool over a directory", () => {
  it("denies a directory that holds a credential file, naming it and a way out", () => {
    fx = makeFixture();
    fx.write("proj/keys/server.p12", "x");
    fx.write("proj/src/app.ts", "export {}\n");
    const r = grepTool({ path: proj() });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("~/proj");
    expect(r.stderr).toContain("~/proj/keys/server.p12 (PKCS#12 key bundle)");
    expect(r.stderr).toContain("narrower path");
    expect(r.stderr).toContain('"!server.p12"');
  });

  it("uses the working directory when `path` is absent", () => {
    fx = makeFixture();
    fx.write("proj/server.p12", "x");
    expect(grepTool({}, proj()).code).toBe(2);
    expect(grepTool({ path: "." }, proj()).code).toBe(2);
    expect(grepTool({ path: "src" }, proj()).code).toBe(0); // missing directory: nothing to read
  });

  it("allows a clean directory and a single non-credential file", () => {
    fx = makeFixture();
    fx.write("proj/server.p12", "x");
    fx.write("proj/src/app.ts", "export {}\n");
    expect(grepTool({ path: path.join(proj(), "src") }).code).toBe(0);
    expect(grepTool({ path: path.join(proj(), "src", "app.ts") }).code).toBe(0);
  });

  it("names at most 3 files and counts the rest", () => {
    fx = makeFixture();
    for (const f of ["a", "b", "c", "d", "e"]) fx.write(`proj/${f}.p12`, "x");
    const r = grepTool({ path: proj() });
    expect(r.code).toBe(2);
    expect(r.stderr.match(/\(PKCS#12 key bundle\)/g)).toHaveLength(3);
    expect(r.stderr).toContain("and 2 more");
  });

  it("allows it when the glob or type provably excludes every flagged file", () => {
    fx = makeFixture();
    fx.write("proj/server.p12", "x");
    fx.write("proj/cookies.txt", "x");
    fx.write("proj/src/app.ts", "export {}\n");
    for (const glob of [
      "*.ts",
      "*.{ts,tsx}",
      "src/**/*.ts",
      "**/*.md",
      "!*.p12 !cookies.txt",
      "!{*.p12,cookies.txt}",
    ]) {
      expect(grepTool({ path: proj(), glob }).code, glob).toBe(0);
    }
    for (const type of ["ts", "js", "py", "rust"]) {
      expect(grepTool({ path: proj(), type }).code, type).toBe(0);
    }
  });

  it("denies when the filter does NOT provably exclude a flagged file", () => {
    fx = makeFixture();
    fx.write("proj/server.p12", "x");
    fx.write("proj/gcp/my-service-account.json", "{}\n");
    for (const glob of ["*", "**/*", "*.p12", "*.{ts,p12}"]) {
      expect(grepTool({ path: proj(), glob }).code, glob).toBe(2);
    }
    // a type that could cover the file, and one the engine does not know
    expect(grepTool({ path: proj(), type: "json" }).code).toBe(2);
    expect(grepTool({ path: proj(), type: "no-such-type" }).code).toBe(2);
    // only the .p12 is filtered out; the service-account JSON is still readable
    expect(grepTool({ path: proj(), glob: "!*.p12" }).code).toBe(2);
    expect(grepTool({ path: proj(), glob: "!*.p12 !my-service-account.json" }).code).toBe(0);
  });

  it("walks 4 levels deep and no further", () => {
    fx = makeFixture();
    fx.write("proj/a/b/c/server.p12", "x"); // depth 4
    expect(grepTool({ path: proj() }).code).toBe(2);
    fx.cleanup();
    fx = makeFixture();
    fx.write("proj/a/b/c/d/server.p12", "x"); // depth 5
    expect(grepTool({ path: proj() }).code).toBe(0);
  });

  it("skips the walker's default excludes and sweep.json excludes, and honours hookAllow", () => {
    fx = makeFixture();
    fx.write("proj/node_modules/pkg/server.p12", "x");
    fx.write("proj/dist/server.p12", "x");
    expect(grepTool({ path: proj() }).code).toBe(0);

    fx.write("proj/secrets/server.p12", "x");
    expect(grepTool({ path: proj() }).code).toBe(2);
    fs.mkdirSync(fx.env.configDir, { recursive: true });
    fs.writeFileSync(
      path.join(fx.env.configDir, "sweep.json"),
      JSON.stringify({ exclude: ["**/secrets/**"] }),
    );
    expect(grepTool({ path: proj() }).code).toBe(0);

    fx.write("proj/keep/server.p12", "x");
    expect(grepTool({ path: proj() }).code).toBe(2);
    fs.writeFileSync(
      path.join(fx.env.configDir, "sweep.json"),
      JSON.stringify({ exclude: ["**/secrets/**"], hookAllow: ["**/keep/server.p12"] }),
    );
    expect(grepTool({ path: proj() }).code).toBe(0);
  });

  it("does not follow links out of the tree", () => {
    fx = makeFixture();
    fx.write("outside/server.p12", "x");
    fs.mkdirSync(proj(), { recursive: true });
    try {
      fs.symlinkSync(path.join(fx.home, "outside"), path.join(proj(), "link"), "junction");
    } catch {
      return; // no symlink privilege on this machine
    }
    expect(grepTool({ path: proj() }).code).toBe(0);
  });

  it("falls back to the baseline's locations once the entry bound is hit", () => {
    fx = makeFixture();
    bulk(proj(), SEARCH_MAX_ENTRIES + 100);
    fx.write("proj/zz/server.p12", "x");
    // the bound is hit, so the name-rule walk is abandoned (deterministically)…
    expect(grepTool({ path: proj() }).code).toBe(0);
    // …but a recorded location is still protected
    saveBaselineFor(fx.env, ["~/proj/f0007.txt"]);
    const r = grepTool({ path: proj() });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("~/proj/f0007.txt");
    expect(r.stderr).toContain("previous sweep");
    // and the call's own filter still applies to it
    expect(grepTool({ path: proj(), glob: "!f0007.txt" }).code).toBe(0);
  });

  it("stays inside the 50 ms budget on a ~2,000-file tree, hit or clear", () => {
    fx = makeFixture();
    for (let d = 0; d < 19; d++) bulk(path.join(proj(), `pkg${d}`), 100, "m");
    fx.write("proj/pkg10/server.p12", "x");
    const hit = call("Grep", { pattern: "x", path: proj() }, fx.home);
    const clear = call("Grep", { pattern: "x", path: proj(), glob: "*.txt" }, fx.home);
    expect(check(hit).code).toBe(2); // a full (not truncated) walk finds it
    expect(check(clear).code).toBe(0);
    for (const [label, stdin] of [
      ["hit", hit],
      ["clear", clear],
    ] as const) {
      const times: number[] = [];
      for (let i = 0; i < 7; i++) {
        const t0 = performance.now();
        check(stdin);
        times.push(performance.now() - t0);
      }
      times.sort((a, b) => a - b);
      expect(times[Math.floor(times.length / 2)]!, label).toBeLessThan(50);
    }
  });
});

// ---------------------------------------------------------------------------
// 2b. ripgrep's default filtering decides what a search would actually read
// ---------------------------------------------------------------------------

describe("hook check — searches that would not read a flagged file are allowed", () => {
  const savedEnv: Record<string, string | undefined> = {};
  beforeAll(() => {
    // The developer's own git config / global excludes must not leak into the fixtures.
    const quiet = path.join(os.tmpdir(), "sweep-test-no-git-config");
    for (const [k, v] of Object.entries({
      GIT_CONFIG_GLOBAL: path.join(quiet, "gitconfig"),
      GIT_CONFIG_NOSYSTEM: "1",
      XDG_CONFIG_HOME: quiet,
    })) {
      savedEnv[k] = process.env[k];
      process.env[k] = v;
    }
  });
  afterAll(() => {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  // git is given a generous deadline here; the 30 ms production default is exercised below.
  const repoFixture = (gitignore = ".env.local\nconfig/server.p12\n", git = true) => {
    fx = makeFixture({ git: { timeoutMs: 15_000 } });
    fs.mkdirSync(proj(), { recursive: true });
    if (git) execFileSync("git", ["init", "-q"], { cwd: proj(), stdio: "ignore" });
    fx.write("proj/.gitignore", gitignore);
    fx.write("proj/.env.local", "DATABASE_URL=x\n"); // hidden + gitignored
    fx.write("proj/config/server.p12", "x"); // visible + gitignored
    fx.write("proj/src/app.ts", "export {}\n");
    return proj();
  };
  const rg = (args: string) => bash(`rg ${args}`, proj());
  const grepIn = (input: Record<string, unknown> = {}) => grepTool(input, proj());

  it("the reported regression: a gitignored .env.local does not block Grep or rg", () => {
    repoFixture();
    expect(grepIn().code).toBe(0); // no path: the cwd
    expect(grepIn({ path: proj() }).code).toBe(0);
    expect(rg("foo").code).toBe(0);
    expect(rg("foo .").code).toBe(0);
  });

  it("a gitignored file is out of scope until the call lifts ignore rules", () => {
    repoFixture();
    // config/server.p12 is visible but gitignored
    expect(grepIn().code).toBe(0);
    expect(rg("foo").code).toBe(0);
    for (const flag of ["--no-ignore", "-u", "--no-ignore-vcs", "--no-ignore-parent", "-uu"]) {
      expect(rg(`${flag} foo`).code, flag).toBe(2);
    }
    expect(rg("--no-ignore-dot foo").code).toBe(0); // only .ignore/.rgignore lifted
    // …and a lifted ignore still leaves the hidden file hidden
    fs.rmSync(path.join(proj(), "config"), { recursive: true });
    expect(rg("--no-ignore foo").code).toBe(0);
    expect(rg("--no-ignore --hidden foo").code).toBe(2);
    expect(rg("-uu foo").code).toBe(2);
    expect(rg("-uuu foo").code).toBe(2);
    expect(rg("--hidden foo").code).toBe(0); // hidden, but still gitignored
  });

  it("a hidden file that is NOT ignored counts once --hidden opts in", () => {
    repoFixture();
    fx.write("proj/.env.prod", "X=1\n");
    expect(rg("foo").code).toBe(0);
    expect(grepIn().code).toBe(0);
    expect(rg("--hidden foo").code).toBe(2);
    expect(rg("-. foo").code).toBe(2);
    expect(rg("-g '!.env.prod' --hidden foo").code).toBe(0);
  });

  it("a visible, non-ignored backup of an env file counts for Grep and rg", () => {
    repoFixture();
    fx.write("proj/backup/env.bak", "X=1\n");
    const g = grepIn();
    expect(g.code).toBe(2);
    expect(g.stderr).toContain("~/proj/backup/env.bak (environment file backup)");
    expect(rg("foo").code).toBe(2);
    expect(bash("cat backup/env.bak", proj()).code).toBe(2);
    fx.write("proj/notes.bak", "hello\n"); // an ordinary backup is not a credential
    expect(bash("cat notes.bak", proj()).code).toBe(0);
  });

  it("a DIRECT read of a gitignored or hidden file stays denied", () => {
    repoFixture();
    const dotLocal = path.join(proj(), ".env.local");
    expect(check(call("Read", { file_path: dotLocal })).code).toBe(2);
    expect(check(call("Read", { file_path: path.join(proj(), "config", "server.p12") })).code).toBe(
      2,
    );
    expect(grepIn({ path: dotLocal }).code).toBe(2);
    expect(grepIn({ path: ".env.local" }).code).toBe(2);
    expect(rg("foo .env.local").code).toBe(2);
    expect(rg("foo config/server.p12").code).toBe(2);
    expect(rg("-e foo .env.local").code).toBe(2);
    expect(bash("cat .env.local", proj()).code).toBe(2);
    expect(bash("type .env.local", proj()).code).toBe(2);
    expect(bash("Get-Content .env.local", proj()).code).toBe(2);
  });

  it("grep -r, findstr /s, Select-String -Recurse, cat dir/* and gci | sls ignore neither", () => {
    repoFixture();
    expect(bash("grep -r foo .", proj()).code).toBe(2);
    expect(bash("grep -rn foo config", proj()).code).toBe(2);
    expect(bash("findstr /s foo *.*", proj()).code).toBe(2);
    expect(bash("Select-String -Path . -Pattern foo -Recurse", proj()).code).toBe(2);
    expect(bash("Get-ChildItem -Recurse | Select-String foo", proj()).code).toBe(2);
    expect(bash("cat *", proj()).code).toBe(2);
    expect(bash("cat .env*", proj()).code).toBe(2);
    expect(bash("cat config/*", proj()).code).toBe(2);
  });

  it("outside a git work tree there is no gitignore filtering — but hidden files are still skipped", () => {
    repoFixture(".env.local\nconfig/server.p12\n", false);
    expect(grepIn().code).toBe(2); // visible config/server.p12: a .gitignore alone ignores nothing
    expect(rg("foo").code).toBe(2);
    fs.rmSync(path.join(proj(), "config"), { recursive: true });
    expect(grepIn().code).toBe(0); // only the hidden .env.local is left
    expect(rg("foo").code).toBe(0);
    expect(rg("--hidden foo").code).toBe(2);
    expect(bash("grep -r foo .", proj()).code).toBe(2);
  });

  it("fails toward deny when git is missing, errors, or is too slow", () => {
    repoFixture();
    fs.rmSync(path.join(proj(), ".env.local"));
    expect(grepIn().code).toBe(0); // sanity: git says config/server.p12 is ignored

    // git not installed
    fx.env.git = { bin: "git-no-such-binary-here", timeoutMs: 15_000 };
    expect(grepIn().code).toBe(2);
    expect(grepIn().stderr).toContain("could not confirm .gitignore — git unavailable");
    expect(rg("foo").code).toBe(2);
    // a .git that is not a repository: git exits 128
    fx.env.git = { timeoutMs: 15_000 };
    fs.rmSync(path.join(proj(), ".git"), { recursive: true, force: true });
    fs.mkdirSync(path.join(proj(), ".git"));
    expect(grepIn().code).toBe(2);
    // a deadline git cannot meet
    fs.rmSync(path.join(proj(), ".git"), { recursive: true, force: true });
    execFileSync("git", ["init", "-q"], { cwd: proj(), stdio: "ignore" });
    expect(grepIn().code).toBe(0);
    fx.env.git = { timeoutMs: 1 };
    expect(grepIn().code).toBe(2);
    expect(grepIn().stderr).toContain("could not confirm .gitignore — git check-ignore timed out");
  });

  it("gives git a Windows-sized deadline by default", () => {
    expect(GIT_TIMEOUT_MS).toBe(process.platform === "win32" ? 150 : 30);
  });

  it("adds no git note when git answered", () => {
    repoFixture();
    fs.rmSync(path.join(proj(), ".env.local"));
    fx.env.git = { timeoutMs: 15_000 };
    expect(grepIn().code).toBe(0);
    fs.writeFileSync(path.join(proj(), "bundle.p12"), "binary-ish"); // a visible, unignored key bundle
    const r = grepIn();
    expect(r.code).toBe(2);
    expect(r.stderr).not.toContain("could not confirm");
  });

  it("an explicit glob that names a hidden or ignored file brings it back in scope", () => {
    repoFixture();
    for (const glob of [".env.local", "*.local", "*"]) {
      expect(grepIn({ glob }).code, glob).toBe(2);
    }
    expect(grepIn({ glob: "*.ts" }).code).toBe(0);
    expect(rg("-g '.env.local' foo").code).toBe(2);
    expect(rg("-g '*.ts' foo").code).toBe(0);
    expect(rg("-g '*.p12' foo").code).toBe(2); // names the ignored config/server.p12
  });

  it("honours .ignore and .rgignore with a simple glob match", () => {
    repoFixture("", false);
    fs.rmSync(path.join(proj(), "config"), { recursive: true });
    fx.write("proj/keys/server.p12", "x");
    expect(grepIn().code).toBe(2);
    fx.write("proj/.ignore", "*.p12\n");
    expect(grepIn().code).toBe(0);
    expect(rg("foo").code).toBe(0);
    expect(rg("--no-ignore-dot foo").code).toBe(2);
    expect(rg("--no-ignore foo").code).toBe(2);
    expect(bash("grep -r foo .", proj()).code).toBe(2);
    // a directory pattern, an anchored pattern, and a negation in the nearer .rgignore
    fx.write("proj/.ignore", "keys/\n");
    expect(grepIn().code).toBe(0);
    fx.write("proj/.ignore", "/keys/server.p12\n");
    expect(grepIn().code).toBe(0);
    fx.write("proj/.ignore", "/server.p12\n");
    expect(grepIn().code).toBe(2); // anchored at proj/, so keys/server.p12 is not matched
    fx.write("proj/.ignore", "*.p12\n");
    fx.write("proj/keys/.rgignore", "!server.p12\n");
    expect(grepIn().code).toBe(2);
    fs.rmSync(path.join(proj(), "keys", ".rgignore"));
    fx.write("proj/.rgignore", "!*.p12\n"); // .rgignore outranks .ignore
    expect(grepIn().code).toBe(2);
  });

  // 50 ms where git spawns in a few ms; on Windows the spawn alone is 40–120 ms (why
  // GIT_TIMEOUT_MS is 150 there), so the budget is the git deadline plus the walk.
  const budgetMs = process.platform === "win32" ? GIT_TIMEOUT_MS + 50 : 50;

  it("decides within budget, including the git spawn, on a ~2,000-file tree", () => {
    repoFixture();
    for (let d = 0; d < 19; d++) bulk(path.join(proj(), `pkg${d}`), 100, "m");
    const stdin = call("Grep", { pattern: "x" }, proj());
    // with the production deadline git is ~10 ms here; allow the answer to be either way
    const production = { ...fx.env, git: undefined };
    const roomy = { ...fx.env, git: { timeoutMs: 15_000 } };
    expect(runHookCheck(stdin, roomy, proj()).code).toBe(0); // config/server.p12 is gitignored
    const times: number[] = [];
    for (let i = 0; i < 9; i++) {
      const t0 = performance.now();
      runHookCheck(stdin, production, proj());
      times.push(performance.now() - t0);
    }
    times.sort((a, b) => a - b);
    expect(times[Math.floor(times.length / 2)]!).toBeLessThan(budgetMs);
  });
});

describe("hook check — shell directory searches", () => {
  it("denies `grep -r`/`-R` over a directory holding a credential file", () => {
    fx = makeFixture();
    fx.write("proj/.env", "X=1\n");
    fx.write("proj/src/app.ts", "export {}\n");
    for (const cmd of [
      "grep -r token proj",
      "grep -rn token proj",
      "grep -Rin token ~/proj",
      "grep --recursive token proj",
      "grep -d recurse token proj",
      "grep -r -e token proj",
      "egrep -r token proj",
      "sudo grep -r token proj",
      "FOO=1 grep -r token proj",
      "cat x | grep -r token proj",
    ]) {
      expect(bash(cmd).code, cmd).toBe(2);
    }
    expect(bash("grep -r token", proj()).code).toBe(2); // no operand: the cwd
    expect(bash("grep -r token .", proj()).code).toBe(2);
  });

  it("allows grep that is not recursive, or that stays in a clean directory", () => {
    fx = makeFixture();
    fx.write("proj/.env", "X=1\n");
    fx.write("proj/src/app.ts", "export {}\n");
    for (const cmd of [
      "grep token proj/src/app.ts",
      "grep -n token proj/src/app.ts",
      "grep -r token proj/src",
      "grep -r token proj/src proj/src/app.ts",
      "git status",
    ]) {
      expect(bash(cmd).code, cmd).toBe(0);
    }
  });

  it("honours grep --include / --exclude", () => {
    fx = makeFixture();
    fx.write("proj/.env", "X=1\n");
    fx.write("proj/src/app.ts", "export {}\n");
    expect(bash("grep -r token proj --include='*.ts'").code).toBe(0);
    expect(bash("grep -r token proj --include=*.{ts,tsx}").code).toBe(0);
    expect(bash("grep -r token proj --exclude=.env").code).toBe(0);
    expect(bash("grep -r token proj --exclude .env").code).toBe(0);
    expect(bash("grep -r token proj --include='*.env'").code).toBe(2);
    expect(bash("grep -r token proj --exclude='*.md'").code).toBe(2);
    expect(bash("grep -r token proj").stderr).toContain("--exclude=.env");
  });

  it("treats rg like ripgrep: dot-files are skipped unless --hidden / -uu / -.", () => {
    fx = makeFixture();
    fx.write("proj/.env", "X=1\n");
    fx.write("proj/src/app.ts", "export {}\n");
    expect(bash("rg token proj").code).toBe(0); // ripgrep would not read .env
    for (const cmd of [
      "rg --hidden token proj",
      "rg -uu token proj",
      "rg -. token proj",
      "rg -uuu token proj",
    ]) {
      expect(bash(cmd).code, cmd).toBe(2);
    }
    expect(bash("rg --hidden -g '!.env' token proj").code).toBe(0);
    expect(bash("rg --hidden --glob '*.ts' token proj").code).toBe(0);
    expect(bash("rg --hidden -t ts token proj").code).toBe(0);
    expect(bash("rg --hidden -T ts token proj").code).toBe(2);
  });

  it("denies rg over non-hidden credential files, with globs and types honoured", () => {
    fx = makeFixture();
    fx.write("proj/secrets/server.p12", "x");
    fx.write("proj/src/app.ts", "export {}\n");
    expect(bash("rg token proj").code).toBe(2);
    expect(bash("rg token", proj()).code).toBe(2);
    expect(bash("rg -e token proj").code).toBe(2);
    expect(bash("rg -e token", proj()).code).toBe(2);
    expect(bash("rg token proj").stderr).toContain("rg --glob '!server.p12'");
    expect(bash("rg -g '!*.p12' token proj").code).toBe(0);
    expect(bash("rg -g '*.ts' token proj").code).toBe(0);
    expect(bash("rg --glob=*.{ts,tsx} token proj").code).toBe(0);
    expect(bash("rg -t ts token proj").code).toBe(0);
    expect(bash("rg -tts token proj").code).toBe(0);
    expect(bash("rg --type-not ts token proj").code).toBe(2);
    expect(bash("rg token proj/src").code).toBe(0);
    expect(bash("rg --files proj").code).toBe(0); // lists names, reads nothing
    expect(bash("echo x | rg token").code).toBe(0); // searches stdin
    expect(bash("echo x | rg token proj").code).toBe(2); // …unless it is given a path
  });

  it("denies `findstr /s` over a tree, by file spec", () => {
    fx = makeFixture();
    fx.write("proj/.env", "X=1\n");
    fx.write("proj/src/app.ts", "export {}\n");
    expect(bash("findstr /s /i password *.*", proj()).code).toBe(2);
    expect(bash("findstr /S password *", proj()).code).toBe(2);
    expect(bash("findstr /s /c:token proj\\*").code).toBe(2);
    expect(bash("findstr /s password *.ts", proj()).code).toBe(0);
    expect(bash("findstr /s /c:token proj\\*.ts").code).toBe(0);
    expect(bash("findstr /s /c:token proj\\src\\*").code).toBe(0);
    expect(bash("findstr token proj\\src\\app.ts").code).toBe(0);
  });

  it("denies Select-String -Recurse and a recursive Get-ChildItem piped to a reader", () => {
    fx = makeFixture();
    fx.write("proj/.env", "X=1\n");
    fx.write("proj/src/app.ts", "export {}\n");
    expect(bash("Select-String -Path proj -Pattern token -Recurse").code).toBe(2);
    expect(bash("sls token proj -r").code).toBe(2);
    expect(bash("Select-String -Path:proj -Pattern token -Recurse").code).toBe(2);
    expect(bash("Select-String -Path proj -Pattern token -Recurse -Include *.ts,*.tsx").code).toBe(
      0,
    );
    expect(bash("Select-String -Path proj\\src -Pattern token -Recurse").code).toBe(0);
    expect(bash("Get-ChildItem -Recurse proj | Select-String token").code).toBe(2);
    expect(bash("gci -r | sls token", proj()).code).toBe(2);
    expect(bash("gci proj -Recurse | Get-Content").code).toBe(2);
    expect(bash("gci -Recurse -Filter *.ts | sls token", proj()).code).toBe(0);
    expect(bash("gci -Recurse -Include *.ts | sls token", proj()).code).toBe(0);
    expect(bash("Get-ChildItem -Recurse proj | Measure-Object").code).toBe(0); // reads nothing
    expect(bash("Select-String -Path proj\\src\\app.ts -Pattern token").code).toBe(0);
  });

  it("names the files a wildcard like `cat dir/*` would read", () => {
    fx = makeFixture();
    fx.write("proj/.env", "X=1\n");
    fx.write("proj/.env.local", "X=1\n");
    fx.write("proj/src/app.ts", "export {}\n");
    const r = bash("cat proj/*");
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("~/proj/.env (environment file)");
    expect(r.stderr).toContain("~/proj/.env.local (environment file)");
    expect(r.stderr).toContain("narrower pattern");
    expect(bash("cat proj/src/*").code).toBe(0);
    expect(bash("Get-Content proj\\*").code).toBe(2);
    expect(bash("type proj\\src\\*").code).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 3. Pure parsing
// ---------------------------------------------------------------------------

describe("tokenizeSegments", () => {
  it("splits on separators and marks piped segments", () => {
    expect(tokenizeSegments("a x | b y || c; d && e")).toEqual([
      { words: ["a", "x"], piped: false },
      { words: ["b", "y"], piped: true },
      { words: ["c"], piped: false },
      { words: ["d"], piped: false },
      { words: ["e"], piped: false },
    ]);
    expect(tokenizeSegments("echo 'a | b' | cat")).toEqual([
      { words: ["echo", "a | b"], piped: false },
      { words: ["cat"], piped: true },
    ]);
    expect(tokenizeSegments("")).toEqual([]);
  });
});

describe("detectShellSearches", () => {
  it("reads grep operands, skipping the pattern and option values", () => {
    expect(detectShellSearches("grep -rn -m 5 -A2 pattern a b")[0]).toMatchObject({
      tool: "grep",
      dirs: ["a", "b"],
    });
    expect(detectShellSearches("grep -r -e p1 -e p2 a")[0]!.dirs).toEqual(["a"]);
    expect(detectShellSearches("grep pattern a")).toEqual([]); // not recursive
  });
  it("reads rg operands, globs and types", () => {
    const [r] = detectShellSearches("rg -g '!*.p12' -g '*.ts' -t py -j 4 pattern a");
    expect(r).toMatchObject({
      dirs: ["a"],
      include: ["*.ts"],
      exclude: ["*.p12"],
      types: ["py"],
      skipHidden: true,
    });
    expect(detectShellSearches("rg --hidden p")[0]!.skipHidden).toBe(false);
  });
  it("ignores unrelated commands", () => {
    expect(detectShellSearches("ls -la && git status | wc -l")).toEqual([]);
  });
});

describe("globs", () => {
  it("expands braces and splits a glob list", () => {
    expect(expandBraces("*.{ts,tsx}")).toEqual(["*.ts", "*.tsx"]);
    expect(expandBraces("{a,b}/{c,d}")).toEqual(["a/c", "a/d", "b/c", "b/d"]);
    expect(splitGlobs("*.{ts,tsx} !dist")).toEqual(["*.ts", "*.tsx", "!dist"]);
    expect(grepToolRequest({ glob: "*.ts !x", path: "p", type: "ts" })).toMatchObject({
      dirs: ["p"],
      include: ["*.ts"],
      exclude: ["x"],
      types: ["ts"],
    });
  });
  it("makeFilter: positive globs are case-insensitive, negative ones are not", () => {
    const excluded = makeFilter({
      tool: "x",
      dirs: [],
      include: [],
      exclude: ["*.p12"],
      types: [],
      typesNot: [],
      skipHidden: false,
      ignore: { vcs: false, dot: false },
    });
    expect(excluded("a/b.p12")).toBe(true);
    expect(excluded("a/b.P12")).toBe(false);
    const wanted = makeFilter({
      tool: "x",
      dirs: [],
      include: ["*.TS"],
      exclude: [],
      types: [],
      typesNot: [],
      skipHidden: false,
      ignore: { vcs: false, dot: false },
    });
    expect(wanted("a/b.ts")).toBe(false);
    expect(wanted("a/.env")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 4. Installing the wider matcher
// ---------------------------------------------------------------------------

describe("hook install — matcher upgrade", () => {
  it("covers MultiEdit, NotebookEdit and the PowerShell tool", () => {
    for (const tool of [
      "Read",
      "Bash",
      "PowerShell",
      "Grep",
      "Edit",
      "MultiEdit",
      "NotebookEdit",
    ]) {
      expect(HOOK_MATCHER.split("|")).toContain(tool);
    }
  });

  it("upgrades an entry installed with the old matcher in place", () => {
    fx = makeFixture();
    const file = settingsPath("user", fx.env, fx.home);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(
      file,
      JSON.stringify({
        model: "opus",
        hooks: {
          PreToolUse: [
            { matcher: "Write", hooks: [{ type: "command", command: "my-linter" }] },
            {
              matcher: "Read|Bash|Grep|Edit",
              hooks: [{ type: "command", command: "repo-wrapped-sweep hook check" }],
            },
          ],
        },
      }),
    );
    expect(installHook(file).changed).toBe(true);
    const s = JSON.parse(fs.readFileSync(file, "utf8"));
    expect(s.model).toBe("opus");
    expect(s.hooks.PreToolUse).toHaveLength(2);
    expect(s.hooks.PreToolUse[0].matcher).toBe("Write");
    expect(s.hooks.PreToolUse[1]).toEqual({
      matcher: HOOK_MATCHER,
      hooks: [{ type: "command", command: "repo-wrapped-sweep hook check" }],
    });
    expect(installHook(file).changed).toBe(false); // and it is stable afterwards
  });
});
