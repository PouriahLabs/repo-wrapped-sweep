// `disk clean` (Phase C3) — one test per safety rule in ENDPOINT-MACHINE-INSIGHTS § C8 (C3)
// and decision C9.4. Everything runs in a tmp dir with an injected home and config dir;
// nothing here touches the real home. Package-manager binaries are stubs on a fake PATH
// that only RECORD their argv — the real pnpm/npm/yarn never run.

import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { main, type CliIO } from "../src/cli";
import { loadMdmConfig } from "../src/device";
import {
  gitGuard,
  parseOlderThan,
  planClean,
  removeTarget,
  removeTree,
  vetTarget,
  type CleanTarget,
} from "../src/insights/clean";
import type { DiskCollection } from "../src/insights/disk";
import { scheduledArgs } from "../src/schedule";
import { readDiskReclaimed } from "../src/wrapped";
import { captureIO, makeFixture, type Fixture } from "./helpers";
import { DAY_MS, age, ageTopFiles, gitIn, initRepo, put } from "./insights-fixture";

let fx: Fixture;
afterEach(() => fx?.cleanup());

const NOW = Date.now();
const OLD = NOW - 60 * DAY_MS;

/** A directory junction on Windows (no privilege needed), a dir symlink elsewhere. */
function junction(target: string, link: string): void {
  fs.mkdirSync(path.dirname(link), { recursive: true });
  fs.symlinkSync(target, link, "junction");
}

const exists = (p: string) => {
  try {
    fs.lstatSync(p);
    return true;
  } catch {
    return false;
  }
};

interface Tree {
  /** git, pnpm lockfile, node_modules (with two junctions + a read-only file), dist/. Old. */
  a: string;
  /** not git, package-lock + .next. Old. */
  b: string;
  /** pyproject + __pycache__ + .venv. Old, not git. */
  py: string;
  /** git; target/ holds a COMMITTED file. Old. */
  rustTracked: string;
  /** git; target/ is not ignored, so git sees it as untracked. Old. */
  rustUntracked: string;
  /** git, lockfile, node_modules — committed today. */
  fresh: string;
  /** Outside home: the junction targets that must survive. */
  sentinelOutside: string;
  /** Inside home but outside any target: also a junction target that must survive. */
  sentinelInside: string;
  /** Bytes of real files under a/node_modules (junction targets excluded). */
  aNodeModulesBytes: number;
}

function buildTree(f: Fixture): Tree {
  const code = path.join(f.home, "code");

  const sentinelOutside = path.join(f.root, "sentinel-outside");
  put(path.join(sentinelOutside, "keep.txt"), "must survive\n");
  const sentinelInside = path.join(f.home, "important");
  put(path.join(sentinelInside, "keep.txt"), "must survive too\n");

  const a = path.join(code, "a");
  put(path.join(a, "package.json"), '{"name":"a"}\n');
  put(path.join(a, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
  put(path.join(a, ".gitignore"), "node_modules\ndist\n");
  put(path.join(a, "index.js"), "console.log(1)\n");
  initRepo(f, a, OLD);
  put(path.join(a, "node_modules", ".pnpm", "dep@1", "index.js"), Buffer.alloc(4096, 1));
  const ro = put(path.join(a, "node_modules", ".pnpm", "dep@1", "ro.js"), Buffer.alloc(100, 2));
  fs.chmodSync(ro, 0o444);
  // pnpm-style links: junctions pointing out of the folder being deleted.
  junction(sentinelOutside, path.join(a, "node_modules", "outside-link"));
  junction(sentinelInside, path.join(a, "node_modules", "inside-link"));
  put(path.join(a, "dist", "bundle.js"), "x".repeat(100));
  ageTopFiles(a, OLD);
  age(path.join(a, "node_modules"), OLD);

  const b = path.join(code, "b");
  put(path.join(b, "package.json"), '{"name":"b"}\n');
  put(path.join(b, "package-lock.json"), "{}\n");
  put(path.join(b, ".next", "cache", "x.bin"), Buffer.alloc(2048));
  put(path.join(b, "out", "index.html"), "<p>static export</p>");
  ageTopFiles(b, OLD);
  age(path.join(b, ".next"), OLD);

  const py = path.join(code, "py");
  put(path.join(py, "pyproject.toml"), '[project]\nname = "py"\n');
  put(path.join(py, "__pycache__", "m.pyc"), Buffer.alloc(512));
  put(path.join(py, ".venv", "lib", "site.py"), Buffer.alloc(256));
  ageTopFiles(py, OLD);
  age(path.join(py, "__pycache__"), OLD);
  age(path.join(py, ".venv"), OLD);

  const rustTracked = path.join(code, "rust-tracked");
  put(path.join(rustTracked, "Cargo.toml"), '[package]\nname = "t"\n');
  put(path.join(rustTracked, "target", "keep.bin"), Buffer.alloc(64));
  initRepo(f, rustTracked, OLD); // commits target/keep.bin too
  ageTopFiles(rustTracked, OLD);
  age(path.join(rustTracked, "target"), OLD);

  const rustUntracked = path.join(code, "rust-untracked");
  put(path.join(rustUntracked, "Cargo.toml"), '[package]\nname = "u"\n');
  initRepo(f, rustUntracked, OLD);
  put(path.join(rustUntracked, "target", "debug", "u"), Buffer.alloc(128));
  ageTopFiles(rustUntracked, OLD);
  age(path.join(rustUntracked, "target"), OLD);

  const fresh = path.join(code, "fresh");
  put(path.join(fresh, "package.json"), '{"name":"fresh"}\n');
  put(path.join(fresh, "yarn.lock"), "\n");
  put(path.join(fresh, ".gitignore"), "node_modules\n");
  initRepo(f, fresh, NOW);
  put(path.join(fresh, "node_modules", "dep", "index.js"), Buffer.alloc(1000));

  return {
    a,
    b,
    py,
    rustTracked,
    rustUntracked,
    fresh,
    sentinelOutside,
    sentinelInside,
    aNodeModulesBytes: 4096 + 100,
  };
}

/** Stub package managers that only append their argv to `<bin>/calls.log`. */
function stubRecorders(binDir: string, names: string[]): string {
  fs.mkdirSync(binDir, { recursive: true });
  const log = path.join(binDir, "calls.log");
  for (const name of names) {
    if (process.platform === "win32") {
      fs.writeFileSync(
        path.join(binDir, `${name}.cmd`),
        `@echo off\r\necho ${name} %*>> "${log}"\r\n`,
      );
    } else {
      const file = path.join(binDir, name);
      fs.writeFileSync(file, `#!/bin/sh\necho "${name} $*" >> '${log}'\n`);
      fs.chmodSync(file, 0o755);
    }
  }
  return log;
}

function setup(): Tree {
  fx = makeFixture();
  const bin = path.join(fx.root, "bin");
  fs.mkdirSync(bin, { recursive: true });
  // An empty PATH by default: no prune can run unless a test stubs it.
  fx.env.processEnv =
    process.platform === "win32" ? { PATH: bin, PATHEXT: ".COM;.EXE;.BAT;.CMD" } : { PATH: bin };
  return buildTree(fx);
}

async function run(args: string[], extra: Partial<CliIO> = {}) {
  const io = { ...captureIO(), interactive: false, ...extra };
  const code = await main(args, io, fx.env);
  return { code, out: io.out(), err: io.err() };
}

const display = (abs: string) => `~${abs.slice(fx.home.length).replace(/\\/g, "/")}`;

function readLog(): Array<{
  path: string;
  bytes: number;
  time: string;
  cls: string;
  tool?: string;
}> {
  const file = path.join(fx.env.configDir, "clean-log.jsonl");
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

// ---------------------------------------------------------------------------

describe("disk clean: dry run by default", () => {
  it("non-interactive without --yes prints exactly what would go and the total, deletes nothing", async () => {
    const t = setup();
    const r = await run(["disk", "clean"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("DRY RUN");
    expect(r.out).toContain(display(path.join(t.a, "node_modules")));
    expect(r.out).toContain(display(path.join(t.b, ".next")));
    expect(r.out).toContain(display(path.join(t.py, "__pycache__")));
    // 4096 + 100 (a/node_modules) + 2048 (b/.next) + 512 (py/__pycache__) bytes.
    expect(r.out).toMatch(/Total: 7 KB in 3 folders across 3 projects/);
    expect(r.out).toContain("Re-run with --yes");
    // Nothing deleted, nothing logged.
    for (const p of [
      path.join(t.a, "node_modules"),
      path.join(t.b, ".next"),
      path.join(t.py, "__pycache__"),
    ]) {
      expect(exists(p)).toBe(true);
    }
    expect(readLog()).toEqual([]);
  });

  it("--json dry run lists the plan with home-relative paths and skip reasons", async () => {
    const t = setup();
    const r = await run(["disk", "clean", "--json"]);
    const j = JSON.parse(r.out);
    expect(j).toMatchObject({ kind: "disk-clean", mode: "dry-run", olderThanDays: 30 });
    expect(j.remove.map((x: { path: string }) => x.path).sort()).toEqual(
      [
        display(path.join(t.a, "node_modules")),
        display(path.join(t.b, ".next")),
        display(path.join(t.py, "__pycache__")),
      ].sort(),
    );
    const reasons = Object.fromEntries(
      j.skipped.map((s: { path: string; reason: string }) => [s.path, s.reason]),
    );
    expect(reasons[display(path.join(t.py, ".venv"))]).toBe("venv");
    expect(reasons[display(path.join(t.fresh, "node_modules"))]).toBe("recent");
    expect(reasons[display(path.join(t.rustTracked, "target"))]).toBe("tracked");
    expect(reasons[display(path.join(t.rustUntracked, "target"))]).toBe("uncommitted");
    expect(r.out).not.toContain(JSON.stringify(fx.home).slice(1, -1));
  });

  it("--dry-run wins over --yes", async () => {
    const t = setup();
    const r = await run(["disk", "clean", "--yes", "--dry-run"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("DRY RUN");
    expect(exists(path.join(t.a, "node_modules"))).toBe(true);
  });
});

describe("disk clean --yes", () => {
  it("deletes only eligible classes, keeps everything else, and logs path/bytes/time", async () => {
    const t = setup();
    const r = await run(["disk", "clean", "--yes"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("Freed");

    // Deleted: stale, proven, clean in git.
    expect(exists(path.join(t.a, "node_modules"))).toBe(false);
    expect(exists(path.join(t.b, ".next"))).toBe(false);
    expect(exists(path.join(t.py, "__pycache__"))).toBe(false);

    // Kept: dist/ and out/ (never), .venv (no opt-in), fresh project, git-tracked and
    // git-visible targets, and every source file.
    expect(exists(path.join(t.a, "dist", "bundle.js"))).toBe(true);
    expect(exists(path.join(t.b, "out", "index.html"))).toBe(true);
    expect(exists(path.join(t.py, ".venv", "lib", "site.py"))).toBe(true);
    expect(exists(path.join(t.fresh, "node_modules", "dep", "index.js"))).toBe(true);
    expect(exists(path.join(t.rustTracked, "target", "keep.bin"))).toBe(true);
    expect(exists(path.join(t.rustUntracked, "target", "debug", "u"))).toBe(true);
    for (const f of ["package.json", "pnpm-lock.yaml", "index.js", ".gitignore"]) {
      expect(exists(path.join(t.a, f))).toBe(true);
    }
    expect(exists(path.join(t.py, "pyproject.toml"))).toBe(true);

    // Log: one line per deleted folder, absolute path, bytes, ISO time.
    const log = readLog();
    expect(log.map((e) => e.path).sort()).toEqual(
      [
        path.join(t.a, "node_modules"),
        path.join(t.b, ".next"),
        path.join(t.py, "__pycache__"),
      ].sort(),
    );
    const aEntry = log.find((e) => e.path === path.join(t.a, "node_modules"))!;
    expect(aEntry.bytes).toBe(t.aNodeModulesBytes);
    expect(aEntry.cls).toBe("node-modules");
    expect(Number.isFinite(Date.parse(aEntry.time))).toBe(true);
    // Machine Wrapped reads the same log.
    expect(readDiskReclaimed(fx.env, NOW - DAY_MS, Date.now() + DAY_MS)).toBe(
      t.aNodeModulesBytes + 2048 + 512,
    );
  });

  it("never follows a junction/symlink inside a target: the sentinels it points at survive", async () => {
    const t = setup();
    await run(["disk", "clean", "--yes"]);
    expect(exists(path.join(t.a, "node_modules"))).toBe(false);
    expect(fs.readFileSync(path.join(t.sentinelOutside, "keep.txt"), "utf8")).toBe(
      "must survive\n",
    );
    expect(fs.readFileSync(path.join(t.sentinelInside, "keep.txt"), "utf8")).toBe(
      "must survive too\n",
    );
    // The link targets were never even counted.
    const log = readLog();
    expect(log.find((e) => e.path === path.join(t.a, "node_modules"))!.bytes).toBe(
      t.aNodeModulesBytes,
    );
  });

  it("--include-venv also removes .venv", async () => {
    const t = setup();
    await run(["disk", "clean", "--yes", "--include-venv"]);
    expect(exists(path.join(t.py, ".venv"))).toBe(false);
    expect(exists(path.join(t.py, "pyproject.toml"))).toBe(true);
  });

  it("--older-than moves the window; a project inside it is kept", async () => {
    const t = setup();
    const r = await run(["disk", "clean", "--yes", "--older-than", "90d"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("Nothing deleted");
    expect(exists(path.join(t.a, "node_modules"))).toBe(true);
    expect(readLog()).toEqual([]);
    expect(parseOlderThan("8w")).toBe(56);
    expect(parseOlderThan("30")).toBe(30);
    expect(parseOlderThan(undefined)).toBe(30);
    expect(parseOlderThan("0d")).toBeNull();
    expect(parseOlderThan("soon")).toBeNull();
    expect((await run(["disk", "clean", "--older-than", "soon"])).code).toBe(2);
  });

  it("a freshly regenerated folder in an old project is kept (the folder's own mtime counts)", async () => {
    const t = setup();
    age(path.join(t.a, "node_modules"), NOW); // e.g. `pnpm install` just ran
    await run(["disk", "clean", "--yes"]);
    expect(exists(path.join(t.a, "node_modules"))).toBe(true);
  });

  it("only next to the proving sibling: node_modules with no lockfile is not a candidate", async () => {
    fx = makeFixture();
    const p = path.join(fx.home, "code", "nolock");
    put(path.join(p, "package.json"), "{}\n");
    put(path.join(p, "node_modules", "x.js"), "x");
    put(path.join(p, "build", "y.class"), "y"); // build/ without a Gradle file
    put(path.join(p, "target", "z"), "z"); // target/ without Cargo.toml
    ageTopFiles(p, OLD);
    for (const d of ["node_modules", "build", "target"]) age(path.join(p, d), OLD);
    const r = await run(["disk", "clean", "--yes"]);
    expect(r.code).toBe(0);
    for (const d of ["node_modules", "build", "target"]) expect(exists(path.join(p, d))).toBe(true);
  });

  it("refuses anything outside the home directory, even when named with --root", async () => {
    fx = makeFixture();
    const outside = path.join(fx.root, "elsewhere", "proj");
    put(path.join(outside, "package.json"), "{}\n");
    put(path.join(outside, "package-lock.json"), "{}\n");
    put(path.join(outside, "node_modules", "x.js"), "x");
    ageTopFiles(outside, OLD);
    age(path.join(outside, "node_modules"), OLD);
    const r = await run([
      "disk",
      "clean",
      "--yes",
      "--all",
      "--root",
      path.join(fx.root, "elsewhere"),
    ]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("outside the home directory");
    expect(exists(path.join(outside, "node_modules", "x.js"))).toBe(true);
  });
});

describe("disk clean: interactive and non-interactive", () => {
  it("at a TTY without --yes it asks per project and acts only on a yes", async () => {
    const t = setup();
    const asked: string[] = [];
    const prompt = {
      async confirm(q: string) {
        asked.push(q);
        return q.includes("/code/b"); // only project b
      },
    };
    const r = await run(["disk", "clean"], { interactive: true, prompt });
    expect(r.code).toBe(0);
    expect(asked).toHaveLength(3); // a, b, py — one question per project
    expect(asked.some((q) => q.includes("/code/a") && q.includes("node_modules"))).toBe(true);
    expect(exists(path.join(t.b, ".next"))).toBe(false);
    expect(exists(path.join(t.a, "node_modules"))).toBe(true);
    expect(exists(path.join(t.py, "__pycache__"))).toBe(true);
    expect(readLog().map((e) => e.path)).toEqual([path.join(t.b, ".next")]);
  });

  it("non-TTY without --yes never asks and never deletes", async () => {
    const t = setup();
    let asked = 0;
    const prompt = {
      async confirm() {
        asked++;
        return true;
      },
    };
    const r = await run(["disk", "clean"], { interactive: false, prompt });
    expect(r.out).toContain("DRY RUN");
    expect(asked).toBe(0);
    expect(exists(path.join(t.a, "node_modules"))).toBe(true);
  });
});

describe("disk clean never runs from schedule or MDM", () => {
  it("refuses --scheduled outright, even with --yes", async () => {
    const t = setup();
    const r = await run(["disk", "clean", "--yes", "--scheduled"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("never runs from a scheduled");
    expect(exists(path.join(t.a, "node_modules"))).toBe(true);
    expect(readLog()).toEqual([]);
  });

  it("the scheduled invocation is a plain sweep that cannot reach disk clean", async () => {
    const t = setup();
    for (const upload of [false, true]) {
      const args = scheduledArgs({ upload });
      expect(args).not.toContain("disk");
      expect(args).not.toContain("clean");
      expect(args).not.toContain("--yes");
    }
    const r = await run([...scheduledArgs({ upload: false }), "--no-update", "--fail-on", "none"]);
    expect(r.code).toBe(0);
    expect(exists(path.join(t.a, "node_modules"))).toBe(true);
    expect(readLog()).toEqual([]);
  });

  it("an MDM config cannot ask for a clean, and an MDM-driven sweep deletes nothing", async () => {
    const t = setup();
    const mdm = path.join(fx.root, "mdm", "sweep.json");
    put(
      mdm,
      JSON.stringify({ schedule: false, upload: false, clean: true, diskClean: true, yes: true }),
    );
    fx.env.mdmConfigPath = mdm;
    const cfg = loadMdmConfig(fx.env)!;
    expect(Object.keys(cfg).sort()).toEqual(["schedule", "upload"]);
    const r = await run(["--no-update", "--fail-on", "none", "--quiet"]);
    expect(r.code).toBe(0);
    expect(exists(path.join(t.a, "node_modules"))).toBe(true);
    expect(readLog()).toEqual([]);
  });

  it("only the CLI dispatcher imports the clean module (not schedule, scan, upload or MDM code)", () => {
    const srcDir = path.join(__dirname, "..", "src");
    const importers: string[] = [];
    const walkSrc = (d: string) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const abs = path.join(d, e.name);
        if (e.isDirectory()) walkSrc(abs);
        else if (
          /\.ts$/.test(e.name) &&
          /from "\.{1,2}\/(?:insights\/)?clean"/.test(fs.readFileSync(abs, "utf8"))
        ) {
          importers.push(path.relative(srcDir, abs).replace(/\\/g, "/"));
        }
      }
    };
    walkSrc(srcDir);
    expect(importers).toEqual(["cli.ts"]);
    // …and the dispatcher reaches it only for the literal `disk clean` positionals.
    const cli = fs.readFileSync(path.join(srcDir, "cli.ts"), "utf8");
    expect(cli.match(/runDiskClean\(/g)).toHaveLength(2); // definition + one call
    expect(cli).toContain('if (command === "disk" && positionals[1] === "clean")');
  });
});

describe("disk clean: package caches via the tool's own prune, never rm", () => {
  function withCaches() {
    const t = setup();
    put(path.join(fx.home, ".local", "share", "pnpm", "store", "v3", "blob"), Buffer.alloc(3000));
    put(path.join(fx.home, ".npm", "_cacache", "index"), Buffer.alloc(2000));
    put(path.join(fx.home, ".cache", "yarn", "pkg"), Buffer.alloc(1000));
    put(path.join(fx.home, ".gradle", "caches", "jar"), Buffer.alloc(500));
    const calls = stubRecorders(path.join(fx.root, "bin"), ["pnpm", "npm", "yarn"]);
    return { t, calls };
  }

  it("dry run lists the prune commands; npm needs --include-npm-cache; Gradle is report-only", async () => {
    const { calls } = withCaches();
    const r = await run(["disk", "clean"]);
    expect(r.out).toContain("pnpm store prune");
    expect(r.out).toContain("yarn cache clean");
    expect(r.out).toContain("npm's cache is cleaned only with --include-npm-cache");
    expect(r.out).toContain("Gradle caches");
    expect(r.out).toContain("has no prune command");
    expect(fs.existsSync(calls)).toBe(false); // nothing ran
  });

  it("--yes runs pnpm store prune and yarn cache clean, not npm, and deletes no cache file itself", async () => {
    const { calls } = withCaches();
    const r = await run(["disk", "clean", "--yes"]);
    expect(r.code).toBe(0);
    const ran = fs
      .readFileSync(calls, "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    expect(ran.sort()).toEqual(["pnpm store prune", "yarn cache clean"]);
    // The stubs delete nothing, and neither do we: every cache file is still there.
    for (const p of [
      [".local", "share", "pnpm", "store", "v3", "blob"],
      [".npm", "_cacache", "index"],
      [".cache", "yarn", "pkg"],
      [".gradle", "caches", "jar"],
    ]) {
      expect(exists(path.join(fx.home, ...p))).toBe(true);
    }
    const log = readLog().filter((e) => e.cls === "package-cache");
    expect(log.map((e) => e.tool).sort()).toEqual(["pnpm", "yarn"]);
    expect(log.every((e) => e.bytes === 0)).toBe(true); // measured, nothing freed
  });

  it("--include-npm-cache adds npm cache clean --force", async () => {
    const { calls } = withCaches();
    await run(["disk", "clean", "--yes", "--include-npm-cache"]);
    const ran = fs.readFileSync(calls, "utf8");
    expect(ran).toContain("npm cache clean --force");
  });

  it("a tool not on PATH is skipped, not replaced by rm", async () => {
    setup();
    const store = put(path.join(fx.home, ".local", "share", "pnpm", "store", "v3", "blob"), "x");
    const r = await run(["disk", "clean", "--yes"]);
    expect(r.out).toContain("its tool is not on PATH");
    expect(exists(store)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Guards, unit level
// ---------------------------------------------------------------------------

describe("vetTarget / removeTarget", () => {
  function proj(name: string, root = path.join(fx.home, "code")) {
    const p = path.join(root, name);
    put(path.join(p, "package.json"), "{}\n");
    put(path.join(p, "package-lock.json"), "{}\n");
    return p;
  }
  const target = (
    p: string,
    rel = "node_modules",
    cls: CleanTarget["cls"] = "node-modules",
  ): CleanTarget => ({
    path: path.join(p, rel),
    cls,
    project: p,
    bytes: 0,
    partial: false,
    lastTouched: OLD,
  });

  it("refuses a target that IS a junction/symlink, and leaves its target alone", async () => {
    fx = makeFixture();
    const p = proj("linked-nm");
    const sentinel = path.join(fx.root, "sentinel");
    put(path.join(sentinel, "keep.txt"), "keep");
    junction(sentinel, path.join(p, "node_modules"));
    expect(vetTarget(path.join(p, "node_modules"), p, "node-modules", fx.env)).toBe("link");
    const r = await removeTarget(target(p), fx.env);
    expect(r.refused).toBe("link");
    expect(exists(path.join(p, "node_modules"))).toBe(true);
    expect(exists(path.join(sentinel, "keep.txt"))).toBe(true);
  });

  it("refuses a target whose realpath leaves home (project reached through a junction)", async () => {
    fx = makeFixture();
    const real = proj("real", path.join(fx.root, "outside"));
    put(path.join(real, "node_modules", "keep.js"), "keep");
    const via = path.join(fx.home, "code", "via");
    junction(real, via);
    expect(vetTarget(path.join(via, "node_modules"), via, "node-modules", fx.env)).toBe("escapes");
    const r = await removeTarget(target(via), fx.env);
    expect(r.refused).toBe("escapes");
    expect(exists(path.join(real, "node_modules", "keep.js"))).toBe(true);
  });

  it("refuses a nested class folder reached through a link (.vercel → elsewhere)", () => {
    fx = makeFixture();
    const p = proj("vercel");
    const elsewhere = path.join(fx.root, "vercel-real");
    put(path.join(elsewhere, "output", "keep.txt"), "keep");
    junction(elsewhere, path.join(p, ".vercel"));
    expect(vetTarget(path.join(p, ".vercel", "output"), p, "next-build", fx.env)).toBe("link");
  });

  it("refuses targets outside home, dist/out, missing proof, and a nested git repo", async () => {
    fx = makeFixture();
    const out = proj("o", path.join(fx.root, "outside"));
    put(path.join(out, "node_modules", "x"), "x");
    expect(vetTarget(path.join(out, "node_modules"), out, "node-modules", fx.env)).toBe(
      "outside-home",
    );

    const p = proj("p");
    put(path.join(p, "dist", "x"), "x");
    expect(vetTarget(path.join(p, "dist"), p, "next-build", fx.env)).toBe("report-only");
    put(path.join(p, "out", "x"), "x");
    expect(vetTarget(path.join(p, "out"), p, "next-build", fx.env)).toBe("report-only");

    put(path.join(p, "node_modules", "x"), "x");
    expect(vetTarget(path.join(p, "node_modules"), p, "node-modules", fx.env)).toBeNull();
    fs.rmSync(path.join(p, "package-lock.json"));
    // The lockfile went away after the plan: refused at the last moment.
    const r = await removeTarget(target(p), fx.env);
    expect(r.refused).toBe("no-proof");
    expect(exists(path.join(p, "node_modules", "x"))).toBe(true);

    const q = proj("q");
    put(path.join(q, "node_modules", ".git", "HEAD"), "ref: refs/heads/main\n");
    expect(vetTarget(path.join(q, "node_modules"), q, "node-modules", fx.env)).toBe("nested-repo");

    expect(vetTarget(path.join(q, "gone"), q, "node-modules", fx.env)).toBe("missing");
  });

  it("gitGuard: tracked, untracked-visible, ignored, and git unavailable", async () => {
    fx = makeFixture();
    const repo = path.join(fx.home, "code", "repo");
    put(path.join(repo, "Cargo.toml"), "[package]\n");
    put(path.join(repo, ".gitignore"), "/ignored-target\n");
    put(path.join(repo, "tracked-target", "a"), "a");
    initRepo(fx, repo, OLD);
    put(path.join(repo, "loose-target", "b"), "b");
    put(path.join(repo, "ignored-target", "c"), "c");
    put(path.join(repo, "[odd]", "d"), "d"); // a literal pathspec, not a glob
    gitIn(fx, repo, ["add", "-f", "[odd]/d"]);
    gitIn(fx, repo, ["commit", "-q", "-m", "odd"]);
    put(path.join(repo, "o", "e"), "e");

    expect(await gitGuard(path.join(repo, "tracked-target"), fx.env)).toBe("tracked");
    expect(await gitGuard(path.join(repo, "loose-target"), fx.env)).toBe("uncommitted");
    expect(await gitGuard(path.join(repo, "ignored-target"), fx.env)).toBeNull();
    expect(await gitGuard(path.join(repo, "[odd]"), fx.env)).toBe("tracked");
    // `[odd]` as a literal path: the untracked folder `o` must not match it as a glob.
    expect(await gitGuard(path.join(repo, "o"), fx.env)).toBe("uncommitted");

    // A modified tracked file is caught too.
    fs.writeFileSync(path.join(repo, "tracked-target", "a"), "changed");
    expect(await gitGuard(path.join(repo, "tracked-target"), fx.env)).toBe("tracked");

    // Not in a repo: nothing to check.
    const loose = path.join(fx.home, "code", "loose");
    put(path.join(loose, "target", "z"), "z");
    expect(await gitGuard(path.join(loose, "target"), fx.env)).toBeNull();

    // In a repo but git cannot answer: refused, never a guess.
    const noGit = { ...fx.env, git: { bin: path.join(fx.root, "no-such-git") } };
    expect(await gitGuard(path.join(repo, "ignored-target"), noGit)).toBe("git-unknown");
  });
});

describe("removeTree", () => {
  it("unlinks links without traversing them, clears read-only files, counts real bytes", () => {
    fx = makeFixture();
    const root = path.join(fx.home, "code", "p", "node_modules");
    put(path.join(root, "a", "b", "c.js"), Buffer.alloc(300));
    const ro = put(path.join(root, "ro.js"), Buffer.alloc(200));
    fs.chmodSync(ro, 0o444);
    const sentinelDir = path.join(fx.root, "sentinel-dir");
    put(path.join(sentinelDir, "deep", "keep.txt"), "keep");
    junction(sentinelDir, path.join(root, "a", "dir-link"));
    const sentinelFile = put(path.join(fx.root, "sentinel-file.txt"), "keep");
    let fileLink = false;
    try {
      fs.symlinkSync(sentinelFile, path.join(root, "file-link"), "file");
      fileLink = true;
    } catch {
      // Windows without Developer Mode cannot create file symlinks; the junction covers it.
    }

    const r = removeTree(root);
    expect(r.errors).toEqual([]);
    expect(exists(root)).toBe(false);
    expect(r.bytes).toBe(500);
    expect(r.links).toBe(fileLink ? 2 : 1);
    expect(fs.readFileSync(path.join(sentinelDir, "deep", "keep.txt"), "utf8")).toBe("keep");
    expect(fs.readFileSync(sentinelFile, "utf8")).toBe("keep");
  });
});

describe("planClean (pure policy over a collection)", () => {
  it("never plans Docker, dist/ or out/, whatever the collection says", async () => {
    fx = makeFixture();
    const p = path.join(fx.home, "code", "p");
    put(path.join(p, "package.json"), "{}\n");
    put(path.join(p, "dist", "x"), "x");
    age(path.join(p, "dist"), OLD);
    const disk: DiskCollection = {
      folders: [
        {
          path: path.join(p, "dist"),
          cls: "next-build",
          project: p,
          bytes: 10,
          partial: false,
          lastTouched: OLD,
          stale: true,
          venv: false,
        },
      ],
      reportOnly: [],
      packageCaches: [],
      dockerBytes: 5e9,
      totals: {
        reclaimableBytes: 5e9,
        staleReclaimableBytes: 0,
        staleProjects: 0,
        projects: 0,
        byClass: { docker: 5e9 },
      },
      partial: false,
      staleDays: 30,
    };
    const plan = await planClean(disk, { env: fx.env, now: NOW });
    expect(plan.remove).toEqual([]);
    expect(plan.caches).toEqual([]);
    expect(plan.skipped.map((s) => s.reason)).toEqual(["report-only"]);
  });

  it("an undatable project is never stale", async () => {
    fx = makeFixture();
    const p = path.join(fx.home, "code", "p");
    put(path.join(p, "package.json"), "{}\n");
    put(path.join(p, "package-lock.json"), "{}\n");
    const nm = path.join(p, "node_modules");
    fs.mkdirSync(nm, { recursive: true });
    fs.rmSync(nm, { recursive: true }); // vanished after the walk: no mtime, no touch time
    const plan = await planClean(
      {
        folders: [
          {
            path: nm,
            cls: "node-modules",
            project: p,
            bytes: 1,
            partial: false,
            lastTouched: null,
            stale: false,
            venv: false,
          },
        ],
        reportOnly: [],
        packageCaches: [],
        dockerBytes: null,
        totals: {
          reclaimableBytes: 1,
          staleReclaimableBytes: 0,
          staleProjects: 0,
          projects: 1,
          byClass: {},
        },
        partial: false,
        staleDays: 30,
      },
      { env: fx.env, now: NOW },
    );
    expect(plan.skipped.map((s) => s.reason)).toEqual(["unknown-age"]);
  });
});
