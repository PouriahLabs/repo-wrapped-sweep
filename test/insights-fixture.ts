// Machine Insights fixtures: real git repos (with a bare "remote" outside the home
// directory), project folders, regenerable folders, and a PATH of stub binaries that
// answer `--version` (.cmd on Windows, sh scripts elsewhere). Host paths are always
// built with path.join so the same tests run on Windows and Linux CI.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { Fixture } from "./helpers";

export const DAY_MS = 86_400_000;

/** git with a private, empty global config and fixed identity/dates. */
export function gitIn(fx: Fixture, cwd: string, args: string[], atMs?: number): string {
  const globalCfg = path.join(fx.root, "gitconfig");
  if (!fs.existsSync(globalCfg)) fs.writeFileSync(globalCfg, "");
  const date = atMs === undefined ? undefined : `${Math.floor(atMs / 1000)} +0000`;
  const r = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: globalCfg,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_AUTHOR_NAME: "Fixture",
      GIT_AUTHOR_EMAIL: "fixture@example.invalid",
      GIT_COMMITTER_NAME: "Fixture",
      GIT_COMMITTER_EMAIL: "fixture@example.invalid",
      ...(date ? { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date } : {}),
    },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${r.stderr}`);
  return r.stdout;
}

/** Set a file or folder's mtime/atime. */
export function age(abs: string, atMs: number): void {
  const t = new Date(atMs);
  fs.utimesSync(abs, t, t);
}

/** Age every top-level FILE of a folder (what `lastTouchedOf` reads). */
export function ageTopFiles(dir: string, atMs: number): void {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isFile()) age(path.join(dir, e.name), atMs);
  }
}

export function put(abs: string, content: string | Buffer): string {
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
  return abs;
}

/** `git init -b main` + one commit of whatever is already in `dir`. */
export function initRepo(fx: Fixture, dir: string, atMs: number): void {
  fs.mkdirSync(dir, { recursive: true });
  gitIn(fx, dir, ["init", "-q", "-b", "main"]);
  gitIn(fx, dir, ["config", "commit.gpgsign", "false"]);
  gitIn(fx, dir, ["config", "core.autocrlf", "false"]);
  gitIn(fx, dir, ["add", "-A"]);
  gitIn(fx, dir, ["commit", "-q", "-m", "init", "--allow-empty"], atMs);
}

/** A bare repo OUTSIDE the home directory, wired as `origin`, with `main` pushed. */
export function addRemote(fx: Fixture, dir: string, name: string): string {
  const bare = path.join(fx.root, "remotes", `${name}.git`);
  fs.mkdirSync(bare, { recursive: true });
  gitIn(fx, bare, ["init", "-q", "--bare", "-b", "main"]);
  gitIn(fx, dir, ["remote", "add", "origin", bare]);
  gitIn(fx, dir, ["push", "-q", "-u", "origin", "main"]);
  return bare;
}

export interface InsightsTree {
  /** Pushed and clean; old; has node_modules (regenerable, stale) and dist/ (report-only). */
  pushed: string;
  /** Pushed, then one more local commit; an old stash; .nvmrc wants 22. */
  ahead: string;
  /** No remote; an untracked file 10 days old. */
  local: string;
  /** A project folder that is not a git repo. */
  plain: string;
  /** A Rust project with a `target/` folder. */
  rusty: string;
  /** Bytes written into pushed/node_modules. */
  nodeModulesBytes: number;
}

/**
 * The standard tree under `fx.home/code`. `now` is the reference clock; "old" means
 * 60 days before it.
 */
export function buildInsightsTree(fx: Fixture, now: number): InsightsTree {
  const old = now - 60 * DAY_MS;
  const code = path.join(fx.home, "code");

  const pushed = path.join(code, "pushed");
  put(path.join(pushed, "package.json"), '{"name":"pushed"}\n');
  put(path.join(pushed, "package-lock.json"), "{}\n");
  put(path.join(pushed, ".gitignore"), "node_modules\ndist\n");
  put(path.join(pushed, "index.js"), "console.log(1)\n");
  initRepo(fx, pushed, old);
  addRemote(fx, pushed, "pushed");
  const nm = Buffer.alloc(4096, 1);
  put(path.join(pushed, "node_modules", "dep", "index.js"), nm);
  put(path.join(pushed, "node_modules", "dep", "lib", "more.js"), nm);
  put(path.join(pushed, "dist", "bundle.js"), "x".repeat(100));
  ageTopFiles(pushed, old);

  const ahead = path.join(code, "ahead");
  put(path.join(ahead, "package.json"), '{"name":"ahead","engines":{"node":">=20"}}\n');
  put(path.join(ahead, ".nvmrc"), "22\n");
  put(path.join(ahead, "a.txt"), "one\n");
  initRepo(fx, ahead, now - 20 * DAY_MS);
  addRemote(fx, ahead, "ahead");
  put(path.join(ahead, "a.txt"), "two\n");
  gitIn(fx, ahead, ["commit", "-q", "-am", "local only"], now - 2 * DAY_MS);
  put(path.join(ahead, "a.txt"), "stashed\n");
  gitIn(fx, ahead, ["stash", "-q"], old);

  const local = path.join(code, "local");
  put(path.join(local, "Cargo.toml"), '[package]\nname = "local"\n');
  put(path.join(local, "src", "main.rs"), "fn main() {}\n");
  initRepo(fx, local, now - 5 * DAY_MS);
  age(put(path.join(local, "notes.txt"), "untracked\n"), now - 10 * DAY_MS);

  const plain = path.join(code, "plain");
  put(path.join(plain, "pyproject.toml"), '[project]\nname = "plain"\n');
  put(path.join(plain, "app.py"), "print(1)\n");
  put(path.join(plain, "__pycache__", "app.cpython-312.pyc"), Buffer.alloc(512));

  const rusty = path.join(code, "rusty");
  put(path.join(rusty, "Cargo.toml"), '[package]\nname = "rusty"\n');
  put(path.join(rusty, "target", "debug", "rusty"), Buffer.alloc(2048));
  put(path.join(rusty, "src", "main.rs"), "fn main() {}\n");

  return { pushed, ahead, local, plain, rusty, nodeModulesBytes: nm.length * 2 };
}

// ---------------------------------------------------------------------------
// Stub binaries on a fake PATH
// ---------------------------------------------------------------------------

/**
 * Write a stub `name` into `dir` that prints `output` (to stderr with `toStderr`).
 * Windows: `name.cmd`; elsewhere an executable sh script.
 */
export function stubBin(dir: string, name: string, output: string, toStderr = false): string {
  fs.mkdirSync(dir, { recursive: true });
  if (process.platform === "win32") {
    const file = path.join(dir, `${name}.cmd`);
    fs.writeFileSync(file, `@echo off\r\necho ${output}${toStderr ? " 1>&2" : ""}\r\n`);
    return file;
  }
  const file = path.join(dir, name);
  const quoted = `'${output.replace(/'/g, "'\\''")}'`;
  fs.writeFileSync(file, `#!/bin/sh\necho ${quoted}${toStderr ? " 1>&2" : ""}\n`);
  fs.chmodSync(file, 0o755);
  return file;
}

/** A process environment whose PATH holds only `dir`. */
export function stubPathEnv(dir: string): NodeJS.ProcessEnv {
  return process.platform === "win32"
    ? { PATH: dir, PATHEXT: ".COM;.EXE;.BAT;.CMD" }
    : { PATH: dir };
}
