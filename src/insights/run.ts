// Shell-outs for the Machine Insights collectors (ENDPOINT-MACHINE-INSIGHTS § C2):
// `git` per repo, `--version` per tool. Same contract as the agent guard's
// `git check-ignore` (hook-search.ts): argv only, never a shell for anything
// user-controlled, a hard deadline, and a failure is a REASON ("timeout" |
// "unavailable") rather than an exception — a collector reports "unknown" and
// moves on; it never stops the run.

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { GitFailure } from "../hook-search";

/** Why a command gave no answer — the same vocabulary as the agent guard. */
export type RunFailure = GitFailure;

export type RunResult =
  { ok: true; code: number; stdout: string; stderr: string } | { ok: false; failure: RunFailure };

export interface RunOptions {
  cwd?: string;
  timeoutMs: number;
  /** Full environment for the child (default: this process's). */
  env?: NodeJS.ProcessEnv;
  /** Output kept per stream; the rest is dropped (default 1 MB). */
  maxBytes?: number;
}

/**
 * Run `cmd args` and resolve with its output, or with why it could not be run. The
 * deadline resolves the promise ITSELF — a Windows `.cmd` wrapper's grandchild can hold
 * the pipes open after the wrapper is killed, and we must not wait on it.
 */
export function runCommand(
  cmd: string,
  args: readonly string[],
  opts: RunOptions,
): Promise<RunResult> {
  const max = opts.maxBytes ?? 1024 * 1024;
  return new Promise((resolve) => {
    let settled = false;
    const finish = (r: RunResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(r);
    };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(cmd, [...args], {
        cwd: opts.cwd,
        env: opts.env ?? process.env,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
        windowsVerbatimArguments: isCmdShell(cmd),
      });
    } catch {
      resolve({ ok: false, failure: "unavailable" });
      return;
    }
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      killTree(child);
      finish({ ok: false, failure: "timeout" });
    }, opts.timeoutMs);
    child.stdout?.on("data", (d: Buffer) => {
      if (stdout.length < max) stdout += d.toString("utf8");
    });
    child.stderr?.on("data", (d: Buffer) => {
      if (stderr.length < max) stderr += d.toString("utf8");
    });
    child.on("error", () => finish({ ok: false, failure: "unavailable" }));
    child.on("close", (code, signal) => {
      if (signal && code === null) finish({ ok: false, failure: "timeout" });
      else finish({ ok: true, code: code ?? 1, stdout, stderr });
    });
  });
}

const isCmdShell = (cmd: string) => /(?:^|[\\/])cmd(?:\.exe)?$/i.test(cmd);

function killTree(child: ReturnType<typeof spawn>): void {
  try {
    if (process.platform === "win32" && child.pid !== undefined) {
      // A .cmd wrapper's real work runs in a grandchild; /T takes the whole tree.
      spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
      }).on("error", () => {});
    } else {
      child.kill("SIGKILL");
    }
  } catch {
    // already gone
  }
}

/** `fn` over `items` with at most `limit` in flight; results keep input order. */
export async function mapPool<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!, i);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return out;
}

// ---------------------------------------------------------------------------
// PATH lookup (toolchain probes)
// ---------------------------------------------------------------------------

export interface PathLookup {
  /** The PATH value to search. */
  path: string;
  /** Windows `PATHEXT` (default `.COM;.EXE;.BAT;.CMD`). */
  pathext?: string;
  platform: NodeJS.Platform;
}

/**
 * The absolute path `name` would run as, or null when it is not on PATH. Resolving it
 * ourselves means a missing tool costs no spawn, and on Windows we know whether it is a
 * `.cmd`/`.bat` wrapper (which Node will not spawn without a shell).
 */
export function findOnPath(name: string, lookup: PathLookup): string | null {
  const win = lookup.platform === "win32";
  const dirs = lookup.path.split(win ? ";" : ":").filter(Boolean);
  const exts = win
    ? (lookup.pathext ?? ".COM;.EXE;.BAT;.CMD")
        .split(";")
        .filter(Boolean)
        .map((e) => e.toLowerCase())
    : [""];
  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = path.join(dir.replace(/^"|"$/g, ""), name + ext);
      try {
        const st = fs.statSync(candidate);
        if (!st.isFile()) continue;
        if (!win) fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      } catch {
        // not here
      }
    }
  }
  return null;
}

/**
 * The argv to run a resolved binary with constant arguments. A Windows `.cmd`/`.bat`
 * goes through `cmd.exe /d /s /c` — safe here because the arguments are fixed probe
 * flags from this module, never user input, and the path comes from PATH.
 */
export function commandFor(
  abs: string,
  args: readonly string[],
  platform: NodeJS.Platform,
  comSpec = process.env.ComSpec ?? "cmd.exe",
): { cmd: string; args: string[] } {
  if (platform === "win32" && /\.(?:cmd|bat)$/i.test(abs)) {
    return { cmd: comSpec, args: ["/d", "/s", "/c", `"${[`"${abs}"`, ...args].join(" ")}"`] };
  }
  return { cmd: abs, args: [...args] };
}
