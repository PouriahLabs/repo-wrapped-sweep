// OS-specific shell-outs behind injectable interfaces (§ A2.5, § A2.8): the OS
// trash, the OS credential store and process execution. Everything destructive
// or machine-global goes through `Exec` / `TrashAdapter` / `KeychainAdapter` so
// tests exercise the logic with mocks and CI never touches a real trash, keychain
// or scheduler.
//
// Arguments are ALWAYS passed as an argv array to `execFile` — never through a
// shell — and anything user-controlled (a file path, a secret) travels via
// stdin or an environment variable rather than being spliced into a command
// string. The one exception is documented on `macKeychain`.

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { SweepEnv } from "./env";

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface ExecOptions {
  /** Piped to the child's stdin. */
  input?: string;
  timeoutMs?: number;
  /** Extra environment variables (merged over the parent's). */
  env?: Record<string, string>;
}

/** Run a program with an argv array (no shell). Never rejects: failures are a non-zero code. */
export type Exec = (cmd: string, args: string[], opts?: ExecOptions) => Promise<ExecResult>;

export const realExec: Exec = (cmd, args, opts = {}) =>
  new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, ...opts.env },
        windowsHide: true,
      });
    } catch (err) {
      resolve({ code: 127, stdout: "", stderr: (err as Error).message });
      return;
    }
    let stdout = "";
    let stderr = "";
    const timer = opts.timeoutMs ? setTimeout(() => child.kill(), opts.timeoutMs) : undefined;
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", (err) => {
      if (timer) clearTimeout(timer);
      resolve({ code: 127, stdout, stderr: stderr || err.message });
    });
    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(opts.input ?? "");
  });

// ---------------------------------------------------------------------------
// Trash — never `unlink`
// ---------------------------------------------------------------------------

export interface ActionResult {
  ok: boolean;
  message?: string;
}

export interface TrashAdapter {
  /** Human name of where files go ("the Recycle Bin"). */
  readonly destination: string;
  trash(file: string): Promise<ActionResult>;
}

/** A name that does not collide in `dir`: `x.env`, `x 2.env`, `x 3.env` … */
export function uniqueTrashName(base: string, exists: (name: string) => boolean): string {
  if (!exists(base)) return base;
  const ext = path.extname(base);
  const stem = base.slice(0, base.length - ext.length);
  for (let i = 2; i < 10_000; i++) {
    const candidate = `${stem} ${i}${ext}`;
    if (!exists(candidate)) return candidate;
  }
  return `${stem} ${Date.now()}${ext}`;
}

/** macOS: move into `~/.Trash`; fall back to Finder (via osascript) across volumes. */
export function macTrash(env: Pick<SweepEnv, "home">, exec: Exec): TrashAdapter {
  return {
    destination: "the Trash",
    async trash(file) {
      const dir = path.join(env.home, ".Trash");
      try {
        fs.mkdirSync(dir, { recursive: true });
        const name = uniqueTrashName(path.basename(file), (n) => fs.existsSync(path.join(dir, n)));
        await fs.promises.rename(file, path.join(dir, name));
        return { ok: true };
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EXDEV") {
          return { ok: false, message: (err as Error).message };
        }
      }
      // Different volume: ask Finder, passing the path as an argument (no splicing).
      const r = await exec("osascript", [
        "-e",
        "on run argv",
        "-e",
        'tell application "Finder" to delete POSIX file (item 1 of argv)',
        "-e",
        "end run",
        file,
      ]);
      return r.code === 0
        ? { ok: true }
        : { ok: false, message: r.stderr.trim() || "Finder refused" };
    },
  };
}

/**
 * Windows: the Recycle Bin via `Microsoft.VisualBasic.FileIO.FileSystem`. The path
 * is handed over in an environment variable so quoting can never break out of the
 * command.
 */
export function windowsTrash(exec: Exec): TrashAdapter {
  const script =
    "Add-Type -AssemblyName Microsoft.VisualBasic; " +
    "[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($env:SWEEP_TRASH_PATH, " +
    "'OnlyErrorDialogs', 'SendToRecycleBin')";
  return {
    destination: "the Recycle Bin",
    async trash(file) {
      const r = await exec(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", script],
        { env: { SWEEP_TRASH_PATH: file }, timeoutMs: 30_000 },
      );
      return r.code === 0
        ? { ok: true }
        : { ok: false, message: r.stderr.trim() || "Recycle Bin move failed" };
    },
  };
}

/** Linux: `gio trash`, then `trash-put`. */
export function linuxTrash(exec: Exec): TrashAdapter {
  return {
    destination: "the Trash",
    async trash(file) {
      const gio = await exec("gio", ["trash", "--", file]);
      if (gio.code === 0) return { ok: true };
      const tp = await exec("trash-put", ["--", file]);
      if (tp.code === 0) return { ok: true };
      return {
        ok: false,
        message: "no trash tool found (install `gio` or `trash-cli`) — nothing was deleted",
      };
    },
  };
}

export function trashFor(env: Pick<SweepEnv, "platform" | "home">, exec: Exec): TrashAdapter {
  if (env.platform === "darwin") return macTrash(env, exec);
  if (env.platform === "win32") return windowsTrash(exec);
  return linuxTrash(exec);
}

// ---------------------------------------------------------------------------
// OS credential store
// ---------------------------------------------------------------------------

export interface KeychainAdapter {
  readonly name: string;
  store(label: string, secret: string): Promise<ActionResult>;
}

/** The service name every adapter files a secret under. */
export const keychainService = (label: string) => `repo-wrapped/${label}`;

/**
 * macOS Keychain. CAVEAT: `security add-generic-password` accepts the secret only
 * as the `-w` argument, so it is briefly visible in this user's process list while
 * the command runs. It is never written to disk or printed by this tool.
 */
export function macKeychain(exec: Exec, account: string = os.userInfo().username): KeychainAdapter {
  return {
    name: "macOS Keychain",
    async store(label, secret) {
      const r = await exec("security", [
        "add-generic-password",
        "-U",
        "-a",
        account,
        "-s",
        keychainService(label),
        "-w",
        secret,
      ]);
      return r.code === 0
        ? { ok: true }
        : { ok: false, message: r.stderr.trim() || "keychain refused" };
    },
  };
}

/**
 * Windows Credential Manager via `cmdkey`. Same caveat as macOS: `/pass:` is an
 * argument. Passed as an argv element, never through a shell.
 */
export function windowsKeychain(
  exec: Exec,
  account: string = os.userInfo().username,
): KeychainAdapter {
  return {
    name: "Windows Credential Manager",
    async store(label, secret) {
      const r = await exec("cmdkey", [
        `/generic:${keychainService(label)}`,
        `/user:${account}`,
        `/pass:${secret}`,
      ]);
      return r.code === 0
        ? { ok: true }
        : { ok: false, message: r.stdout.trim() || r.stderr.trim() || "cmdkey failed" };
    },
  };
}

/** Linux libsecret via `secret-tool`; the secret goes over STDIN, never argv. */
export function linuxKeychain(exec: Exec): KeychainAdapter {
  return {
    name: "the system keyring (secret-tool)",
    async store(label, secret) {
      const r = await exec(
        "secret-tool",
        ["store", `--label=${keychainService(label)}`, "service", keychainService(label)],
        { input: secret },
      );
      return r.code === 0
        ? { ok: true }
        : { ok: false, message: r.stderr.trim() || "secret-tool failed (is libsecret installed?)" };
    },
  };
}

export function keychainFor(env: Pick<SweepEnv, "platform">, exec: Exec): KeychainAdapter {
  if (env.platform === "darwin") return macKeychain(exec);
  if (env.platform === "win32") return windowsKeychain(exec);
  return linuxKeychain(exec);
}

/**
 * The 1Password CLI alternative. NEVER contains the secret: it is a template the
 * user completes themselves (the CLI does not shell out to `op`).
 */
export function onePasswordHint(label: string): string {
  return `op item create --category=password --title='${keychainService(label)}' 'password=<paste the secret here>'`;
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

export interface Prompter {
  confirm(question: string): Promise<boolean>;
}

/** Ask on the terminal. No TTY (CI, a pipe) → every confirm is "no": a destructive
 *  step never proceeds on a guess. */
export function ttyPrompter(
  input: NodeJS.ReadableStream & { isTTY?: boolean } = process.stdin,
  output: NodeJS.WritableStream = process.stderr,
): Prompter {
  return {
    async confirm(question) {
      if (!input.isTTY) return false;
      const { createInterface } = await import("node:readline");
      const rl = createInterface({ input, output });
      try {
        const answer: string = await new Promise((resolve) =>
          rl.question(`${question} [y/N] `, resolve),
        );
        return /^y(es)?$/i.test(answer.trim());
      } finally {
        rl.close();
      }
    },
  };
}
