// Cloud-placeholder detection for Windows (A10, Known Folder Move).
//
// OneDrive "Files On-Demand" leaves files in a folder as PLACEHOLDERS: the name and
// size are real, the bytes are in the cloud, and the first read downloads them. A
// sweep that opened every file in a redirected Documents folder would pull the
// whole library down. Whether a file is a placeholder is a Windows file ATTRIBUTE
// (FILE_ATTRIBUTE_OFFLINE, …RECALL_ON_OPEN, …RECALL_ON_DATA_ACCESS) that Node's `fs`
// does not expose — and stat-ing a placeholder is fine, but nothing that reads it is.
//
// So the walker asks a `PlaceholderProvider` for the attributes of a DIRECTORY'S
// entries — never touching a file's contents — and skips any entry whose attributes
// say it would recall. The real provider keeps one PowerShell process alive and
// sends it one directory per request (a process per directory would cost ~0.5 s each
// on a tree of thousands). If the attributes of a directory cannot be read, the
// walker skips that directory and counts it: when unsure, never open.
//
// Everything OS-specific sits behind `PlaceholderProvider`, so the walker is tested
// with a mock on any host.

import { spawn as nodeSpawn } from "node:child_process";

/** FILE_ATTRIBUTE_OFFLINE — the data is not available locally. */
export const FILE_ATTRIBUTE_OFFLINE = 0x1000;
/** FILE_ATTRIBUTE_RECALL_ON_OPEN — opening it downloads it. */
export const FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000;
/** FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS — reading it downloads it (OneDrive online-only). */
export const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000;

const PLACEHOLDER_MASK =
  FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

/** Would touching this entry download it (or has it no local data)? */
export const isPlaceholderAttr = (attributes: number): boolean =>
  (attributes & PLACEHOLDER_MASK) !== 0;

export interface PlaceholderProvider {
  /**
   * The Windows file-attribute bitmask of every entry directly inside `dir`, keyed by
   * entry name — or `null` when they could not be read (the caller then skips the
   * directory). MUST NOT open or read any entry's contents.
   */
  attributes(dir: string): Promise<Map<string, number> | null>;
  /** Release any helper process. Safe to call twice. */
  close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Wire format — pure, so it is testable without a process
// ---------------------------------------------------------------------------

const END = "<<END>>";
const ERR = "<<ERR>>";

/** One response line: `<attributes>:<base64 utf8 name>`. */
export function parseAttributeLine(line: string): [string, number] | null {
  const m = /^(\d+):([A-Za-z0-9+/=]*)$/.exec(line.trim());
  if (!m) return null;
  const attrs = Number(m[1]);
  if (!Number.isSafeInteger(attrs)) return null;
  const name = Buffer.from(m[2]!, "base64").toString("utf8");
  return name ? [name, attrs] : null;
}

/**
 * A directory listing from the helper's lines, or null when any line is malformed — a
 * half-understood listing must never be taken as "nothing here is a placeholder".
 */
export function parseAttributeListing(lines: readonly string[]): Map<string, number> | null {
  const out = new Map<string, number>();
  for (const line of lines) {
    if (line.trim() === "") continue;
    const parsed = parseAttributeLine(line);
    if (!parsed) return null;
    out.set(parsed[0], parsed[1]);
  }
  return out;
}

/** One request line: the directory path, base64 so no quoting or encoding can go wrong. */
export const encodeDirRequest = (dir: string): string =>
  `${Buffer.from(dir, "utf8").toString("base64")}\n`;

/**
 * The helper's loop. Get-ChildItem -Force lists a directory's entries WITHOUT reading
 * them (it reads metadata), and Attributes carries the recall bits as raw flag values.
 */
export const LISTER_SCRIPT = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$in = [Console]::In
$out = [Console]::Out
while ($true) {
  $line = $in.ReadLine()
  if ($null -eq $line) { break }
  try {
    $dir = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($line))
    foreach ($e in (Get-ChildItem -LiteralPath $dir -Force)) {
      $name = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($e.Name))
      $out.WriteLine(([int]$e.Attributes).ToString() + ':' + $name)
    }
    $out.WriteLine('${END}')
  } catch {
    $out.WriteLine('${ERR}')
  }
  $out.Flush()
}
`;

// ---------------------------------------------------------------------------
// The real provider
// ---------------------------------------------------------------------------

/** The slice of a child process this module uses (the real one, or a test double). */
export interface HelperProcess {
  stdin: { write(chunk: string): unknown; end(): unknown };
  stdout: { on(event: "data", cb: (chunk: Buffer | string) => void): unknown };
  on(event: "error", cb: (err: Error) => void): unknown;
  on(event: "exit", cb: () => void): unknown;
  kill(): unknown;
  unref?(): unknown;
}

export type SpawnHelper = (exe: string, args: string[]) => HelperProcess;

const defaultSpawn: SpawnHelper = (exe, args) =>
  nodeSpawn(exe, args, { stdio: ["pipe", "pipe", "ignore"], windowsHide: true }) as HelperProcess;

export interface PowerShellProviderOptions {
  spawn?: SpawnHelper;
  exe?: string;
  /** Per-directory deadline; a hung helper is killed and the directory counts as unreadable. */
  timeoutMs?: number;
}

interface Pending {
  lines: string[];
  resolve: (v: Map<string, number> | null) => void;
  timer: NodeJS.Timeout;
}

/** A lazily started, long-lived PowerShell that answers one directory at a time. */
export function createPowerShellProvider(
  opts: PowerShellProviderOptions = {},
): PlaceholderProvider {
  const spawnHelper = opts.spawn ?? defaultSpawn;
  const exe = opts.exe ?? "powershell.exe";
  const timeoutMs = opts.timeoutMs ?? 15_000;

  let child: HelperProcess | null = null;
  let unavailable = false; // powershell.exe could not be started at all
  let buffer = "";
  let pending: Pending | null = null;
  let chain: Promise<unknown> = Promise.resolve();

  const settle = (value: Map<string, number> | null) => {
    if (!pending) return;
    clearTimeout(pending.timer);
    const { resolve } = pending;
    pending = null;
    resolve(value);
  };

  const onData = (chunk: Buffer | string) => {
    buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    let nl: number;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, nl).replace(/\r$/, "");
      buffer = buffer.slice(nl + 1);
      if (!pending) continue;
      if (line === END) settle(parseAttributeListing(pending.lines));
      else if (line === ERR) settle(null);
      else pending.lines.push(line);
    }
  };

  const drop = () => {
    const c = child;
    child = null;
    buffer = "";
    settle(null);
    try {
      c?.kill();
    } catch {
      // already gone
    }
  };

  const start = (): HelperProcess | null => {
    if (child) return child;
    if (unavailable) return null;
    try {
      const encoded = Buffer.from(LISTER_SCRIPT, "utf16le").toString("base64");
      const c = spawnHelper(exe, [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        encoded,
      ]);
      c.stdout.on("data", onData);
      c.on("error", () => {
        unavailable = true; // no PowerShell here: every directory is "unreadable"
        drop();
      });
      c.on("exit", () => {
        if (child === c) {
          child = null;
          settle(null);
        }
      });
      c.unref?.();
      child = c;
      return c;
    } catch {
      unavailable = true;
      return null;
    }
  };

  const request = (dir: string): Promise<Map<string, number> | null> =>
    new Promise((resolve) => {
      const c = start();
      if (!c) return resolve(null);
      const timer = setTimeout(() => {
        // Never wait on a stuck helper; restart it for the next directory.
        drop();
      }, timeoutMs);
      pending = { lines: [], resolve, timer };
      try {
        c.stdin.write(encodeDirRequest(dir));
      } catch {
        drop();
      }
    });

  return {
    attributes(dir) {
      // One request in flight at a time — the helper is a single loop.
      const run = () => request(dir);
      const next = chain.then(run, run);
      chain = next.catch(() => undefined);
      return next;
    },
    async close() {
      const c = child;
      child = null;
      settle(null);
      if (!c) return;
      try {
        c.stdin.end();
      } catch {
        // ignore
      }
      setTimeout(() => {
        try {
          c.kill();
        } catch {
          // ignore
        }
      }, 250).unref?.();
    },
  };
}
