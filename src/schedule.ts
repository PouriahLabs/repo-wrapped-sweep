// Daily scheduling (§ A2.8): a macOS LaunchAgent, a Windows scheduled task, a
// Linux systemd user timer. The file/argument GENERATORS are pure (and snapshot
// tested per OS); the install/uninstall/status runners shell out through the
// injectable `Exec`.
//
// A scheduled run is `--quiet --scheduled [--upload]`. `--scheduled` is how the
// CLI knows it is unattended, so it can refuse `--validate` there (decision E3:
// a background job must never send found secrets to their providers).
//
// Start time: a stable per-machine offset inside 12:00 ± 3 h. Jitter alone does
// not protect Neon — uploads are buffered server-side regardless — it just keeps a
// fleet from stampeding the ingest endpoint at the same minute.

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { SweepEnv } from "./env";
import type { Exec } from "./platform";

export const LAUNCH_LABEL = "com.repowrapped.sweep";
export const WINDOWS_TASK = "RepoWrappedSweep";
export const SYSTEMD_UNIT = "repo-wrapped-sweep";

export interface Invocation {
  program: string;
  args: string[];
}

/**
 * How to re-run this CLI from a scheduler. A Node install runs
 * `node <script>`; a compiled single binary runs itself.
 */
export function resolveInvocation(argv1: string | undefined, execPath: string): Invocation {
  const base = path
    .basename(execPath)
    .toLowerCase()
    .replace(/\.exe$/, "");
  const isRuntime = base === "node" || base === "bun" || base === "nodejs";
  return isRuntime && argv1
    ? { program: execPath, args: [path.resolve(argv1)] }
    : { program: execPath, args: [] };
}

export function scheduledArgs(opts: { upload: boolean }): string[] {
  return ["--quiet", "--scheduled", ...(opts.upload ? ["--upload"] : [])];
}

export interface StartTime {
  hour: number;
  minute: number;
}

/** A stable start time in 09:00–14:59 (12:00 ± 3 h), derived from `seed`. */
export function pickStartTime(seed: string): StartTime {
  const n = createHash("sha256").update(seed).digest().readUInt32BE(0);
  const offset = n % 360; // minutes after 09:00
  return { hour: 9 + Math.floor(offset / 60), minute: offset % 60 };
}

const pad2 = (n: number) => String(n).padStart(2, "0");
export const formatTime = (t: StartTime) => `${pad2(t.hour)}:${pad2(t.minute)}`;

// ---------------------------------------------------------------------------
// macOS — LaunchAgent
// ---------------------------------------------------------------------------

const xmlEscape = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export function launchAgentPath(env: Pick<SweepEnv, "home">): string {
  return path.join(env.home, "Library", "LaunchAgents", `${LAUNCH_LABEL}.plist`);
}

export function renderLaunchAgentPlist(opts: {
  invocation: Invocation;
  args: string[];
  start: StartTime;
  logPath: string;
}): string {
  const argv = [opts.invocation.program, ...opts.invocation.args, ...opts.args];
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LAUNCH_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${argv.map((a) => `    <string>${xmlEscape(a)}</string>`).join("\n")}
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>${opts.start.hour}</integer>
    <key>Minute</key>
    <integer>${opts.start.minute}</integer>
  </dict>
  <key>RunAtLoad</key>
  <false/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>LowPriorityIO</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${xmlEscape(opts.logPath)}</string>
  <key>StandardErrorPath</key>
  <string>${xmlEscape(opts.logPath)}</string>
</dict>
</plist>
`;
}

// ---------------------------------------------------------------------------
// Windows — schtasks
// ---------------------------------------------------------------------------

/** Quote one command-line token for the scheduled task's `/TR` string. */
export function quoteWindowsToken(t: string): string {
  return /[\s"]/.test(t) ? `"${t.replace(/"/g, '\\"')}"` : t;
}

export function renderSchtasksCreate(opts: {
  invocation: Invocation;
  args: string[];
  start: StartTime;
}): string[] {
  const tr = [opts.invocation.program, ...opts.invocation.args, ...opts.args]
    .map(quoteWindowsToken)
    .join(" ");
  return [
    "/Create",
    "/SC",
    "DAILY",
    "/TN",
    WINDOWS_TASK,
    "/TR",
    tr,
    "/ST",
    formatTime(opts.start),
    "/F",
  ];
}

// ---------------------------------------------------------------------------
// Linux — systemd user timer
// ---------------------------------------------------------------------------

export function systemdDir(env: Pick<SweepEnv, "home">): string {
  return path.join(env.home, ".config", "systemd", "user");
}

/** systemd ExecStart word: quote anything with whitespace/special characters. */
export function quoteSystemd(t: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(t)
    ? t
    : `"${t.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function renderSystemdUnits(opts: {
  invocation: Invocation;
  args: string[];
  start: StartTime;
}): { service: string; timer: string } {
  const exec = [opts.invocation.program, ...opts.invocation.args, ...opts.args]
    .map(quoteSystemd)
    .join(" ");
  return {
    service: `[Unit]
Description=Repo Wrapped endpoint sweep

[Service]
Type=oneshot
ExecStart=${exec}
Nice=10
IOSchedulingClass=idle
`,
    timer: `[Unit]
Description=Daily Repo Wrapped endpoint sweep

[Timer]
OnCalendar=*-*-* ${formatTime(opts.start)}:00
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
`,
  };
}

// ---------------------------------------------------------------------------
// macOS Full Disk Access probe (pure over an injected readdir)
// ---------------------------------------------------------------------------

export const PROTECTED_FOLDERS = ["Documents", "Desktop", "Downloads"] as const;

/** Protected folders that EXIST but cannot be listed (EPERM/EACCES). */
export function probeProtectedFolders(
  env: Pick<SweepEnv, "home">,
  readdir: (dir: string) => void = (d) => void fs.readdirSync(d),
): string[] {
  const blocked: string[] = [];
  for (const name of PROTECTED_FOLDERS) {
    const dir = path.join(env.home, name);
    try {
      readdir(dir);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EPERM" || code === "EACCES") blocked.push(name);
    }
  }
  return blocked;
}

export function fullDiskAccessInstructions(program: string, blocked: string[]): string[] {
  return [
    `macOS is blocking access to ${blocked.map((b) => `~/${b}`).join(", ")}.`,
    "A scheduled run can't read those folders until you grant Full Disk Access:",
    "  System Settings → Privacy & Security → Full Disk Access → “+” → add:",
    `    ${program}`,
  ];
}

// ---------------------------------------------------------------------------
// Runners
// ---------------------------------------------------------------------------

export interface ScheduleDeps {
  env: SweepEnv;
  exec: Exec;
  invocation: Invocation;
  /** Seed for the stable start time (hostname + home by default). */
  seed: string;
  /** Numeric uid for `launchctl gui/<uid>` (macOS). */
  uid?: number;
  /** Overridable for tests. */
  fs?: Pick<typeof fs, "mkdirSync" | "writeFileSync" | "rmSync" | "existsSync">;
  readdir?: (dir: string) => void;
}

export interface ScheduleResult {
  ok: boolean;
  lines: string[];
}

export async function installSchedule(
  opts: { upload: boolean },
  deps: ScheduleDeps,
): Promise<ScheduleResult> {
  const f = deps.fs ?? fs;
  const { env } = deps;
  const args = scheduledArgs(opts);
  const start = pickStartTime(deps.seed);
  const when = `daily at ${formatTime(start)} local time`;

  if (env.platform === "darwin") {
    const file = launchAgentPath(env);
    const logPath = path.join(env.configDir, "sweep.log");
    f.mkdirSync(path.dirname(file), { recursive: true });
    f.mkdirSync(env.configDir, { recursive: true });
    f.writeFileSync(
      file,
      renderLaunchAgentPlist({ invocation: deps.invocation, args, start, logPath }),
    );
    const domain = `gui/${deps.uid ?? 501}`;
    await deps.exec("launchctl", ["bootout", `${domain}/${LAUNCH_LABEL}`]); // ignore "not loaded"
    const r = await deps.exec("launchctl", ["bootstrap", domain, file]);
    if (r.code !== 0) {
      return {
        ok: false,
        lines: [
          `launchctl could not load the agent: ${r.stderr.trim() || `exit ${r.code}`}`,
          `The plist was written to ${file}.`,
        ],
      };
    }
    const lines = [
      `Installed ${LAUNCH_LABEL} — runs ${when}.`,
      `Plist: ${file}`,
      `Log:   ${logPath}`,
    ];
    const blocked = probeProtectedFolders(env, deps.readdir);
    if (blocked.length > 0)
      lines.push("", ...fullDiskAccessInstructions(deps.invocation.program, blocked));
    else {
      lines.push(
        "",
        `Note: a LaunchAgent has its own privacy grants. If scheduled runs report skipped folders, add`,
        `  ${deps.invocation.program}`,
        "to System Settings → Privacy & Security → Full Disk Access.",
      );
    }
    return { ok: true, lines };
  }

  if (env.platform === "win32") {
    const r = await deps.exec(
      "schtasks",
      renderSchtasksCreate({ invocation: deps.invocation, args, start }),
    );
    return r.code === 0
      ? { ok: true, lines: [`Installed scheduled task ${WINDOWS_TASK} — runs ${when}.`] }
      : {
          ok: false,
          lines: [`schtasks failed: ${(r.stderr || r.stdout).trim() || `exit ${r.code}`}`],
        };
  }

  const dir = systemdDir(env);
  const { service, timer } = renderSystemdUnits({ invocation: deps.invocation, args, start });
  f.mkdirSync(dir, { recursive: true });
  f.writeFileSync(path.join(dir, `${SYSTEMD_UNIT}.service`), service);
  f.writeFileSync(path.join(dir, `${SYSTEMD_UNIT}.timer`), timer);
  await deps.exec("systemctl", ["--user", "daemon-reload"]);
  const r = await deps.exec("systemctl", ["--user", "enable", "--now", `${SYSTEMD_UNIT}.timer`]);
  return r.code === 0
    ? {
        ok: true,
        lines: [
          `Installed systemd user timer ${SYSTEMD_UNIT}.timer — runs ${when}.`,
          `Units: ${dir}`,
        ],
      }
    : {
        ok: false,
        lines: [
          `systemctl could not enable the timer: ${r.stderr.trim() || `exit ${r.code}`}`,
          `Units were written to ${dir}.`,
        ],
      };
}

export async function uninstallSchedule(deps: ScheduleDeps): Promise<ScheduleResult> {
  const f = deps.fs ?? fs;
  const { env } = deps;
  if (env.platform === "darwin") {
    await deps.exec("launchctl", ["bootout", `gui/${deps.uid ?? 501}/${LAUNCH_LABEL}`]);
    const had = f.existsSync(launchAgentPath(env));
    f.rmSync(launchAgentPath(env), { force: true });
    return { ok: true, lines: [had ? `Removed ${LAUNCH_LABEL}.` : "No schedule was installed."] };
  }
  if (env.platform === "win32") {
    const r = await deps.exec("schtasks", ["/Delete", "/TN", WINDOWS_TASK, "/F"]);
    return {
      ok: true,
      lines: [
        r.code === 0 ? `Removed scheduled task ${WINDOWS_TASK}.` : "No schedule was installed.",
      ],
    };
  }
  const dir = systemdDir(env);
  await deps.exec("systemctl", ["--user", "disable", "--now", `${SYSTEMD_UNIT}.timer`]);
  const had = f.existsSync(path.join(dir, `${SYSTEMD_UNIT}.timer`));
  f.rmSync(path.join(dir, `${SYSTEMD_UNIT}.timer`), { force: true });
  f.rmSync(path.join(dir, `${SYSTEMD_UNIT}.service`), { force: true });
  await deps.exec("systemctl", ["--user", "daemon-reload"]);
  return {
    ok: true,
    lines: [had ? `Removed ${SYSTEMD_UNIT}.timer.` : "No schedule was installed."],
  };
}

/** Is a schedule installed? */
export async function isScheduleInstalled(deps: ScheduleDeps): Promise<boolean> {
  const f = deps.fs ?? fs;
  const { env } = deps;
  if (env.platform === "darwin") return f.existsSync(launchAgentPath(env));
  if (env.platform === "win32")
    return (await deps.exec("schtasks", ["/Query", "/TN", WINDOWS_TASK])).code === 0;
  return f.existsSync(path.join(systemdDir(env), `${SYSTEMD_UNIT}.timer`));
}

export async function scheduleStatus(deps: ScheduleDeps): Promise<ScheduleResult> {
  const { env } = deps;
  if (!(await isScheduleInstalled(deps))) return { ok: true, lines: ["No schedule installed."] };
  if (env.platform === "darwin") {
    const r = await deps.exec("launchctl", ["print", `gui/${deps.uid ?? 501}/${LAUNCH_LABEL}`]);
    return {
      ok: true,
      lines: [
        `Installed: ${launchAgentPath(env)}`,
        r.code === 0
          ? "Loaded in launchd."
          : "Not currently loaded (launchctl bootstrap it, or re-run `schedule install`).",
      ],
    };
  }
  if (env.platform === "win32") {
    const r = await deps.exec("schtasks", ["/Query", "/TN", WINDOWS_TASK, "/FO", "LIST"]);
    return { ok: true, lines: r.stdout.trim().split(/\r?\n/).filter(Boolean) };
  }
  const r = await deps.exec("systemctl", [
    "--user",
    "list-timers",
    `${SYSTEMD_UNIT}.timer`,
    "--no-pager",
  ]);
  return { ok: true, lines: r.stdout.trim().split(/\r?\n/).filter(Boolean) };
}
