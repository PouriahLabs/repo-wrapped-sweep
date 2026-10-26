import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { SweepEnv } from "../src/env";
import type { Exec } from "../src/platform";
import {
  LAUNCH_LABEL,
  SYSTEMD_UNIT,
  WINDOWS_TASK,
  formatTime,
  fullDiskAccessInstructions,
  installSchedule,
  isScheduleInstalled,
  launchAgentPath,
  pickStartTime,
  probeProtectedFolders,
  quoteSystemd,
  quoteWindowsToken,
  renderLaunchAgentPlist,
  renderSchtasksCreate,
  renderSystemdUnits,
  resolveInvocation,
  scheduleStatus,
  scheduledArgs,
  systemdDir,
  uninstallSchedule,
  type ScheduleDeps,
} from "../src/schedule";
import { makeFixture, type Fixture } from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

const START = { hour: 10, minute: 7 };
const NODE_INV = { program: "/usr/local/bin/node", args: ["/opt/sweep/dist/index.js"] };
const BIN_INV = { program: "/usr/local/bin/repo-wrapped-sweep", args: [] };

describe("invocation + args + start time", () => {
  it("runs a Node install as `node <script>` and a compiled binary as itself", () => {
    expect(resolveInvocation("dist/index.js", "/usr/bin/node")).toEqual({
      program: "/usr/bin/node",
      args: [path.resolve("dist/index.js")],
    });
    expect(
      resolveInvocation("C:\\x\\index.js", "C:\\Program Files\\nodejs\\node.exe").program,
    ).toMatch(/node\.exe$/);
    expect(resolveInvocation("/ignored", "/opt/bin/repo-wrapped-sweep")).toEqual({
      program: "/opt/bin/repo-wrapped-sweep",
      args: [],
    });
    expect(resolveInvocation(undefined, "/usr/bin/node")).toEqual({
      program: "/usr/bin/node",
      args: [],
    });
  });

  it("scheduled runs are quiet and flagged unattended; --upload only when asked", () => {
    expect(scheduledArgs({ upload: false })).toEqual(["--quiet", "--scheduled"]);
    expect(scheduledArgs({ upload: true })).toEqual(["--quiet", "--scheduled", "--upload"]);
    expect(scheduledArgs({ upload: true })).not.toContain("--validate");
  });

  it("picks a stable start time within 12:00 ± 3 h", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 300; i++) {
      const t = pickStartTime(`host-${i}`);
      expect(t.hour).toBeGreaterThanOrEqual(9);
      expect(t.hour).toBeLessThanOrEqual(14);
      expect(t.minute).toBeGreaterThanOrEqual(0);
      expect(t.minute).toBeLessThan(60);
      seen.add(formatTime(t));
      expect(pickStartTime(`host-${i}`)).toEqual(t); // deterministic
    }
    expect(seen.size).toBeGreaterThan(100); // spread out, not a stampede
    expect(formatTime({ hour: 9, minute: 5 })).toBe("09:05");
  });
});

describe("macOS LaunchAgent plist", () => {
  it("renders the agent (snapshot)", () => {
    expect(
      renderLaunchAgentPlist({
        invocation: NODE_INV,
        args: scheduledArgs({ upload: true }),
        start: START,
        logPath: "/Users/me/.repo-wrapped/sweep.log",
      }),
    ).toMatchSnapshot();
  });
  it("escapes XML-special characters in paths", () => {
    const xml = renderLaunchAgentPlist({
      invocation: { program: "/Apps/A&B <x>/sweep", args: [] },
      args: [],
      start: START,
      logPath: "/l",
    });
    expect(xml).toContain("/Apps/A&amp;B &lt;x&gt;/sweep");
    expect(xml).not.toContain("A&B");
  });
});

describe("Windows schtasks", () => {
  it("renders the create argv (snapshot), quoting a path with spaces", () => {
    const argv = renderSchtasksCreate({
      invocation: {
        program: "C:\\Program Files\\nodejs\\node.exe",
        args: ["C:\\Users\\me\\sweep\\dist\\index.js"],
      },
      args: scheduledArgs({ upload: true }),
      start: START,
    });
    expect(argv).toMatchSnapshot();
    expect(argv.slice(0, 6)).toEqual(["/Create", "/SC", "DAILY", "/TN", WINDOWS_TASK, "/TR"]);
    expect(argv.at(-1)).toBe("/F");
  });
  it("quotes only tokens that need it", () => {
    expect(quoteWindowsToken("--quiet")).toBe("--quiet");
    expect(quoteWindowsToken("C:\\a b\\c.exe")).toBe('"C:\\a b\\c.exe"');
    expect(quoteWindowsToken('say "hi"')).toBe('"say \\"hi\\""');
  });
});

describe("Linux systemd user timer", () => {
  it("renders the service and timer (snapshot)", () => {
    expect(
      renderSystemdUnits({
        invocation: BIN_INV,
        args: scheduledArgs({ upload: false }),
        start: START,
      }),
    ).toMatchSnapshot();
  });
  it("quotes ExecStart words with spaces", () => {
    expect(quoteSystemd("/usr/bin/node")).toBe("/usr/bin/node");
    expect(quoteSystemd("/opt/my tools/sweep")).toBe('"/opt/my tools/sweep"');
    const { service } = renderSystemdUnits({
      invocation: { program: "/opt/my tools/sweep", args: [] },
      args: ["--quiet"],
      start: START,
    });
    expect(service).toContain('ExecStart="/opt/my tools/sweep" --quiet');
    expect(service).toContain("Type=oneshot");
  });
});

// ---------------------------------------------------------------------------
// Runners (mocked exec + real fs in a temp home)
// ---------------------------------------------------------------------------

interface Call {
  cmd: string;
  args: string[];
}
function deps(
  platform: NodeJS.Platform,
  over: Partial<ScheduleDeps> = {},
  results: Record<string, number> = {},
) {
  const calls: Call[] = [];
  const exec: Exec = async (cmd, args) => {
    calls.push({ cmd, args });
    return { code: results[cmd] ?? 0, stdout: "", stderr: results[cmd] ? "failed" : "" };
  };
  const env: SweepEnv = { ...fx.env, platform };
  const d: ScheduleDeps = {
    env,
    exec,
    invocation: NODE_INV,
    seed: "test-seed",
    uid: 501,
    readdir: () => {},
    ...over,
  };
  return { d, calls };
}

describe("installSchedule — macOS", () => {
  it("writes the plist, (re)bootstraps it in the user's gui domain and notes Full Disk Access", async () => {
    fx = makeFixture();
    const { d, calls } = deps("darwin");
    const r = await installSchedule({ upload: true }, d);
    expect(r.ok).toBe(true);
    const plist = fs.readFileSync(launchAgentPath(d.env), "utf8");
    expect(plist).toContain(LAUNCH_LABEL);
    expect(plist).toContain("<string>--upload</string>");
    expect(plist).toContain("<string>--scheduled</string>");
    expect(calls.map((c) => [c.cmd, c.args[0]])).toEqual([
      ["launchctl", "bootout"],
      ["launchctl", "bootstrap"],
    ]);
    expect(calls[1]!.args).toEqual(["bootstrap", "gui/501", launchAgentPath(d.env)]);
    expect(r.lines.join("\n")).toMatch(/Full Disk Access/);
  });

  it("probes protected folders and prints the exact System Settings path + binary on failure", async () => {
    fx = makeFixture();
    const denied = (dir: string) => {
      if (/Documents|Desktop$/.test(dir))
        throw Object.assign(new Error("EPERM"), { code: "EPERM" });
    };
    const { d } = deps("darwin", { readdir: denied });
    const r = await installSchedule({ upload: false }, d);
    const text = r.lines.join("\n");
    expect(text).toContain("System Settings → Privacy & Security → Full Disk Access");
    expect(text).toContain("~/Documents");
    expect(text).toContain("~/Desktop");
    expect(text).not.toContain("~/Downloads");
    expect(text).toContain(NODE_INV.program);
  });

  it("reports a launchctl failure but keeps the written plist", async () => {
    fx = makeFixture();
    const { d } = deps("darwin", {}, { launchctl: 5 });
    const r = await installSchedule({ upload: false }, d);
    expect(r.ok).toBe(false);
    expect(r.lines.join("\n")).toContain("launchctl could not load");
    expect(fs.existsSync(launchAgentPath(d.env))).toBe(true);
  });
});

describe("installSchedule — Windows", () => {
  it("creates the daily task with schtasks", async () => {
    fx = makeFixture();
    const { d, calls } = deps("win32");
    const r = await installSchedule({ upload: true }, d);
    expect(r.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.cmd).toBe("schtasks");
    expect(calls[0]!.args).toContain(WINDOWS_TASK);
    expect(calls[0]!.args.join(" ")).toContain("--scheduled");
    expect(r.lines[0]).toMatch(/runs daily at \d\d:\d\d/);
    const bad = await installSchedule({ upload: true }, deps("win32", {}, { schtasks: 1 }).d);
    expect(bad.ok).toBe(false);
  });
});

describe("installSchedule — Linux", () => {
  it("writes the service + timer and enables the user timer", async () => {
    fx = makeFixture();
    const { d, calls } = deps("linux");
    const r = await installSchedule({ upload: false }, d);
    expect(r.ok).toBe(true);
    const dir = systemdDir(d.env);
    expect(fs.readFileSync(path.join(dir, `${SYSTEMD_UNIT}.service`), "utf8")).toContain(
      "--scheduled",
    );
    expect(fs.readFileSync(path.join(dir, `${SYSTEMD_UNIT}.timer`), "utf8")).toContain(
      "OnCalendar=",
    );
    expect(calls.map((c) => c.args.join(" "))).toEqual([
      "--user daemon-reload",
      `--user enable --now ${SYSTEMD_UNIT}.timer`,
    ]);
  });
});

describe("uninstall / status / isInstalled", () => {
  it("removes what install wrote on each OS and is a no-op when nothing is installed", async () => {
    fx = makeFixture();
    const mac = deps("darwin");
    await installSchedule({ upload: false }, mac.d);
    expect(await isScheduleInstalled(mac.d)).toBe(true);
    expect((await uninstallSchedule(mac.d)).lines[0]).toMatch(/Removed/);
    expect(fs.existsSync(launchAgentPath(mac.d.env))).toBe(false);
    expect((await uninstallSchedule(mac.d)).lines[0]).toMatch(/No schedule/);

    const lin = deps("linux");
    await installSchedule({ upload: false }, lin.d);
    expect(await isScheduleInstalled(lin.d)).toBe(true);
    await uninstallSchedule(lin.d);
    expect(fs.existsSync(path.join(systemdDir(lin.d.env), `${SYSTEMD_UNIT}.timer`))).toBe(false);
    expect(await isScheduleInstalled(lin.d)).toBe(false);

    const win = deps("win32");
    expect((await uninstallSchedule(win.d)).lines[0]).toMatch(/Removed scheduled task/);
    expect(win.calls[0]!.args).toEqual(["/Delete", "/TN", WINDOWS_TASK, "/F"]);
    expect((await uninstallSchedule(deps("win32", {}, { schtasks: 1 }).d)).lines[0]).toMatch(
      /No schedule/,
    );
  });

  it("reports status", async () => {
    fx = makeFixture();
    expect((await scheduleStatus(deps("linux").d)).lines).toEqual(["No schedule installed."]);
    const mac = deps("darwin");
    await installSchedule({ upload: false }, mac.d);
    const s = await scheduleStatus(mac.d);
    expect(s.lines.join("\n")).toContain(launchAgentPath(mac.d.env));
    expect(s.lines.join("\n")).toContain("Loaded in launchd");
    const win = deps("win32");
    expect(await isScheduleInstalled(win.d)).toBe(true); // schtasks /Query succeeded
  });
});

describe("Full Disk Access probe", () => {
  it("lists only folders that exist but are blocked", () => {
    const env = { home: "/Users/me" };
    const throwing = (code: string) => (dir: string) => {
      if (dir.endsWith("Documents")) throw Object.assign(new Error(code), { code });
      if (dir.endsWith("Desktop")) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    };
    expect(probeProtectedFolders(env, throwing("EPERM"))).toEqual(["Documents"]);
    expect(probeProtectedFolders(env, throwing("EACCES"))).toEqual(["Documents"]);
    expect(probeProtectedFolders(env, () => {})).toEqual([]);
    expect(fullDiskAccessInstructions("/bin/x", ["Documents"]).join("\n")).toContain("/bin/x");
  });
});
