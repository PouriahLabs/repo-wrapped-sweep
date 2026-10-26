// Command dispatch for `repo-wrapped-sweep`. Kept separate from `index.ts` (the
// process entry) so tests can drive `main()` with an injected env and streams.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";
import pkg from "../package.json";
import {
  defaultBaselinePath,
  diffAgainstBaseline,
  loadBaseline,
  saveBaseline,
  updateBaseline,
} from "./baseline";
import { loadDevice, loadMdmConfig, resolveApiBase, resolveSalt } from "./device";
import { currentEnv, expandPath, type SweepEnv } from "./env";
import { enrol, reportFailure, runEnrol } from "./enrol-cmd";
import { runFix } from "./fix";
import { keychainFor, realExec, trashFor, ttyPrompter, type Exec, type Prompter } from "./platform";
import {
  installSchedule,
  isScheduleInstalled,
  resolveInvocation,
  scheduleStatus,
  uninstallSchedule,
  type ScheduleDeps,
} from "./schedule";
import {
  VALIDATE_WARNING,
  checkSecret,
  providerFor,
  rankByValidity,
  type HttpFetch,
  type Validity,
} from "./validate";
import {
  HOOK_COMMAND,
  hookInstalled,
  installHook,
  runHookCheck,
  settingsPath,
  uninstallHook,
  type HookScope,
} from "./hook";
import { buildJsonReport, exitCodeFor, parseFailOn, renderHtml, renderTable } from "./report";
import { recoverSecret, scan } from "./scan";
import { loadConfig } from "./state";
import { buildIngestBody, uploadRun, type FetchLike } from "./upload";

export const VERSION: string = pkg.version;

export interface CliIO {
  stdout: { write(s: string): unknown; isTTY?: boolean; columns?: number };
  stderr: { write(s: string): unknown; isTTY?: boolean };
  /** Reads piped stdin (the hook JSON). Injected by tests. */
  readStdin?: () => Promise<string>;
  /** HTTP client for enrol/upload. Injected by tests. */
  fetch?: FetchLike;
  sleep?: (ms: number) => Promise<void>;
  /** Process runner for the OS trash / keychain / scheduler. Injected by tests. */
  exec?: Exec;
  /** Confirmation prompts for `fix`. Injected by tests. */
  prompt?: Prompter;
  /** HTTP client for `--validate`. Injected by tests. */
  validateFetch?: HttpFetch;
}

const HELP = `repo-wrapped-sweep ${VERSION}
Sweep this machine for plaintext secrets. Local-first: the raw secret never
leaves the process — reports carry a masked preview and a salted fingerprint.

Usage
  repo-wrapped-sweep [scan] [options]

Options
  --root <dir>        Directory to sweep (repeatable). Default: your home directory
  --quick             Only the high-risk locations: editor history, agent
                      transcripts, shell history, credential files, ~/.ssh,
                      Downloads and Desktop
  --exclude <glob>    Skip matching files/folders (repeatable)
  --include-cloud     Also sweep all of OneDrive / iCloud. (A redirected Documents/Desktop
                      on Windows is swept by default; online-only files are never opened)
  --no-default-excludes
                      Also walk installed-software trees the sweep skips by default
                      (Program Files, editor extensions, package caches, browser
                      profiles). node_modules, .git and OS caches stay skipped
  --all               List low-severity findings too (folded into one line by default)
  --json              Print the report as JSON (schemaVersion 1) instead of a table
  --html <file>       Also write a self-contained HTML report
  --fail-on <level>   Exit 1 at/above critical|high|medium|low, on any NEW finding
                      ("new"), or never ("none"). Default: high
  --baseline <file>   Baseline path (default ~/.repo-wrapped/sweep-baseline.json)
  --no-update         Do not write the baseline after the run
  --concurrency <n>   Parallel readers (default 8)
  --progress          Print a running file count to stderr
  --quiet             No table (exit code only)
  --upload            After the sweep, upload METADATA to your Repo Wrapped account
                      (fingerprints, masked previews, location counts — never the secret)
  --validate          Interactive only: ask each key's own provider (GitHub, Anthropic,
                      OpenAI, Stripe, Slack) whether it still works, and rank live keys
                      first. Sends the key to that provider; never used in scheduled runs
  -h, --help          Show this help
  -v, --version       Print the version

Enrol this machine (optional — every command works without an account)
  repo-wrapped-sweep enrol <token> [--label <name>] [--share-paths] [--api <url>]
                      Token from Workspace → Endpoints (rwd_…) or an org admin (rwo_…).
                      --share-paths also uploads home-relative paths (off by default;
                      for an org token the admin's setting applies).

Fix a finding
  repo-wrapped-sweep fix <fingerprint> [--yes]
                      Store the secret in the OS keychain, move its copies to the Trash
                      (never deleted), print the rotation link, re-sweep and mark it
                      resolved. Asks before every destructive step; --yes skips the
                      prompts for Trash moves only — never for the keychain.

Daily schedule
  repo-wrapped-sweep schedule install --daily [--upload]
  repo-wrapped-sweep schedule uninstall
  repo-wrapped-sweep schedule status

Agent guard (Claude Code PreToolUse hook)
  repo-wrapped-sweep hook install [--scope user|project]
  repo-wrapped-sweep hook uninstall [--scope user|project]
  repo-wrapped-sweep hook status
  repo-wrapped-sweep hook check        (invoked by Claude Code; JSON on stdin)

Exit codes: 0 clean · 1 findings at/above --fail-on · 2 run error
`;

export async function main(
  argv: string[],
  io: CliIO = { stdout: process.stdout, stderr: process.stderr },
  env: SweepEnv = currentEnv(),
  cwd: string = process.cwd(),
): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        root: { type: "string", multiple: true },
        quick: { type: "boolean" },
        exclude: { type: "string", multiple: true },
        "include-cloud": { type: "boolean" },
        "no-default-excludes": { type: "boolean" },
        all: { type: "boolean" },
        json: { type: "boolean" },
        html: { type: "string" },
        "fail-on": { type: "string" },
        baseline: { type: "string" },
        "no-update": { type: "boolean" },
        concurrency: { type: "string" },
        scope: { type: "string" },
        command: { type: "string" },
        progress: { type: "boolean" },
        quiet: { type: "boolean" },
        upload: { type: "boolean" },
        validate: { type: "boolean" },
        scheduled: { type: "boolean" },
        yes: { type: "boolean", short: "y" },
        daily: { type: "boolean" },
        "share-paths": { type: "boolean" },
        label: { type: "string" },
        api: { type: "string" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });
  } catch (err) {
    io.stderr.write(`${(err as Error).message}\n\n${HELP}`);
    return 2;
  }
  const { values, positionals } = parsed;

  if (values.help) {
    io.stdout.write(HELP);
    return 0;
  }
  if (values.version) {
    io.stdout.write(`${VERSION}\n`);
    return 0;
  }

  const command = positionals[0] ?? "scan";
  if (command === "hook") {
    return runHookCommand(
      positionals[1],
      { scope: values.scope, command: values.command },
      io,
      env,
      cwd,
    );
  }
  if (command === "enrol") {
    return runEnrol(
      positionals[1],
      { api: values.api, label: values.label, sharePaths: values["share-paths"] },
      io,
      env,
      VERSION,
    );
  }
  if (command === "fix") {
    return runFixCommand(positionals[1], values.yes === true, values.baseline, io, env);
  }
  if (command === "schedule") {
    return runScheduleCommand(positionals[1], values, io, env);
  }
  if (command !== "scan") {
    io.stderr.write(`unknown command "${command}"\n\n${HELP}`);
    return 2;
  }

  const failOn = parseFailOn(values["fail-on"]);
  if (!failOn) {
    io.stderr.write(
      `invalid --fail-on "${values["fail-on"]}" (use critical|high|medium|low|new|none)\n`,
    );
    return 2;
  }
  const concurrency = values.concurrency === undefined ? 8 : Number(values.concurrency);
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 64) {
    io.stderr.write("invalid --concurrency (use an integer from 1 to 64)\n");
    return 2;
  }

  try {
    return await runScan({ values, env, io, failOn, concurrency });
  } catch (err) {
    io.stderr.write(`sweep failed: ${(err as Error).message}\n`);
    return 2;
  }
}

interface ScanArgs {
  values: {
    root?: string[];
    quick?: boolean;
    exclude?: string[];
    "include-cloud"?: boolean;
    "no-default-excludes"?: boolean;
    all?: boolean;
    json?: boolean;
    html?: string;
    baseline?: string;
    "no-update"?: boolean;
    progress?: boolean;
    quiet?: boolean;
    upload?: boolean;
    validate?: boolean;
    scheduled?: boolean;
    api?: string;
  };
  env: SweepEnv;
  io: CliIO;
  failOn: NonNullable<ReturnType<typeof parseFailOn>>;
  concurrency: number;
}

async function runScan({ values, env, io, failOn, concurrency }: ScanArgs): Promise<number> {
  // Decision E3: validity checks send a secret to its provider, so they are for an
  // interactive human only — never a scheduled or MDM-driven run.
  if (values.validate && values.scheduled) {
    io.stderr.write(
      "--validate cannot be used in a scheduled run: a background job must not send the secrets it finds to their providers.\n",
    );
    return 2;
  }
  const config = loadConfig(env, (m) => io.stderr.write(`warning: ${m}\n`));
  const cliRoots = (values.root ?? []).map((r) => path.resolve(expandPath(r, env)));
  const roots =
    cliRoots.length > 0 ? cliRoots : config.roots.map((r) => path.resolve(expandPath(r, env)));
  for (const r of roots) {
    if (!fs.existsSync(r)) io.stderr.write(`warning: root not found: ${r}\n`);
  }

  // An enrolled device fingerprints with its scope's salt (the org's, or the
  // user's own) so the same secret groups across machines. An MDM-pushed enrol
  // token enrols the machine itself on first run.
  const mdm = loadMdmConfig(env);
  let device = loadDevice(env);
  if (!device && mdm?.enrolToken) {
    device = await enrol(
      mdm.enrolToken,
      { api: values.api, sharePaths: mdm.sharePaths },
      { stdout: io.stdout, stderr: io.stderr, fetch: io.fetch, sleep: io.sleep },
      env,
      VERSION,
    );
  }
  // MDM can also ask for the daily schedule; install it once (best-effort).
  if (mdm?.schedule === true) {
    await ensureScheduled({ upload: mdm.upload === true }, io, env);
  }
  const salt = resolveSalt(env, device);
  const baselinePath = values.baseline ? path.resolve(values.baseline) : defaultBaselinePath(env);
  const previous = loadBaseline(baselinePath);

  const tty = io.stderr.isTTY === true;
  let result = await scan({
    env,
    roots,
    quick: values.quick === true,
    excludeGlobs: [...config.exclude, ...(values.exclude ?? [])],
    includeCloud: values["include-cloud"] === true,
    noDefaultExcludes: values["no-default-excludes"] === true,
    concurrency,
    salt,
    onProgress: values.progress
      ? (n) =>
          io.stderr.write(
            tty ? `\rscanned ${n.toLocaleString("en-US")} files` : `scanned ${n} files\n`,
          )
      : undefined,
  });
  if (values.progress && tty) io.stderr.write("\n");

  // --validate: ask each key's own provider whether it still works, then float the
  // live ones to the top. Interactive only (guarded above).
  let validity: ReadonlyMap<string, Validity> | undefined;
  if (values.validate) {
    validity = await validateGroups(result.groups, salt, env, io);
    result = { ...result, groups: rankByValidity(result.groups, validity) };
  }

  const diff = diffAgainstBaseline(result.groups, previous, result.scope);
  const ctx = { version: VERSION, os: env.platform, diff, validity };

  if (values.html) {
    fs.writeFileSync(path.resolve(values.html), renderHtml(result, ctx));
    io.stderr.write(`wrote ${path.resolve(values.html)}\n`);
  }
  if (values.json) {
    io.stdout.write(`${JSON.stringify(buildJsonReport(result, ctx), null, 2)}\n`);
  } else if (!values.quiet) {
    const color = io.stdout.isTTY === true && !process.env.NO_COLOR;
    io.stdout.write(
      `${renderTable(result, ctx, { color, width: io.stdout.columns ?? 120, all: values.all === true })}\n`,
    );
  }

  if (!values["no-update"]) {
    saveBaseline(
      baselinePath,
      updateBaseline(result.groups, previous, result.scope, result.finishedAt),
    );
  }

  if (values.upload === true || mdm?.upload === true) {
    await uploadResult(result, device, values, io, validity);
  }
  return exitCodeFor(result.groups, failOn, diff);
}

/** One outbound call per recognised key, sequential, 5 s each, never retried. */
async function validateGroups(
  groups: Awaited<ReturnType<typeof scan>>["groups"],
  salt: Uint8Array,
  env: SweepEnv,
  io: CliIO,
): Promise<Map<string, Validity>> {
  const out = new Map<string, Validity>();
  let warned = false;
  for (const g of groups) {
    // Recover the secret LOCALLY from a copy; it never leaves these locals except
    // to its own provider.
    let secret: string | null = null;
    for (const loc of g.locations.slice(0, 5)) {
      secret = await recoverSecret(
        expandPath(loc.path, env),
        loc.locationClass,
        g.fingerprint,
        salt,
      );
      if (secret !== null) break;
    }
    if (secret === null) {
      out.set(g.fingerprint, "unknown");
      continue;
    }
    if (!warned && providerFor(secret) !== null) {
      io.stderr.write(`${VALIDATE_WARNING}\n`);
      warned = true;
    }
    const r = await checkSecret(secret, io.validateFetch);
    secret = null;
    out.set(g.fingerprint, r.validity);
  }
  return out;
}

/** Upload failures never change the exit code: the sweep itself succeeded. */
async function uploadResult(
  result: Awaited<ReturnType<typeof scan>>,
  device: ReturnType<typeof loadDevice>,
  values: { quiet?: boolean; api?: string },
  io: CliIO,
  validity?: ReadonlyMap<string, Validity>,
): Promise<void> {
  if (!device) {
    io.stderr.write(
      "not uploaded: this machine is not enrolled. Run `repo-wrapped-sweep enrol <token>`.\n",
    );
    return;
  }
  let body;
  try {
    body = buildIngestBody(result, {
      cliVersion: VERSION,
      platform: process.platform,
      sharePaths: device.sharePaths,
      validity,
    });
  } catch (err) {
    io.stderr.write(`not uploaded: ${(err as Error).message}\n`);
    return;
  }
  const apiBase = resolveApiBase({ flag: values.api, device });
  const outcome = await uploadRun({ ...device, apiBase }, body, {
    fetch: io.fetch,
    sleep: io.sleep,
  });
  if (!outcome.ok) {
    reportFailure(io, "upload failed", outcome);
    return;
  }
  if (!values.quiet) {
    const n = body.findings.length;
    io.stderr.write(
      `uploaded ${n} finding${n === 1 ? "" : "s"} (metadata only${
        device.sharePaths ? ", with home-relative paths" : ", no paths"
      })\n`,
    );
  }
}

// ---------------------------------------------------------------------------
// hook subcommands
// ---------------------------------------------------------------------------

async function readProcessStdin(): Promise<string> {
  if (process.stdin.isTTY) return "";
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    // Claude Code closes stdin after writing; the timeout only guards a stuck pipe.
    const timer = setTimeout(() => done(), 2000);
    const done = () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks).toString("utf8"));
    };
    process.stdin.on("data", (c: Buffer) => chunks.push(c));
    process.stdin.on("end", done);
    process.stdin.on("error", done);
  });
}

async function runHookCommand(
  sub: string | undefined,
  flags: { scope?: string; command?: string },
  io: CliIO,
  env: SweepEnv,
  cwd: string,
): Promise<number> {
  if (sub === "check") {
    const r = runHookCheck(await (io.readStdin ?? readProcessStdin)(), env, cwd);
    if (r.stderr) io.stderr.write(r.stderr);
    return r.code;
  }
  if (sub === "status") {
    for (const scope of ["user", "project"] as const) {
      const file = settingsPath(scope, env, cwd);
      io.stdout.write(
        `${scope.padEnd(8)} ${hookInstalled(file) ? "installed  " : "not installed"}  ${file}\n`,
      );
    }
    return 0;
  }
  if (sub === "install" || sub === "uninstall") {
    const scope = (flags.scope ?? "user") as HookScope;
    if (scope !== "user" && scope !== "project") {
      io.stderr.write(`invalid --scope "${flags.scope}" (use user or project)\n`);
      return 2;
    }
    const file = settingsPath(scope, env, cwd);
    try {
      if (sub === "install") {
        const r = installHook(file, flags.command ?? HOOK_COMMAND);
        io.stdout.write(
          r.changed
            ? `installed the agent guard in ${file}\n`
            : `agent guard already installed in ${file}\n`,
        );
      } else {
        const r = uninstallHook(file);
        io.stdout.write(
          r.removed > 0
            ? `removed the agent guard from ${file}\n`
            : `agent guard not installed in ${file}\n`,
        );
      }
      return 0;
    } catch (err) {
      io.stderr.write(`${(err as Error).message}\n`);
      return 2;
    }
  }
  io.stderr.write(`usage: repo-wrapped-sweep hook <install|uninstall|status|check>\n`);
  return 2;
}

// ---------------------------------------------------------------------------
// fix / schedule subcommands
// ---------------------------------------------------------------------------

async function runFixCommand(
  fingerprint: string | undefined,
  yes: boolean,
  baselineFlag: string | undefined,
  io: CliIO,
  env: SweepEnv,
): Promise<number> {
  if (!fingerprint) {
    io.stderr.write("usage: repo-wrapped-sweep fix <fingerprint> [--yes]\n");
    return 2;
  }
  const exec = io.exec ?? realExec;
  const salt = resolveSalt(env);
  const config = loadConfig(env);
  try {
    return await runFix(fingerprint, {
      env,
      io,
      baselinePath: baselineFlag ? path.resolve(baselineFlag) : defaultBaselinePath(env),
      prompt: io.prompt ?? ttyPrompter(),
      trash: trashFor(env, exec),
      keychain: keychainFor(env, exec),
      yes,
      recover: (abs, cls, fp) => recoverSecret(abs, cls, fp, salt),
      rescan: (paths) =>
        scan({
          env,
          roots: paths,
          quick: false,
          excludeGlobs: config.exclude,
          includeCloud: true, // the user named these exact paths
          concurrency: 4,
          salt,
        }),
    });
  } catch (err) {
    io.stderr.write(`fix failed: ${(err as Error).message}\n`);
    return 2;
  }
}

function scheduleDeps(env: SweepEnv, io: CliIO): ScheduleDeps {
  return {
    env,
    exec: io.exec ?? realExec,
    invocation: resolveInvocation(process.argv[1], process.execPath),
    seed: `${os.hostname()}|${env.home}`,
    uid: typeof process.getuid === "function" ? process.getuid() : undefined,
  };
}

async function runScheduleCommand(
  sub: string | undefined,
  values: { daily?: boolean; upload?: boolean },
  io: CliIO,
  env: SweepEnv,
): Promise<number> {
  if (sub !== "install" && sub !== "uninstall" && sub !== "status") {
    io.stderr.write(
      "usage: repo-wrapped-sweep schedule <install --daily [--upload] | uninstall | status>\n",
    );
    return 2;
  }
  if (sub === "install" && !values.daily) {
    io.stderr.write("schedule install needs --daily (the only schedule in v1)\n");
    return 2;
  }
  const deps = scheduleDeps(env, io);
  const r =
    sub === "install"
      ? await installSchedule({ upload: values.upload === true }, deps)
      : sub === "uninstall"
        ? await uninstallSchedule(deps)
        : await scheduleStatus(deps);
  for (const line of r.lines) (r.ok ? io.stdout : io.stderr).write(`${line}\n`);
  return r.ok ? 0 : 2;
}

/** MDM `schedule: true`: install the daily task once, never fail the sweep over it. */
async function ensureScheduled(opts: { upload: boolean }, io: CliIO, env: SweepEnv): Promise<void> {
  try {
    const deps = scheduleDeps(env, io);
    if (await isScheduleInstalled(deps)) return;
    const r = await installSchedule(opts, deps);
    if (!r.ok) io.stderr.write(`schedule not installed: ${r.lines[0] ?? "unknown error"}\n`);
  } catch (err) {
    io.stderr.write(`schedule not installed: ${(err as Error).message}\n`);
  }
}
