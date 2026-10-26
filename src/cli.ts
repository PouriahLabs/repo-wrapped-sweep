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
import { currentEnv, displayPath, expandPath, type SweepEnv } from "./env";
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
import { INSIGHT_SECTIONS, collectInsights, type InsightSection } from "./insights";
import {
  AI_GROUP_BYS,
  buildAiJson,
  buildAiReport,
  parseSince,
  renderAiText,
  type AiGroupBy,
} from "./insights/ai-report";
import { collectAiUsage, repoResolver } from "./insights/ai-usage";
import {
  SKIP_LABELS,
  byProject,
  cleanLogPath,
  parseOlderThan,
  planClean,
  planJson,
  pruneCache,
  removeTarget,
  renderPlanText,
} from "./insights/clean";
import { Discovery, discover } from "./insights/discover";
import { formatBytes } from "./insights/disk";
import { buildMachineWrapped } from "@/lib/endpoint/insights/machine-wrapped";
import { buildShareBody } from "@/lib/endpoint/insights/wrapped-wire";
import {
  collectYearCommits,
  findBrowser,
  localParts,
  readDiskReclaimed,
  renderPng,
  renderWrappedHtml,
  renderWrappedText,
  shareRefusal,
  yearBounds,
} from "./wrapped";
import {
  buildInsightsJson,
  buildJsonReport,
  exitCodeFor,
  parseFailOn,
  renderHtml,
  renderInsightsHtml,
  renderInsightsSummary,
  renderInsightsText,
  renderTable,
} from "./report";
import { recoverSecret, scan } from "./scan";
import { loadConfig } from "./state";
import {
  MAX_UPLOAD_BODY_BYTES,
  buildIngestBody,
  shareWrapped,
  uploadRun,
  type FetchLike,
} from "./upload";
import { collectUploadInsights, saveUploadCursor } from "./insights/upload";
import type { InsightsBlock } from "@/lib/endpoint/insights/wire";

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
  /** Locates Chrome/Edge for `wrapped --png`. Injected by tests. */
  findBrowser?: (env: SweepEnv) => string | null;
  /** A human can answer questions on this terminal (default: stdin is a TTY). `disk clean`
   *  asks per project only then; otherwise, without --yes, it is a dry run. */
  interactive?: boolean;
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
  --no-insights       Skip the machine-insights summary a full sweep prints after the table,
                      and the insights block (counts, versions, token totals) --upload sends
  -h, --help          Show this help
  -v, --version       Print the version

Machine insights (local only — nothing is uploaded, no network; only disk clean changes anything)
  repo-wrapped-sweep git [--fetch] [--all]
                      Clones with work that exists only on this machine: unpushed commits,
                      no remote, uncommitted changes, old stashes, far behind upstream.
                      "Behind" is as of the last fetch; --fetch runs git fetch first
  repo-wrapped-sweep disk
                      Regenerable build output and caches by size (node_modules, .next,
                      target, …) and how much sits in projects untouched for 30+ days
  repo-wrapped-sweep disk clean [--yes] [--older-than 30d] [--include-venv]
                      [--include-npm-cache] [--dry-run] [--all] [--json]
                      Delete those folders in projects untouched for --older-than. A DRY RUN
                      unless --yes; at a terminal without --yes it asks per project. Only
                      folders next to the file that rebuilds them (lockfile, Cargo.toml, …),
                      never dist/, out/, .venv (unless --include-venv), Docker or anything
                      outside home; never follows links; skips folders git tracks or sees
                      changes in. Package caches only via the tool's own prune (pnpm store
                      prune, yarn cache clean, pip cache purge; npm only with
                      --include-npm-cache). Deletes permanently (not to the Trash) and logs
                      every action to ~/.repo-wrapped/clean-log.jsonl. Never scheduled
  repo-wrapped-sweep toolchain [--all]
                      Installed runtimes and CLIs (local --version probes), and repo pins
                      (.nvmrc, engines, packageManager, …) they don't satisfy
  repo-wrapped-sweep backup [--all]
                      Project folders that are neither in a synced folder nor pushed
  repo-wrapped-sweep insights
                      All four. Each takes --root, --exclude, --include-cloud,
                      --concurrency, --json and --html <file>
  repo-wrapped-sweep ai [--since 30d|YYYY-MM-DD] [--by repo|day|model] [--json]
                      Claude Code and Codex sessions, tokens and API-equivalent cost per
                      repo, day or model. Reads token counts, models, times and working
                      directories from the transcripts — never message text. Incremental
                      (~/.repo-wrapped/ai-cursor.json); lines over 64 KB are skipped (about
                      0.3% of tokens). Cost is what the API would charge, not a bill
  repo-wrapped-sweep wrapped [--year 2026] [--out <file.html>] [--png] [--share]
                      The year on this machine as a self-contained HTML card (commits,
                      languages, AI sessions and share, busiest day/hour, streak).
                      --png also screenshots it with a Chrome/Edge already installed.
                      Aggregates only — no repo names; nothing is uploaded unless --share
                      --share (Pro, personal enrolled device, you at a terminal) publishes
                      that year's aggregate card as a section of your public Contributor
                      Wrapped at /dev/<login>: counts, language shares, token totals and
                      the top model — never repo names, paths, email or message text. One
                      year per run; run it again to update, unpublish from Workspace →
                      Endpoints → Machine. Never from a schedule or when your administrator
                      has turned insights off

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
        "no-insights": { type: "boolean" },
        fetch: { type: "boolean" },
        since: { type: "string" },
        by: { type: "string" },
        year: { type: "string" },
        out: { type: "string" },
        png: { type: "boolean" },
        share: { type: "boolean" },
        scheduled: { type: "boolean" },
        yes: { type: "boolean", short: "y" },
        "older-than": { type: "string" },
        "include-venv": { type: "boolean" },
        "include-npm-cache": { type: "boolean" },
        "dry-run": { type: "boolean" },
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
  if (command === "ai" || command === "wrapped") {
    if (positionals.length > 1) {
      io.stderr.write(`usage: repo-wrapped-sweep ${command} [options] (see --help)
`);
      return 2;
    }
    try {
      return command === "ai"
        ? await runAiCommand(values, env, io)
        : await runWrappedCommand(values, env, io, cwd);
    } catch (err) {
      io.stderr.write(`${command} failed: ${(err as Error).message}
`);
      return 2;
    }
  }
  const isInsights = (INSIGHT_COMMANDS as readonly string[]).includes(command);
  if (command !== "scan" && !isInsights) {
    io.stderr.write(`unknown command "${command}"\n\n${HELP}`);
    return 2;
  }

  const concurrency = values.concurrency === undefined ? 8 : Number(values.concurrency);
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 64) {
    io.stderr.write("invalid --concurrency (use an integer from 1 to 64)\n");
    return 2;
  }
  if (command === "disk" && positionals[1] === "clean") {
    if (positionals.length > 2) {
      io.stderr.write("usage: repo-wrapped-sweep disk clean [options] (see --help)\n");
      return 2;
    }
    try {
      return await runDiskClean(values, env, io, concurrency);
    } catch (err) {
      io.stderr.write(`disk clean failed: ${(err as Error).message}\n`);
      return 2;
    }
  }
  if (isInsights) {
    if (positionals.length > 1) {
      io.stderr.write(`usage: repo-wrapped-sweep ${command} [options] (see --help)\n`);
      return 2;
    }
    try {
      return await runInsightsCommand(command as InsightCommand, values, env, io, concurrency);
    } catch (err) {
      io.stderr.write(`${command} failed: ${(err as Error).message}\n`);
      return 2;
    }
  }

  const failOn = parseFailOn(values["fail-on"]);
  if (!failOn) {
    io.stderr.write(
      `invalid --fail-on "${values["fail-on"]}" (use critical|high|medium|low|new|none)\n`,
    );
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
    "no-insights"?: boolean;
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

  // A full interactive sweep also notes what else its walk saw (repos, projects,
  // regenerable folders) and prints a short insights summary after the table. The walk
  // is shared — the observer is passive, so the findings are identical without it.
  const fullScope = !values.quick && roots.length === 0;
  const insightsOn =
    !values["no-insights"] && fullScope && !values.json && !values.quiet && !values.scheduled;
  // An upload carries the Machine Insights block (schema v2) unless --no-insights or the MDM
  // config's `insights: false` turns it off. A full-scope upload (the scheduled run included)
  // needs the walk's observer too, for the git/disk/backup sections — see insights/upload.ts.
  const wantUpload = values.upload === true || mdm?.upload === true;
  const uploadInsights = wantUpload && !values["no-insights"] && mdm?.insights !== false;
  const found = insightsOn || (uploadInsights && fullScope) ? new Discovery(env) : undefined;

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
    observer: found,
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
    if (found && insightsOn) await printInsightsSummary(found, env, io, color);
  }

  if (!values["no-update"]) {
    saveBaseline(
      baselinePath,
      updateBaseline(result.groups, previous, result.scope, result.finishedAt),
    );
  }

  if (wantUpload) {
    await uploadResult(result, device, values, io, validity, {
      env,
      enabled: uploadInsights,
      found: fullScope ? found : undefined,
    });
  }
  return exitCodeFor(result.groups, failOn, diff);
}

/** The post-sweep insights block. Best-effort: it never changes the exit code. */
async function printInsightsSummary(
  found: Discovery,
  env: SweepEnv,
  io: CliIO,
  color: boolean,
): Promise<void> {
  try {
    const r = await collectInsights(found, ["git", "disk", "backup"], {
      env,
      scope: "full",
      machineWide: false,
      sizeBudgetMs: SUMMARY_SIZE_BUDGET_MS,
    });
    const text = renderInsightsSummary(r, { color });
    if (text) io.stdout.write(`\n${text}\n`);
  } catch (err) {
    io.stderr.write(`insights unavailable: ${(err as Error).message}\n`);
  }
}

// ---------------------------------------------------------------------------
// Machine insights commands (git / disk / toolchain / backup / insights)
// ---------------------------------------------------------------------------

const INSIGHT_COMMANDS = ["git", "disk", "toolchain", "backup", "insights"] as const;
type InsightCommand = (typeof INSIGHT_COMMANDS)[number];

/** Folder sizing budget for the summary after a sweep (the `disk` command gets longer). */
const SUMMARY_SIZE_BUDGET_MS = 60_000;

async function runInsightsCommand(
  command: InsightCommand,
  values: {
    root?: string[];
    exclude?: string[];
    "include-cloud"?: boolean;
    json?: boolean;
    html?: string;
    all?: boolean;
    fetch?: boolean;
  },
  env: SweepEnv,
  io: CliIO,
  concurrency: number,
): Promise<number> {
  const config = loadConfig(env, (m) => io.stderr.write(`warning: ${m}\n`));
  const cliRoots = (values.root ?? []).map((r) => path.resolve(expandPath(r, env)));
  const roots =
    cliRoots.length > 0 ? cliRoots : config.roots.map((r) => path.resolve(expandPath(r, env)));
  for (const r of roots) {
    if (!fs.existsSync(r)) io.stderr.write(`warning: root not found: ${r}\n`);
  }
  const found = await discover({
    env,
    roots,
    excludeGlobs: [...config.exclude, ...(values.exclude ?? [])],
    includeCloud: values["include-cloud"] === true,
    concurrency,
  });
  const sections: readonly InsightSection[] = command === "insights" ? INSIGHT_SECTIONS : [command];
  const result = await collectInsights(found, sections, {
    env,
    scope: roots.length === 0 ? "full" : "paths",
    fetch: values.fetch === true,
  });

  const ctx = { version: VERSION, os: env.platform };
  if (values.html) {
    fs.writeFileSync(path.resolve(values.html), renderInsightsHtml(result, ctx, env));
    io.stderr.write(`wrote ${path.resolve(values.html)}\n`);
  }
  if (values.json) {
    io.stdout.write(`${JSON.stringify(buildInsightsJson(result, ctx, env), null, 2)}\n`);
  } else {
    const color = io.stdout.isTTY === true && !process.env.NO_COLOR;
    io.stdout.write(`${renderInsightsText(result, env, { color, all: values.all === true })}\n`);
  }
  return 0;
}

// ---------------------------------------------------------------------------
// disk clean — the only command that changes the machine (src/insights/clean.ts)
// ---------------------------------------------------------------------------

async function runDiskClean(
  values: {
    root?: string[];
    exclude?: string[];
    "include-cloud"?: boolean;
    json?: boolean;
    all?: boolean;
    yes?: boolean;
    scheduled?: boolean;
    "older-than"?: string;
    "include-venv"?: boolean;
    "include-npm-cache"?: boolean;
    "dry-run"?: boolean;
  },
  env: SweepEnv,
  io: CliIO,
  concurrency: number,
): Promise<number> {
  // Never from a schedule (or the MDM-installed one): a background job must not delete.
  if (values.scheduled) {
    io.stderr.write(
      "disk clean never runs from a scheduled or MDM-driven run — run it yourself at a terminal.\n",
    );
    return 2;
  }
  const olderThanDays = parseOlderThan(values["older-than"]);
  if (olderThanDays === null) {
    io.stderr.write(
      `invalid --older-than "${values["older-than"]}" (use e.g. 30d or 8w; at least 1 day)\n`,
    );
    return 2;
  }
  const interactive = io.interactive ?? process.stdin.isTTY === true;
  const mode: "dry-run" | "yes" | "ask" =
    values["dry-run"] === true
      ? "dry-run"
      : values.yes === true
        ? "yes"
        : interactive && !values.json
          ? "ask"
          : "dry-run";

  const config = loadConfig(env, (m) => io.stderr.write(`warning: ${m}\n`));
  const cliRoots = (values.root ?? []).map((r) => path.resolve(expandPath(r, env)));
  const roots =
    cliRoots.length > 0 ? cliRoots : config.roots.map((r) => path.resolve(expandPath(r, env)));
  for (const r of roots) {
    if (!fs.existsSync(r)) io.stderr.write(`warning: root not found: ${r}\n`);
  }
  const found = await discover({
    env,
    roots,
    excludeGlobs: [...config.exclude, ...(values.exclude ?? [])],
    includeCloud: values["include-cloud"] === true,
    concurrency,
  });
  const now = Date.now();
  const collected = await collectInsights(found, ["disk"], {
    env,
    scope: roots.length === 0 ? "full" : "paths",
    now,
  });
  const plan = await planClean(collected.disk!, {
    env,
    olderThanDays,
    includeVenv: values["include-venv"] === true,
    includeNpmCache: values["include-npm-cache"] === true,
    now,
  });

  if (mode === "dry-run") {
    if (values.json) {
      io.stdout.write(
        `${JSON.stringify({ schemaVersion: 1, kind: "disk-clean", mode, ...planJson(plan, env) }, null, 2)}\n`,
      );
    } else {
      io.stdout.write(`${renderPlanText(plan, env, { now, all: values.all, dryRun: true })}\n`);
      if (plan.remove.length > 0 || plan.caches.length > 0) {
        io.stdout.write(
          interactive
            ? "\nRe-run without --dry-run to choose per project, or with --yes to delete all of the above.\n"
            : "\nRe-run with --yes to delete all of the above.\n",
        );
      }
    }
    return 0;
  }

  if (!values.json) {
    io.stdout.write(`${renderPlanText(plan, env, { now, all: values.all, dryRun: false })}\n\n`);
  }
  const prompt = io.prompt ?? ttyPrompter();
  const removals: Awaited<ReturnType<typeof removeTarget>>[] = [];
  for (const [project, targets] of byProject(plan.remove)) {
    if (mode === "ask") {
      const bytes = targets.reduce((n, t) => n + t.bytes, 0);
      const names = targets.map((t) => path.relative(project, t.path).replace(/\\/g, "/"));
      const ok = await prompt.confirm(
        `Delete ${names.join(", ")} (${formatBytes(bytes)}) in ${displayPath(project, env)}?`,
      );
      if (!ok) continue;
    }
    for (const t of targets) removals.push(await removeTarget(t, env));
  }
  const prunes: Awaited<ReturnType<typeof pruneCache>>[] = [];
  for (const c of plan.caches) {
    if (mode === "ask" && !(await prompt.confirm(`Run \`${c.argv.join(" ")}\` (${c.label})?`))) {
      continue;
    }
    prunes.push(await pruneCache(c, env));
  }

  let freed = 0;
  let failures = 0;
  const lines: string[] = [];
  for (const r of removals) {
    const where = displayPath(r.target.path, env);
    if (r.refused) {
      lines.push(`kept    ${where} — ${SKIP_LABELS[r.refused]} (re-checked before deleting)`);
    } else if (r.result) {
      freed += r.result.bytes;
      if (r.result.errors.length > 0) {
        failures++;
        lines.push(
          `partial ${where} — ${formatBytes(r.result.bytes)} freed, ${r.result.errors.length} entr${r.result.errors.length === 1 ? "y" : "ies"} could not be removed (${r.result.errors[0]})`,
        );
      } else {
        lines.push(`deleted ${where} — ${formatBytes(r.result.bytes)}`);
      }
    }
  }
  for (const p of prunes) {
    freed += p.freed;
    if (!p.ok) failures++;
    lines.push(
      p.ok
        ? `pruned  ${p.cache.label} (${p.cache.argv.join(" ")}) — ${formatBytes(p.freed)} freed`
        : `failed  ${p.cache.label} (${p.cache.argv.join(" ")}) — ${p.error}`,
    );
  }
  const acted = removals.filter((r) => r.result).length + prunes.length;
  if (values.json) {
    io.stdout.write(
      `${JSON.stringify(
        {
          schemaVersion: 1,
          kind: "disk-clean",
          mode,
          ...planJson(plan, env),
          results: [
            ...removals.map((r) => ({
              path: displayPath(r.target.path, env),
              outcome: r.refused ? "kept" : r.result!.errors.length > 0 ? "partial" : "deleted",
              reason: r.refused,
              bytes: r.result?.bytes ?? 0,
            })),
            ...prunes.map((p) => ({
              tool: p.cache.tool,
              outcome: p.ok ? "pruned" : "failed",
              bytes: p.freed,
            })),
          ],
          freedBytes: freed,
        },
        null,
        2,
      )}\n`,
    );
  } else {
    for (const l of lines) io.stdout.write(`${l}\n`);
    io.stdout.write(
      acted === 0
        ? "Nothing deleted.\n"
        : `Freed ${formatBytes(freed)}. Logged to ${displayPath(cleanLogPath(env), env)}.\n`,
    );
  }
  return failures > 0 ? 2 : 0;
}

// ---------------------------------------------------------------------------
// ai / wrapped
// ---------------------------------------------------------------------------

async function runAiCommand(
  values: { since?: string; by?: string; json?: boolean },
  env: SweepEnv,
  io: CliIO,
): Promise<number> {
  const now = Date.now();
  const by = (values.by ?? "repo") as AiGroupBy;
  if (!(AI_GROUP_BYS as readonly string[]).includes(by)) {
    io.stderr.write(`invalid --by "${values.by}" (use repo|day|model)\n`);
    return 2;
  }
  const since = parseSince(values.since, now);
  if (since === null) {
    io.stderr.write(`invalid --since "${values.since}" (use e.g. 30d or 2026-01-01)\n`);
    return 2;
  }
  const ai = await collectAiUsage({ env, now });
  if (ai.scan.zstdSkipped > 0) {
    io.stderr.write(
      `note: skipped ${ai.scan.zstdSkipped} compressed Codex session(s) — Node ${process.version} has no zstd decoder (22.15+ does)\n`,
    );
  }
  // `until` is exclusive; include an event stamped this very millisecond.
  const report = buildAiReport(ai.events, { since, until: now + 1, by, repoOf: repoResolver(env) });
  const ctx = {
    version: VERSION,
    os: env.platform,
    collectedAt: new Date(now).toISOString(),
    scan: ai.scan,
  };
  if (values.json) {
    io.stdout.write(`${JSON.stringify(buildAiJson(report, ctx), null, 2)}\n`);
  } else {
    const color = io.stdout.isTTY === true && !process.env.NO_COLOR;
    const v = (values.since ?? "30d").trim();
    const periodLabel = /d$/i.test(v) ? `last ${Number.parseInt(v, 10)} days` : `since ${v}`;
    io.stdout.write(`${renderAiText(report, ctx, { color, periodLabel })}\n`);
  }
  return 0;
}

async function runWrappedCommand(
  values: {
    year?: string;
    out?: string;
    png?: boolean;
    share?: boolean;
    scheduled?: boolean;
    api?: string;
    root?: string[];
    exclude?: string[];
    "include-cloud"?: boolean;
    concurrency?: string;
  },
  env: SweepEnv,
  io: CliIO,
  cwd: string,
): Promise<number> {
  const now = Date.now();
  const year = values.year === undefined ? new Date(now).getFullYear() : Number(values.year);
  if (!Number.isInteger(year) || year < 2000 || year > new Date(now).getFullYear()) {
    io.stderr.write(`invalid --year "${values.year}"\n`);
    return 2;
  }
  // --share is checked BEFORE the (slow) collection so a refusal costs nothing.
  const shareDevice = values.share ? loadDevice(env) : null;
  if (values.share) {
    const refusal = shareRefusal({
      scheduled: values.scheduled === true,
      mdmInsights: loadMdmConfig(env)?.insights,
      device: shareDevice,
    });
    if (refusal) {
      io.stderr.write(`${refusal}\n`);
      return 2;
    }
  }
  const { start, end } = yearBounds(year);
  const ai = await collectAiUsage({ env, now });

  const config = loadConfig(env, (m) => io.stderr.write(`warning: ${m}\n`));
  const cliRoots = (values.root ?? []).map((r) => path.resolve(expandPath(r, env)));
  const roots =
    cliRoots.length > 0 ? cliRoots : config.roots.map((r) => path.resolve(expandPath(r, env)));
  const found = await discover({
    env,
    roots,
    excludeGlobs: [...config.exclude, ...(values.exclude ?? [])],
    includeCloud: values["include-cloud"] === true,
    concurrency: values.concurrency === undefined ? 8 : Number(values.concurrency),
  });
  const yc = await collectYearCommits(found.repos(), { env, start, end });
  const w = buildMachineWrapped({
    year,
    start,
    end,
    commits: yc.commits,
    languageFiles: yc.languageFiles,
    aiEvents: ai.events,
    diskReclaimedBytes: readDiskReclaimed(env, start, end),
    local: localParts,
  });

  const out = path.resolve(cwd, values.out ?? `machine-wrapped-${year}.html`);
  fs.writeFileSync(out, renderWrappedHtml(w, { version: VERSION }));
  io.stderr.write(`wrote ${out}\n`);
  if (values.png) {
    const browser = (io.findBrowser ?? findBrowser)(env);
    if (!browser) {
      io.stderr.write(
        "no PNG: Chrome or Edge was not found on this machine — open the HTML card and screenshot it instead\n",
      );
    } else {
      const png = out.replace(/\.html?$/i, "") + ".png";
      const err = await renderPng(browser, out, png, io.exec ?? realExec);
      io.stderr.write(err ? `no PNG: ${err}\n` : `wrote ${png}\n`);
    }
  }
  io.stdout.write(`${renderWrappedText(w)}\n`);
  if (yc.noEmail > 0) {
    io.stderr.write(`note: ${yc.noEmail} repo(s) with no git user.email were not counted\n`);
  }
  if (yc.unknown > 0) {
    io.stderr.write(
      `note: ${yc.unknown} repo(s) git could not read (or did not answer in time) were not counted\n`,
    );
  }

  if (shareDevice) {
    io.stderr.write(
      `sharing Machine Wrapped ${year} to your public profile — aggregates only: counts, language shares, token totals, the top model. No repo names, paths, email or message text.\n`,
    );
    const outcome = await shareWrapped(
      { ...shareDevice, apiBase: resolveApiBase({ flag: values.api, device: shareDevice }) },
      buildShareBody(w),
      VERSION,
      { fetch: io.fetch, sleep: io.sleep },
    );
    if (!outcome.ok) {
      reportFailure(io, "share failed", outcome);
      return 2;
    }
    const d = outcome.data ?? {};
    const url = typeof d.url === "string" ? d.url : null;
    if (url) {
      io.stdout.write(`\nShared: ${url}\n`);
    } else {
      io.stdout.write(
        `\nShared — it will appear on your public page once you generate your Contributor Wrapped${
          typeof d.generateUrl === "string" ? ` at ${d.generateUrl}` : ""
        }.\n`,
      );
    }
    if (typeof d.manageUrl === "string") io.stdout.write(`Unpublish any time: ${d.manageUrl}\n`);
  }
  return 0;
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
  validity: ReadonlyMap<string, Validity> | undefined,
  insightsOpts: { env: SweepEnv; enabled: boolean; found?: Discovery },
): Promise<void> {
  if (!device) {
    io.stderr.write(
      "not uploaded: this machine is not enrolled. Run `repo-wrapped-sweep enrol <token>`.\n",
    );
    return;
  }
  // Machine Insights (v2). Best-effort: a collector failure sends the findings without it.
  let collected: Awaited<ReturnType<typeof collectUploadInsights>> | undefined;
  if (insightsOpts.enabled) {
    try {
      collected = await collectUploadInsights({
        env: insightsOpts.env,
        found: insightsOpts.found,
        device,
      });
    } catch (err) {
      io.stderr.write(`insights not uploaded: ${(err as Error).message}\n`);
    }
  }
  let body;
  try {
    const build = (insights?: InsightsBlock) =>
      buildIngestBody(result, {
        cliVersion: VERSION,
        platform: process.platform,
        sharePaths: device.sharePaths,
        validity,
        insights,
      });
    body = build(collected?.insights);
    if (collected && JSON.stringify(body).length > MAX_UPLOAD_BODY_BYTES) {
      io.stderr.write("insights not uploaded: the upload would exceed the size limit\n");
      collected = undefined;
      body = build();
    }
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
  // The AI cursor moves only once the server has the rows.
  if (collected?.nextAiCursor) {
    try {
      saveUploadCursor(insightsOpts.env, device.deviceId, collected.nextAiCursor);
    } catch {
      // next run re-sends those days; the server replaces them
    }
  }
  if (!values.quiet) {
    const n = body.findings.length;
    io.stderr.write(
      `uploaded ${n} finding${n === 1 ? "" : "s"} (metadata only${
        device.sharePaths ? ", with home-relative paths" : ", no paths"
      })${collected ? " and machine insights" : ""}\n`,
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
