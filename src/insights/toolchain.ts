// Toolchain inventory and drift (ENDPOINT-MACHINE-INSIGHTS § C2.3, C-3): which runtimes
// and CLIs are installed (local `--version` probes only — no network), which version
// managers are present, and which repo pins the installed versions don't satisfy.
// Pin parsing and the drift judgement are the shared pure core
// (`@/lib/endpoint/insights/{pins,drift}`).
//
// A tool that is not on PATH costs no spawn. Every probe runs from a neutral directory
// (so a corepack shim does not read some project's `packageManager`) with update checks,
// telemetry and corepack downloads switched off.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describeDrift, findDrift, type DriftItem } from "@/lib/endpoint/insights/drift";
import { parsePins, TOOL_IDS, type Pin, type ToolId } from "@/lib/endpoint/insights/pins";
import { displayPath, type SweepEnv } from "../env";
import {
  commandFor,
  findOnPath,
  mapPool,
  runCommand,
  type PathLookup,
  type RunFailure,
} from "./run";

/** Per-probe deadline (§ C2.3). */
export const PROBE_TIMEOUT_MS = 2_000;
/** Python-based CLIs start slowly (gcloud, az); they get longer before "timeout". */
export const SLOW_PROBE_TIMEOUT_MS = 6_000;
/** Probes in flight at once. */
export const PROBE_POOL = 8;
/** Pin files larger than this are not read. */
const MAX_PIN_FILE_BYTES = 256 * 1024;

interface ProbeSpec {
  /** Binary names to try, in order (`python`, then `python3`). */
  bins: readonly string[];
  args: readonly string[];
  /** Pulls the version out of stdout+stderr. */
  pattern: RegExp;
  slow?: boolean;
}

const SEMVERISH = String.raw`(\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?)`;
const plainVersion = new RegExp(String.raw`^\s*v?${SEMVERISH}\s*$`, "m");

const PROBES: Record<ToolId, ProbeSpec> = {
  node: { bins: ["node"], args: ["--version"], pattern: plainVersion },
  npm: { bins: ["npm"], args: ["--version"], pattern: plainVersion },
  pnpm: { bins: ["pnpm"], args: ["--version"], pattern: plainVersion },
  yarn: { bins: ["yarn"], args: ["--version"], pattern: plainVersion },
  bun: { bins: ["bun"], args: ["--version"], pattern: plainVersion },
  deno: { bins: ["deno"], args: ["--version"], pattern: new RegExp(`deno ${SEMVERISH}`) },
  python: {
    bins: ["python", "python3"],
    args: ["--version"],
    pattern: new RegExp(`Python ${SEMVERISH}`),
  },
  pip: { bins: ["pip", "pip3"], args: ["--version"], pattern: new RegExp(`pip ${SEMVERISH}`) },
  uv: { bins: ["uv"], args: ["--version"], pattern: new RegExp(`uv ${SEMVERISH}`) },
  // `-version` (not `--version`) works on Java 8 too, and prints to stderr.
  java: {
    bins: ["java"],
    args: ["-version"],
    pattern: /version "(\d+(?:\.\d+)*(?:_\d+)?)[^"]*"/,
  },
  go: { bins: ["go"], args: ["version"], pattern: /go version go(\d+(?:\.\d+){0,2})/ },
  rustc: { bins: ["rustc"], args: ["--version"], pattern: new RegExp(`rustc ${SEMVERISH}`) },
  cargo: { bins: ["cargo"], args: ["--version"], pattern: new RegExp(`cargo ${SEMVERISH}`) },
  dotnet: { bins: ["dotnet"], args: ["--version"], pattern: plainVersion },
  git: { bins: ["git"], args: ["--version"], pattern: /git version (\d+(?:\.\d+){0,2})/ },
  gh: { bins: ["gh"], args: ["--version"], pattern: /gh version (\d+(?:\.\d+){0,2})/ },
  docker: {
    bins: ["docker"],
    args: ["--version"],
    pattern: /Docker version (\d+(?:\.\d+){0,2})/,
  },
  kubectl: {
    bins: ["kubectl"],
    args: ["version", "--client"],
    pattern: /Client Version: v?(\d+(?:\.\d+){0,2})/,
  },
  terraform: {
    bins: ["terraform"],
    args: ["-version"],
    pattern: /Terraform v(\d+(?:\.\d+){0,2})/,
  },
  aws: { bins: ["aws"], args: ["--version"], pattern: /aws-cli\/(\d+(?:\.\d+){0,2})/ },
  gcloud: {
    bins: ["gcloud"],
    args: ["--version"],
    pattern: /Google Cloud SDK (\d+(?:\.\d+){0,2})/,
    slow: true,
  },
  // `az version` (not `--version`, which checks PyPI for updates).
  az: {
    bins: ["az"],
    args: ["version", "--output", "json"],
    pattern: /"azure-cli":\s*"(\d+(?:\.\d+){0,2})"/,
    slow: true,
  },
  vercel: {
    bins: ["vercel"],
    args: ["--version"],
    pattern: /(?:Vercel CLI )?(\d+\.\d+\.\d+)/,
  },
  code: { bins: ["code"], args: ["--version"], pattern: plainVersion },
  cursor: { bins: ["cursor"], args: ["--version"], pattern: plainVersion },
};

const EDITORS = new Set<ToolId>(["code", "cursor"]);

/** Version managers detected (§ C2.3), so a drift hint can say which to use. */
export const VERSION_MANAGERS = ["nvm", "fnm", "volta", "asdf", "mise", "pyenv"] as const;

export interface ToolProbe {
  tool: ToolId;
  /** The version, or null when the tool is absent or did not answer. */
  version: string | null;
  /**
   * `error`: it ran but exited non-zero without a version (a Windows Store `python` alias,
   * a broken install) — it cannot run anything, so drift treats it as absent. `timeout`,
   * `unavailable` and `unparsed` are UNKNOWN: pins on those tools are not judged.
   */
  status: "present" | "absent" | "error" | RunFailure | "unparsed";
  /** Editors only: number of installed extensions (names are never kept). */
  extensions?: number;
}

export interface RepoDrift {
  /** Absolute path of the repo or project folder. */
  path: string;
  pins: Pin[];
  drift: DriftItem[];
}

export interface ToolchainCollection {
  tools: ToolProbe[];
  managers: string[];
  repos: RepoDrift[];
}

export interface ToolchainOptions {
  env: SweepEnv;
  /** Folders to read pin files from, each with the pin files its listing showed. */
  folders?: ReadonlyArray<{ path: string; pinFiles: readonly string[] }>;
  timeoutMs?: number;
  slowTimeoutMs?: number;
}

/** The environment for a probe: PATH as configured, no update checks, no downloads. */
function probeEnv(vars: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return {
    ...vars,
    NO_UPDATE_NOTIFIER: "1",
    npm_config_update_notifier: "false",
    COREPACK_ENABLE_NETWORK: "0",
    COREPACK_ENABLE_DOWNLOAD_PROMPT: "0",
    CHECKPOINT_DISABLE: "1", // terraform
    DOTNET_CLI_TELEMETRY_OPTOUT: "1",
    DOTNET_NOLOGO: "1",
    VERCEL_TELEMETRY_DISABLED: "1",
    AZURE_CORE_COLLECT_TELEMETRY: "0",
    GH_NO_UPDATE_NOTIFIER: "1",
    CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK: "1",
  };
}

const pathVar = (vars: NodeJS.ProcessEnv): string =>
  vars.PATH ??
  vars.Path ??
  Object.entries(vars).find(([k]) => k.toUpperCase() === "PATH")?.[1] ??
  "";

/** Probe one tool. Never throws. */
async function probe(
  tool: ToolId,
  lookup: PathLookup,
  vars: NodeJS.ProcessEnv,
  opts: ToolchainOptions,
): Promise<ToolProbe> {
  const spec = PROBES[tool];
  let abs: string | null = null;
  for (const b of spec.bins) {
    abs = findOnPath(b, lookup);
    if (abs) break;
  }
  if (!abs) return { tool, version: null, status: "absent" };
  const timeoutMs = spec.slow
    ? (opts.slowTimeoutMs ?? SLOW_PROBE_TIMEOUT_MS)
    : (opts.timeoutMs ?? PROBE_TIMEOUT_MS);
  const env = probeEnv(vars);
  const cwd = os.tmpdir();
  const { cmd, args } = commandFor(abs, spec.args, lookup.platform, vars.ComSpec);
  const r = await runCommand(cmd, args, { cwd, timeoutMs, env });
  if (!r.ok) return { tool, version: null, status: r.failure };
  const m = spec.pattern.exec(`${r.stdout}\n${r.stderr}`);
  if (!m?.[1]) return { tool, version: null, status: r.code === 0 ? "unparsed" : "error" };
  const out: ToolProbe = { tool, version: m[1], status: "present" };
  if (EDITORS.has(tool)) {
    const ext = commandFor(
      abs,
      ["--list-extensions", "--show-versions"],
      lookup.platform,
      vars.ComSpec,
    );
    const e = await runCommand(ext.cmd, ext.args, { cwd, timeoutMs: timeoutMs * 2, env });
    if (e.ok && e.code === 0) {
      out.extensions = e.stdout.split("\n").filter((l) => /\S@\S/.test(l)).length;
    }
  }
  return out;
}

/** Which version managers are installed: on PATH, or announced by their env var / home folder. */
export function detectManagers(
  env: SweepEnv,
  vars: NodeJS.ProcessEnv,
  lookup: PathLookup,
): string[] {
  const exists = (rel: string) => {
    try {
      return fs.statSync(path.join(env.home, rel)).isDirectory();
    } catch {
      return false;
    }
  };
  const signals: Record<(typeof VERSION_MANAGERS)[number], () => boolean> = {
    nvm: () => !!vars.NVM_DIR || !!vars.NVM_HOME || exists(".nvm") || !!findOnPath("nvm", lookup),
    fnm: () => !!vars.FNM_DIR || !!findOnPath("fnm", lookup),
    volta: () => !!vars.VOLTA_HOME || exists(".volta") || !!findOnPath("volta", lookup),
    asdf: () => !!vars.ASDF_DIR || exists(".asdf") || !!findOnPath("asdf", lookup),
    mise: () => !!findOnPath("mise", lookup),
    pyenv: () =>
      !!vars.PYENV_ROOT || !!vars.PYENV || exists(".pyenv") || !!findOnPath("pyenv", lookup),
  };
  return VERSION_MANAGERS.filter((m) => signals[m]());
}

/** Read a folder's pin files (only those its listing showed; small files only). */
export function readPins(dir: string, pinFiles: readonly string[]): Pin[] {
  const files: Record<string, string> = {};
  for (const name of pinFiles) {
    const abs = path.join(dir, name);
    try {
      const st = fs.lstatSync(abs);
      if (!st.isFile() || st.size > MAX_PIN_FILE_BYTES) continue;
      files[name] = fs.readFileSync(abs, "utf8");
    } catch {
      // unreadable
    }
  }
  return parsePins(files);
}

export async function collectToolchain(opts: ToolchainOptions): Promise<ToolchainCollection> {
  const vars = opts.env.processEnv ?? process.env;
  const lookup: PathLookup = {
    path: pathVar(vars),
    pathext: vars.PATHEXT,
    platform: opts.env.platform,
  };
  const tools = await mapPool(TOOL_IDS, PROBE_POOL, (t) => probe(t, lookup, vars, opts));
  const managers = detectManagers(opts.env, vars, lookup);
  const installed: Partial<Record<ToolId, string | null>> = {};
  for (const t of tools) installed[t.tool] = t.version;
  // A probe that timed out or could not be parsed is UNKNOWN, not absent: its pins are
  // dropped from judgement below rather than reported as "not installed".
  const unknown = new Set(
    tools
      .filter(
        (t) => t.status === "timeout" || t.status === "unavailable" || t.status === "unparsed",
      )
      .map((t) => t.tool),
  );

  const repos: RepoDrift[] = [];
  for (const f of opts.folders ?? []) {
    if (f.pinFiles.length === 0) continue;
    const pins = readPins(f.path, f.pinFiles);
    if (pins.length === 0) continue;
    const drift = findDrift(
      pins.filter((p) => !unknown.has(p.tool)),
      installed,
    );
    repos.push({ path: f.path, pins, drift });
  }
  repos.sort((a, b) => b.drift.length - a.drift.length || a.path.localeCompare(b.path));
  return { tools, managers, repos };
}

/** `2 repos pin versions this machine doesn't have (node 20.11.0 installed, .nvmrc wants 22 → …)` */
export function describeToolchain(
  t: ToolchainCollection,
  env: Pick<SweepEnv, "home" | "platform">,
): string {
  const drifting = t.repos.filter((r) => r.drift.length > 0);
  const present = t.tools.filter((x) => x.status === "present").length;
  if (drifting.length === 0) {
    return `${present} tools installed; every repo's pins are satisfied`;
  }
  const first = drifting[0]!;
  return (
    `${drifting.length} repo${drifting.length === 1 ? "" : "s"} pin versions this machine doesn't have ` +
    `(${displayPath(first.path, env)}: ${describeDrift(first.drift[0]!, t.managers)})`
  );
}
