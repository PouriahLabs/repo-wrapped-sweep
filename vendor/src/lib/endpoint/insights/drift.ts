// Toolchain drift for Machine Insights (ENDPOINT-MACHINE-INSIGHTS § C2.3) — PURE.
//
// "Installed node is 20.11.0, this repo's .nvmrc wants 22." `satisfies` is built on
// `rangeAllowsLatest` from the Package Map (ADR 039) — the same range logic the Bump Action
// mirrors via `bumpRange` — so the two features never disagree about what a range admits.
// That helper's rule carries over: a mismatch is claimed only when we can PROVE one. A pin
// that is not a semver range (`lts/iron`, `stable`, `nightly-2024-01-01`) is not judged.

import semver from "semver";
import { rangeAllowsLatest } from "@/lib/version-range";
import type { Pin, ToolId } from "@/lib/endpoint/insights/pins";

/** Strip a leading `v`; `1.8.0_392` style Java versions become `8.0.392` (the pre-9 scheme). */
function normalizeInstalled(tool: ToolId | null, installed: string): string {
  const v = installed.trim().replace(/^v(?=\d)/i, "");
  return tool === "java" ? v.replace(/^1\.(?=\d)/, "").replace("_", ".") : v;
}

/** Can `wanted` be judged at all — is it a valid semver range (a bare major counts)? */
export function canJudge(wanted: string): boolean {
  return semver.validRange(wanted.trim(), { loose: true }) !== null;
}

/**
 * Does the installed version satisfy the pin? A pin we can't parse is treated as satisfied
 * (no provable block), exactly like `rangeAllowsLatest` — check `canJudge` to tell the two apart.
 */
export function satisfies(installed: string, wanted: string): boolean {
  return rangeAllowsLatest(wanted.trim(), normalizeInstalled(null, installed));
}

export type DriftReason = "mismatch" | "missing";

export interface DriftItem {
  tool: ToolId;
  /** The file (field) that pins it — one item per pin, so disagreeing files each report. */
  source: string;
  wanted: string;
  /** null when the tool isn't installed. */
  installed: string | null;
  reason: DriftReason;
}

/**
 * Compare a repo's pins with what is installed. `installed` maps tool → version, null when
 * absent (a tool missing from the map counts as absent). Satisfied pins and pins we can't
 * judge are omitted; a pinned tool that isn't installed at all is `missing`.
 */
export function findDrift(
  pins: readonly Pin[],
  installed: Readonly<Partial<Record<ToolId, string | null>>>,
): DriftItem[] {
  const out: DriftItem[] = [];
  for (const p of pins) {
    const have = installed[p.tool] ?? null;
    if (have === null) {
      out.push({
        tool: p.tool,
        source: p.source,
        wanted: p.wanted,
        installed: null,
        reason: "missing",
      });
      continue;
    }
    if (!canJudge(p.wanted)) continue;
    if (!rangeAllowsLatest(p.wanted, normalizeInstalled(p.tool, have))) {
      out.push({
        tool: p.tool,
        source: p.source,
        wanted: p.wanted,
        installed: have,
        reason: "mismatch",
      });
    }
  }
  return out;
}

const PLAIN_VERSION = /^\d+(?:\.\d+){0,2}$/;

/**
 * A command that would fix the drift, given the version managers detected on the machine
 * (`fnm`, `nvm`, `volta`, `asdf`, `mise`, `pyenv`). Null when there's no confident suggestion.
 */
export function driftHint(d: DriftItem, managers: readonly string[]): string | null {
  const has = (m: string) => managers.includes(m);
  const plain = PLAIN_VERSION.test(d.wanted);

  if (d.source === ".tool-versions") {
    if (has("mise")) return "mise install";
    if (has("asdf")) return "asdf install";
    return null;
  }
  if (
    d.source === "packageManager" &&
    (d.tool === "pnpm" || d.tool === "yarn" || d.tool === "npm")
  ) {
    return `corepack use ${d.tool}@${d.wanted}`;
  }
  if (d.tool === "node") {
    if (d.source === ".nvmrc" || d.source === ".node-version") {
      if (has("fnm")) return "fnm use";
      if (has("nvm")) return "nvm use";
    }
    if (plain) {
      if (has("volta")) return `volta install node@${d.wanted}`;
      if (has("fnm")) return `fnm install ${d.wanted}`;
      if (has("nvm")) return `nvm install ${d.wanted}`;
    }
    return null;
  }
  if (d.tool === "python" && plain && has("pyenv")) return `pyenv install ${d.wanted}`;
  return null;
}

/** `node 20.11.0 installed, .nvmrc wants 22 → run "fnm use"` */
export function describeDrift(d: DriftItem, managers: readonly string[] = []): string {
  const head =
    d.installed === null
      ? `${d.tool} not installed, ${d.source} wants ${d.wanted}`
      : `${d.tool} ${d.installed} installed, ${d.source} wants ${d.wanted}`;
  const hint = driftHint(d, managers);
  return hint ? `${head} → run "${hint}"` : head;
}
