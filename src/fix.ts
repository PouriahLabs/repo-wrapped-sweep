// `repo-wrapped-sweep fix <fingerprint>` (§ A2.5): an interactive, one-secret-at-a-
// time remediation. Every destructive step asks first; `--yes` skips the prompts
// for TRASH MOVES ONLY — never for the keychain.
//
//   1. Store it properly   (optional) hand the secret to the OS credential store
//   2. Remove the copies   MOVE to the OS trash (never unlink) where safe; list the
//                          rest for manual action
//   3. Rotate              print the provider's rotation link — the tool never calls
//                          a provider to revoke
//   4. Re-sweep            confirm the fingerprint is gone, mark it resolved
//
// "Where safe": a file is only trashed when it is a pure secret holder (a key file,
// an env file, a cookie jar, an editor-history copy, a backup). A source file with
// a token inline, a shell history or an agent transcript is NEVER trashed — deleting
// those would destroy far more than the secret — so they are listed for hand-editing.

import fs from "node:fs";
import type { EndpointGroup } from "@/lib/native-scan/fingerprint";
import {
  type LocationClass,
  isBackupPath,
  matchPath,
  rotationUrl,
} from "@/lib/native-scan/path-rules";
import { loadBaseline, saveBaseline, type Baseline, type BaselineEntry } from "./baseline";
import { expandPath, type SweepEnv } from "./env";
import { classifyLocation } from "./locations";
import {
  onePasswordHint,
  type KeychainAdapter,
  type Prompter,
  type TrashAdapter,
} from "./platform";
import type { ScanResult } from "./scan";

export interface FixIO {
  stdout: { write(s: string): unknown };
  stderr: { write(s: string): unknown };
}

export interface FixDeps {
  env: SweepEnv;
  io: FixIO;
  baselinePath: string;
  prompt: Prompter;
  trash: TrashAdapter;
  keychain: KeychainAdapter;
  /** `--yes`: skip the confirms for trash moves (never the keychain). */
  yes: boolean;
  now?: () => Date;
  /** Re-read a file and return the raw secret for a fingerprint (local only). */
  recover: (abs: string, cls: LocationClass, fingerprint: string) => Promise<string | null>;
  /** Re-sweep specific paths (a `paths`-scope scan). */
  rescan: (paths: string[]) => Promise<ScanResult>;
}

// ---------------------------------------------------------------------------
// Pure planning
// ---------------------------------------------------------------------------

/** Resolve a fingerprint or an unambiguous prefix (≥ 6 chars) against the baseline. */
export function resolveFingerprint(
  input: string,
  baseline: Baseline | null,
): { ok: true; fingerprint: string; entry: BaselineEntry } | { ok: false; error: string } {
  const q = input.trim().toLowerCase();
  if (!/^[0-9a-f]{6,32}$/.test(q)) {
    return {
      ok: false,
      error: "give a fingerprint (or at least its first 6 hex characters) from a sweep report",
    };
  }
  if (!baseline) {
    return { ok: false, error: "no baseline yet — run a sweep first so there is something to fix" };
  }
  const matches = Object.keys(baseline.findings).filter((fp) => fp.startsWith(q));
  if (matches.length === 0) {
    return {
      ok: false,
      error: `no finding matches ${q} — re-run a sweep and copy the fingerprint from its report`,
    };
  }
  if (matches.length > 1) {
    return { ok: false, error: `${q} matches ${matches.length} findings; use more characters` };
  }
  const fingerprint = matches[0]!;
  return { ok: true, fingerprint, entry: baseline.findings[fingerprint]! };
}

export type RemovalAction = "trash" | "manual";

export interface FixItem {
  /** Home-relative display path. */
  path: string;
  abs: string;
  locationClass: LocationClass;
  action: RemovalAction;
  /** Why a copy is not trashed ("manual") or what kind of copy it is. */
  reason: string;
}

/**
 * Decide, per copy, whether moving the FILE to the trash is a sound remedy.
 * Pure. Conservative by design: anything that might hold more than the secret is
 * left for the user to edit.
 */
export function planRemoval(
  abs: string,
  locationClass: LocationClass,
): { action: RemovalAction; reason: string } {
  switch (locationClass) {
    case "credential-store":
    case "ssh":
      return {
        action: "manual",
        reason: "an expected credential store — rotate the secret instead of deleting the file",
      };
    case "agent-transcript":
      return {
        action: "manual",
        reason: "an agent transcript — delete or redact the session yourself",
      };
    case "shell-history":
      return {
        action: "manual",
        reason: "shell history — remove the entry (or clear the history) yourself",
      };
    case "editor-history":
      return { action: "trash", reason: "an editor local-history copy" };
    default:
      break;
  }
  const hit = matchPath(abs, locationClass);
  if (hit && hit.ruleId !== "path.env-backup") {
    // A key / env / cookie / service-account file is a pure secret holder.
    return { action: "trash", reason: "a file that exists to hold a secret" };
  }
  if (isBackupPath(abs)) return { action: "trash", reason: "a backup copy" };
  return {
    action: "manual",
    reason: "a file with the secret inline — edit it out; deleting the file would lose the rest",
  };
}

export function planFix(entry: BaselineEntry, env: SweepEnv): FixItem[] {
  return entry.locations.map((display) => {
    const abs = expandPath(display, env);
    const locationClass = classifyLocation(abs, env);
    return { path: display, abs, locationClass, ...planRemoval(abs, locationClass) };
  });
}

/** Keychain / 1Password item label: safe characters only, tied to the finding. */
export function keychainLabel(ruleId: string, fingerprint: string): string {
  return `${ruleId.replace(/[^a-z0-9.-]/gi, "-")}-${fingerprint.slice(0, 8)}`;
}

// ---------------------------------------------------------------------------
// The flow
// ---------------------------------------------------------------------------

const exists = (p: string) => fs.existsSync(p);

export async function runFix(input: string, deps: FixDeps): Promise<number> {
  const { io, env } = deps;
  const out = (s: string) => io.stdout.write(`${s}\n`);
  const now = deps.now ?? (() => new Date());

  const baseline = loadBaseline(deps.baselinePath);
  const resolved = resolveFingerprint(input, baseline);
  if (!resolved.ok) {
    io.stderr.write(`fix: ${resolved.error}\n`);
    return 2;
  }
  const { fingerprint, entry } = resolved;
  if (entry.resolvedAt) {
    out(`${fingerprint.slice(0, 8)} is already marked resolved. Run a full sweep to confirm.`);
    return 0;
  }

  const items = planFix(entry, env);
  out(
    `Fixing ${entry.ruleId} · ${fingerprint.slice(0, 8)} · ${items.length} cop${items.length === 1 ? "y" : "ies"}`,
  );
  for (const it of items.slice(0, 15))
    out(`  ${it.action === "trash" ? "•" : "○"} ${it.path}  (${it.reason})`);
  if (items.length > 15) out(`  … and ${items.length - 15} more`);
  out("");

  // --- 1. Store it properly (never auto-confirmed) ---------------------------
  const label = keychainLabel(entry.ruleId, fingerprint);
  out(`1/4  Store it properly`);
  out(`     Or with 1Password:  ${onePasswordHint(label)}`);
  const wantsStore = await deps.prompt.confirm(
    `     Store this secret in ${deps.keychain.name} as ${label}?`,
  );
  if (wantsStore) {
    const stored = await storeInKeychain(items, fingerprint, label, deps);
    out(
      stored.ok ? `     ✓ stored in ${deps.keychain.name}` : `     ✗ not stored: ${stored.message}`,
    );
  } else {
    out("     skipped");
  }

  // --- 2. Remove the copies ----------------------------------------------------
  out(`2/4  Remove copies (moved to ${deps.trash.destination}, never deleted)`);
  const trashable = items.filter((i) => i.action === "trash" && exists(i.abs));
  const editor = trashable.filter((i) => i.locationClass === "editor-history");
  const others = trashable.filter((i) => i.locationClass !== "editor-history");
  let moved = 0;
  let failed = 0;

  const move = async (item: FixItem) => {
    const r = await deps.trash.trash(item.abs);
    if (r.ok) moved++;
    else {
      failed++;
      out(`     ✗ ${item.path}: ${r.message ?? "could not move"}`);
    }
  };

  if (editor.length > 0) {
    const go =
      deps.yes ||
      (await deps.prompt.confirm(
        `     Move ${editor.length} editor-history cop${editor.length === 1 ? "y" : "ies"} to ${deps.trash.destination}?`,
      ));
    if (go) for (const it of editor) await move(it);
    else
      out(`     skipped ${editor.length} editor-history cop${editor.length === 1 ? "y" : "ies"}`);
  }
  for (const it of others) {
    const go =
      deps.yes || (await deps.prompt.confirm(`     Move ${it.path} to ${deps.trash.destination}?`));
    if (go) await move(it);
    else out(`     skipped ${it.path}`);
  }
  if (trashable.length === 0) out("     nothing to move automatically");
  else out(`     moved ${moved}${failed ? `, ${failed} failed` : ""}`);

  const manual = items.filter((i) => i.action === "manual" && exists(i.abs));
  if (manual.length > 0) {
    out("     Needs your hands:");
    for (const m of manual) out(`       ○ ${m.path} — ${m.reason}`);
  }

  // --- 3. Rotate ----------------------------------------------------------------
  out(`3/4  Rotate`);
  out(`     ${rotationUrl(entry.ruleId)}`);
  out("     Rotation is always your action — this tool never calls a provider to revoke a key.");

  // --- 4. Re-sweep + mark resolved ------------------------------------------------
  out(`4/4  Re-sweep`);
  const stillThere = items.map((i) => i.abs).filter(exists);
  let remaining: EndpointGroup | undefined;
  if (stillThere.length > 0) {
    const result = await deps.rescan(stillThere);
    remaining = result.groups.find((g) => g.fingerprint === fingerprint);
  }

  const latest = loadBaseline(deps.baselinePath) ?? baseline!;
  const nowIso = now().toISOString();
  if (!remaining) {
    latest.findings[fingerprint] = {
      ...entry,
      locations: [],
      copies: 0,
      resolvedAt: nowIso,
      lastSeen: nowIso,
    };
    saveBaseline(deps.baselinePath, { ...latest, updatedAt: nowIso });
    out(
      "     ✓ no copies left — marked resolved. Rotate the secret if you haven't, then run a full sweep to confirm.",
    );
    return 0;
  }
  latest.findings[fingerprint] = {
    ...entry,
    locations: remaining.locations.map((l) => l.path),
    copies: remaining.copies,
    lastSeen: nowIso,
  };
  saveBaseline(deps.baselinePath, { ...latest, updatedAt: nowIso });
  out(
    `     ${remaining.copies} cop${remaining.copies === 1 ? "y" : "ies"} still contain it — finish the manual steps above and run \`fix ${fingerprint.slice(0, 8)}\` again.`,
  );
  return 1;
}

/** Read the secret back from the first copy that still yields it, then file it
 *  with the OS credential store. The value lives only in this function's locals. */
async function storeInKeychain(
  items: FixItem[],
  fingerprint: string,
  label: string,
  deps: FixDeps,
): Promise<{ ok: boolean; message?: string }> {
  let secret: string | null = null;
  for (const it of items) {
    if (!exists(it.abs)) continue;
    secret = await deps.recover(it.abs, it.locationClass, fingerprint);
    if (secret !== null) break;
  }
  if (secret === null) {
    return { ok: false, message: "could not read it back from any copy (it may already be gone)" };
  }
  try {
    return await deps.keychain.store(label, secret);
  } finally {
    secret = null;
  }
}
