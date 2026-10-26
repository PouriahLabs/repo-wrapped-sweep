// On-device state under ~/.repo-wrapped: the fingerprint salt and the user's
// sweep.json. Nothing here is ever uploaded. Files are created owner-only
// (0600/0700); on Windows the mode bits are advisory and the profile ACL applies.

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { SweepEnv } from "./env";

export interface SweepConfig {
  /** Extra exclude globs. */
  exclude: string[];
  /** Hook allow globs (A2). */
  hookAllow: string[];
  /** Default roots when none are passed on the command line. */
  roots: string[];
}

const EMPTY_CONFIG: SweepConfig = { exclude: [], hookAllow: [], roots: [] };

export function ensureConfigDir(env: SweepEnv): string {
  fs.mkdirSync(env.configDir, { recursive: true, mode: 0o700 });
  return env.configDir;
}

/**
 * The local fingerprint salt: 32 random bytes generated once, hex-encoded, 0600.
 * (An enrolled device later swaps this for the org salt — see `upload.ts`.)
 */
export function loadOrCreateSalt(env: SweepEnv): Uint8Array {
  const file = path.join(env.configDir, "sweep-salt");
  try {
    const hex = fs.readFileSync(file, "utf8").trim();
    if (/^[0-9a-f]{64}$/.test(hex)) return Buffer.from(hex, "hex");
  } catch {
    // fall through to create
  }
  ensureConfigDir(env);
  const salt = randomBytes(32);
  try {
    // `wx`: never clobber a salt another process created in the meantime.
    fs.writeFileSync(file, salt.toString("hex"), { mode: 0o600, flag: "wx" });
  } catch {
    const existing = fs.readFileSync(file, "utf8").trim();
    if (/^[0-9a-f]{64}$/.test(existing)) return Buffer.from(existing, "hex");
    fs.writeFileSync(file, salt.toString("hex"), { mode: 0o600 });
  }
  return salt;
}

/** `~/.repo-wrapped/sweep.json`. A malformed file is ignored with a warning —
 *  a bad config must never stop a sweep. */
export function loadConfig(env: SweepEnv, warn: (msg: string) => void = () => {}): SweepConfig {
  const file = path.join(env.configDir, "sweep.json");
  let raw: string;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch {
    return { ...EMPTY_CONFIG };
  }
  try {
    const j = JSON.parse(raw) as Partial<Record<keyof SweepConfig, unknown>>;
    const strings = (v: unknown) =>
      Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
    return {
      exclude: strings(j.exclude),
      hookAllow: strings(j.hookAllow),
      roots: strings(j.roots),
    };
  } catch {
    warn(`ignoring ${file}: not valid JSON`);
    return { ...EMPTY_CONFIG };
  }
}

/** Atomic owner-only write (temp file + rename) so a crash never leaves a
 *  half-written baseline for the hook to choke on. */
export function writeJsonPrivate(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(tmp, file);
}
