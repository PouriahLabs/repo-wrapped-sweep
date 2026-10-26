// Enrolment state (§ A3.1): ~/.repo-wrapped/device.json (0600) and the optional
// machine-wide MDM config. Holds the device bearer token and the fingerprint
// salt for the device's scope (the org's, or the user's own) — both are secrets
// of the device, never printed.

import fs from "node:fs";
import path from "node:path";
import type { SweepEnv } from "./env";
import { loadOrCreateSalt, writeJsonPrivate } from "./state";

export const DEFAULT_API_BASE = "https://repowrapped.com";

export interface DeviceConfig {
  apiBase: string;
  deviceId: string;
  /** `rwd_…` bearer token. Secret. */
  deviceToken: string;
  /** Fingerprint salt, 64 hex chars. Secret. */
  saltHex: string;
  /** The org this device reports to, or null for a personal device. */
  orgLogin: string | null;
  /** Whether uploads may carry home-relative paths (server-confirmed). */
  sharePaths: boolean;
  enrolledAt: string;
}

export function devicePath(env: Pick<SweepEnv, "configDir">): string {
  return path.join(env.configDir, "device.json");
}

function isDevice(v: unknown): v is DeviceConfig {
  if (!v || typeof v !== "object") return false;
  const d = v as Record<string, unknown>;
  return (
    typeof d.apiBase === "string" &&
    typeof d.deviceId === "string" &&
    typeof d.deviceToken === "string" &&
    typeof d.saltHex === "string" &&
    /^[0-9a-f]{64}$/.test(d.saltHex) &&
    typeof d.sharePaths === "boolean"
  );
}

/** The enrolled device, or null when not enrolled / unreadable. */
export function loadDevice(env: Pick<SweepEnv, "configDir">): DeviceConfig | null {
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(devicePath(env), "utf8"));
    return isDevice(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * The fingerprint salt for this machine: an enrolled device uses its scope's salt
 * (the org's, or the user's own) so the same secret groups across machines; an
 * unenrolled one uses its own random local salt.
 */
export function resolveSalt(
  env: SweepEnv,
  device: DeviceConfig | null = loadDevice(env),
): Uint8Array {
  return device ? Buffer.from(device.saltHex, "hex") : loadOrCreateSalt(env);
}

export function saveDevice(env: Pick<SweepEnv, "configDir">, device: DeviceConfig): void {
  writeJsonPrivate(devicePath(env), device);
}

export function clearDevice(env: Pick<SweepEnv, "configDir">): boolean {
  try {
    fs.rmSync(devicePath(env));
    return true;
  } catch {
    return false;
  }
}

// --- MDM config -------------------------------------------------------------

export interface MdmConfig {
  /** An org enrolment token the machine enrols itself with on first run. */
  enrolToken?: string;
  /** Install the daily schedule (A5). */
  schedule?: boolean;
  /** Upload after every run. */
  upload?: boolean;
  /** Personal-device path sharing request (an org token's own setting wins). */
  sharePaths?: boolean;
}

/** Read the machine-wide MDM config. Malformed or missing → null. */
export function loadMdmConfig(env: Pick<SweepEnv, "mdmConfigPath">): MdmConfig | null {
  if (!env.mdmConfigPath) return null;
  let raw: string;
  try {
    raw = fs.readFileSync(env.mdmConfigPath, "utf8");
  } catch {
    return null;
  }
  try {
    const j = JSON.parse(raw) as Record<string, unknown>;
    if (!j || typeof j !== "object" || Array.isArray(j)) return null;
    const out: MdmConfig = {};
    if (typeof j.enrolToken === "string" && j.enrolToken) out.enrolToken = j.enrolToken;
    if (typeof j.schedule === "boolean") out.schedule = j.schedule;
    if (typeof j.upload === "boolean") out.upload = j.upload;
    if (typeof j.sharePaths === "boolean") out.sharePaths = j.sharePaths;
    return out;
  } catch {
    return null;
  }
}

/** Resolve the API base: explicit flag → env var → enrolled device → default. */
export function resolveApiBase(opts: {
  flag?: string;
  device?: Pick<DeviceConfig, "apiBase"> | null;
  processEnv?: NodeJS.ProcessEnv;
}): string {
  const raw =
    opts.flag ??
    (opts.processEnv ?? process.env).REPO_WRAPPED_URL ??
    opts.device?.apiBase ??
    DEFAULT_API_BASE;
  return raw.replace(/\/+$/, "");
}
