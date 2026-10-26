// `repo-wrapped-sweep enrol <token>` and the MDM first-run auto-enrol (§ A3.1).

import fs from "node:fs";
import { defaultBaselinePath } from "./baseline";
import { loadDevice, resolveApiBase, saveDevice, type DeviceConfig } from "./device";
import type { SweepEnv } from "./env";
import { enrolDevice, type FetchLike, type HttpOutcome } from "./upload";

export interface EnrolIO {
  stdout: { write(s: string): unknown };
  stderr: { write(s: string): unknown };
  fetch?: FetchLike;
  sleep?: (ms: number) => Promise<void>;
}

export interface EnrolFlags {
  api?: string;
  label?: string;
  sharePaths?: boolean;
}

/** Print why an enrol/upload call failed, with the upgrade link on a 402. */
export function reportFailure(io: Pick<EnrolIO, "stderr">, what: string, o: HttpOutcome): void {
  io.stderr.write(`${what}: ${o.message}\n`);
  if (o.upgradeUrl) io.stderr.write(`Upgrade: ${o.upgradeUrl}\n`);
}

/**
 * Enrol with a token, persisting `device.json`. Changing the salt invalidates
 * every fingerprint in the local baseline, so the baseline is dropped (it holds
 * no secrets — only NEW/GONE history is lost).
 */
export async function enrol(
  token: string,
  flags: EnrolFlags,
  io: EnrolIO,
  env: SweepEnv,
  version: string,
): Promise<DeviceConfig | null> {
  const apiBase = resolveApiBase({ flag: flags.api, device: loadDevice(env) });
  const { outcome, device } = await enrolDevice(
    apiBase,
    token,
    {
      cliVersion: version,
      platform: env.platform,
      label: flags.label,
      sharePaths: flags.sharePaths,
    },
    { fetch: io.fetch, sleep: io.sleep },
  );
  if (!outcome.ok || !device) {
    reportFailure(io, "enrolment failed", outcome);
    return null;
  }
  saveDevice(env, device);
  try {
    fs.rmSync(defaultBaselinePath(env), { force: true });
  } catch {
    // best-effort
  }
  return device;
}

export async function runEnrol(
  token: string | undefined,
  flags: EnrolFlags,
  io: EnrolIO,
  env: SweepEnv,
  version: string,
): Promise<number> {
  if (!token) {
    io.stderr.write(
      "usage: repo-wrapped-sweep enrol <token> [--label <name>] [--share-paths] [--api <url>]\n",
    );
    return 2;
  }
  const device = await enrol(token, flags, io, env, version);
  if (!device) return 2;

  io.stdout.write(
    device.orgLogin
      ? `Enrolled with ${device.orgLogin}. Findings are grouped with the rest of the organization's devices.\n`
      : "Enrolled. Findings are grouped across your own devices.\n",
  );
  io.stdout.write(
    device.sharePaths
      ? "Paths: home-relative paths (~/…) are shared with uploads — never your username, never the secret.\n"
      : "Paths: NOT shared. Uploads carry fingerprints, masked previews and location counts only.\n",
  );
  io.stdout.write("Run `repo-wrapped-sweep --upload` to sweep and upload.\n");
  return 0;
}
