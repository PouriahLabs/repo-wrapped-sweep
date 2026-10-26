// Enrolment + upload (§ A3). METADATA ONLY: a fingerprint, the masked preview,
// counts by location class and — only when the device's enrolment allows it —
// home-relative paths. The raw secret never reaches this module: it works from
// `EndpointGroup`s, which hold none.

import { randomUUID } from "node:crypto";
import os from "node:os";
import { isMaskedPreview } from "@/lib/native-scan/secret-rules";
import { INSIGHTS_SCHEMA_VERSION, type InsightsBlock } from "@/lib/endpoint/insights/wire";
import type { WrappedShareBody } from "@/lib/endpoint/insights/wrapped-wire";
import { type DeviceConfig } from "./device";
import type { ScanResult } from "./scan";

/** Server cap on findings per upload (§ A3.2). */
export const MAX_UPLOAD_FINDINGS = 2_000;
/** Paths per finding when sharing is on. */
export const MAX_UPLOAD_PATHS = 20;

export interface IngestFinding {
  fingerprint: string;
  ruleId: string;
  severity: "critical" | "high" | "medium" | "low";
  preview: string;
  copies: number;
  locationClasses: Partial<Record<string, number>>;
  validity?: "live" | "revoked" | "unknown";
  paths?: string[];
}

/** Server ceiling on the request body (MAX_INGEST_BODY_BYTES in ingest-schema.ts). */
export const MAX_UPLOAD_BODY_BYTES = 1_500_000;

/**
 * v1 = findings only (what a `--no-insights` / MDM `insights: false` run still sends, so it
 * also works against a server that predates v2); v2 = findings + the Machine Insights block.
 */
export interface IngestBody {
  schemaVersion: 1 | 2;
  /** v2 only. */
  insights?: InsightsBlock;
  runId: string;
  startedAt: string;
  finishedAt: string;
  cliVersion: string;
  os: "darwin" | "win32" | "linux";
  scope: "full" | "quick" | "paths";
  stats: { files: number; skippedDirs: number; skippedCloud: number };
  findings: IngestFinding[];
}

export interface BuildOptions {
  cliVersion: string;
  platform: NodeJS.Platform;
  /** The server-confirmed setting: paths are sent only when true. */
  sharePaths: boolean;
  runId?: string;
  /** Interactive `--validate` results by fingerprint (A5). */
  validity?: ReadonlyMap<string, "live" | "revoked" | "unknown">;
  /** Machine Insights block → a v2 body. Omitted → a v1 body, exactly as before. */
  insights?: InsightsBlock;
}

function uploadOs(platform: NodeJS.Platform): IngestBody["os"] {
  return platform === "darwin" || platform === "win32" ? platform : "linux";
}

/**
 * Build the upload body from a scan. Throws — never uploads — if anything in it
 * could carry more than metadata (a preview that isn't mask-shaped), because a
 * client bug must not be able to ship a raw secret.
 */
export function buildIngestBody(result: ScanResult, opts: BuildOptions): IngestBody {
  const findings: IngestFinding[] = result.groups.slice(0, MAX_UPLOAD_FINDINGS).map((g) => {
    if (!isMaskedPreview(g.preview)) {
      throw new Error(
        `refusing to upload: finding ${g.fingerprint.slice(0, 8)} has a non-masked preview`,
      );
    }
    const f: IngestFinding = {
      fingerprint: g.fingerprint,
      ruleId: g.ruleId,
      severity: g.severity,
      preview: g.preview,
      copies: g.copies,
      locationClasses: { ...g.locationClasses },
    };
    const v = opts.validity?.get(g.fingerprint);
    if (v) f.validity = v;
    if (opts.sharePaths) {
      // Home-relative only: an absolute path would carry the username.
      const paths = g.locations
        .map((l) => l.path)
        .filter((p) => p.startsWith("~/"))
        .slice(0, MAX_UPLOAD_PATHS);
      if (paths.length > 0) f.paths = paths;
    }
    return f;
  });
  return {
    schemaVersion: opts.insights ? INSIGHTS_SCHEMA_VERSION : 1,
    ...(opts.insights ? { insights: opts.insights } : {}),
    runId: opts.runId ?? randomUUID(),
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    cliVersion: opts.cliVersion,
    os: uploadOs(opts.platform),
    scope: result.scope,
    stats: {
      files: result.stats.files,
      skippedDirs: result.stats.skippedDirs,
      skippedCloud: result.stats.skippedCloud,
    },
    findings,
  };
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal },
) => Promise<{ status: number; json(): Promise<unknown> }>;

export interface HttpOutcome {
  ok: boolean;
  status: number;
  /** Server `data` on success, or the server's message on failure. */
  message: string;
  /** Where to upgrade, when the server answered 402. */
  upgradeUrl?: string;
  data?: Record<string, unknown>;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function readJson(res: { json(): Promise<unknown> }): Promise<Record<string, unknown>> {
  try {
    const j = await res.json();
    return j && typeof j === "object" ? (j as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** Map a response to an outcome. 202/200 = accepted; the rest carry a hint. */
export function interpretResponse(status: number, json: Record<string, unknown>): HttpOutcome {
  const error = typeof json.error === "string" ? json.error : "";
  const data =
    json.data && typeof json.data === "object" ? (json.data as Record<string, unknown>) : undefined;
  if (status === 200 || status === 202) {
    return { ok: true, status, message: data?.duplicate ? "already received" : "accepted", data };
  }
  const upgradeUrl = typeof json.upgradeUrl === "string" ? json.upgradeUrl : undefined;
  if (status === 402) {
    return {
      ok: false,
      status,
      upgradeUrl,
      message: error || "Your plan's device limit is reached.",
    };
  }
  if (status === 401) {
    return {
      ok: false,
      status,
      message: error || "The device token was rejected. Re-enrol this device.",
    };
  }
  if (status === 429) return { ok: false, status, message: "Rate limited — try again later." };
  if (status >= 500)
    return { ok: false, status, message: error || "The server is temporarily unavailable." };
  return { ok: false, status, message: error || `Unexpected response (${status}).` };
}

async function postJson(
  fetchImpl: FetchLike,
  url: string,
  headers: Record<string, string>,
  body: unknown,
  attempts: number,
  wait: (ms: number) => Promise<void>,
): Promise<HttpOutcome> {
  let last: HttpOutcome = { ok: false, status: 0, message: "network error" };
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(30_000),
      });
      last = interpretResponse(res.status, await readJson(res));
      // Only transient failures are worth another try; the runId makes it idempotent.
      if (last.ok || (last.status < 500 && last.status !== 429)) return last;
    } catch (err) {
      last = { ok: false, status: 0, message: `network error: ${(err as Error).message}` };
    }
    if (i < attempts - 1) await wait(2_000);
  }
  return last;
}

/** Upload one run. Safe to retry: the server dedupes on `runId`. */
export function uploadRun(
  device: Pick<DeviceConfig, "apiBase" | "deviceToken">,
  body: IngestBody,
  deps: { fetch?: FetchLike; sleep?: (ms: number) => Promise<void> } = {},
): Promise<HttpOutcome> {
  return postJson(
    deps.fetch ?? (globalThis.fetch as unknown as FetchLike),
    `${device.apiBase}/api/endpoint/ingest`,
    {
      authorization: `Bearer ${device.deviceToken}`,
      "user-agent": `repo-wrapped-sweep/${body.cliVersion}`,
    },
    body,
    2,
    deps.sleep ?? sleep,
  );
}

export interface EnrolResult {
  outcome: HttpOutcome;
  device?: DeviceConfig;
}

/** Exchange an enrolment/device token for a device config. */
export async function enrolDevice(
  apiBase: string,
  token: string,
  opts: {
    cliVersion: string;
    platform: NodeJS.Platform;
    label?: string;
    sharePaths?: boolean;
    now?: () => Date;
  },
  deps: { fetch?: FetchLike; sleep?: (ms: number) => Promise<void> } = {},
): Promise<EnrolResult> {
  const outcome = await postJson(
    deps.fetch ?? (globalThis.fetch as unknown as FetchLike),
    `${apiBase}/api/endpoint/enrol`,
    { "user-agent": `repo-wrapped-sweep/${opts.cliVersion}` },
    {
      token,
      label: opts.label ?? os.hostname().slice(0, 80),
      // Lets the server keep the name typed into "Add device" over the hostname.
      ...(opts.label !== undefined ? { labelExplicit: true } : {}),
      os: uploadOs(opts.platform),
      cliVersion: opts.cliVersion,
      ...(opts.sharePaths !== undefined ? { sharePaths: opts.sharePaths } : {}),
    },
    2,
    deps.sleep ?? sleep,
  );
  if (!outcome.ok) return { outcome };
  const d = outcome.data ?? {};
  if (
    typeof d.deviceId !== "string" ||
    typeof d.deviceToken !== "string" ||
    typeof d.saltHex !== "string" ||
    !/^[0-9a-f]{64}$/.test(d.saltHex)
  ) {
    return {
      outcome: {
        ok: false,
        status: outcome.status,
        message: "The server's enrolment response was malformed.",
      },
    };
  }
  return {
    outcome,
    device: {
      apiBase,
      deviceId: d.deviceId,
      deviceToken: d.deviceToken,
      saltHex: d.saltHex,
      orgLogin: typeof d.orgLogin === "string" ? d.orgLogin : null,
      sharePaths: d.sharePaths === true,
      enrolledAt: (opts.now ?? (() => new Date()))().toISOString(),
    },
  };
}

/**
 * Publish a Machine Wrapped card (`wrapped --share`, Pro): POST the aggregate share body with the
 * device token. Safe to retry — the server replaces the year's card. The body is built by the
 * pure allow-list `buildShareBody` (`@/lib/endpoint/insights/wrapped-wire`).
 */
export function shareWrapped(
  device: Pick<DeviceConfig, "apiBase" | "deviceToken">,
  body: WrappedShareBody,
  version: string,
  deps: { fetch?: FetchLike; sleep?: (ms: number) => Promise<void> } = {},
): Promise<HttpOutcome> {
  return postJson(
    deps.fetch ?? (globalThis.fetch as unknown as FetchLike),
    `${device.apiBase}/api/endpoint/wrapped-share`,
    {
      authorization: `Bearer ${device.deviceToken}`,
      "user-agent": `repo-wrapped-sweep/${version}`,
    },
    body,
    2,
    deps.sleep ?? sleep,
  );
}
