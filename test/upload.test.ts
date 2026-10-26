import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { EndpointGroup } from "@/lib/native-scan/fingerprint";
import { defaultBaselinePath } from "../src/baseline";
import { main } from "../src/cli";
import { devicePath, loadDevice, loadMdmConfig, resolveApiBase, saveDevice } from "../src/device";
import type { ScanResult } from "../src/scan";
import {
  MAX_UPLOAD_FINDINGS,
  MAX_UPLOAD_PATHS,
  buildIngestBody,
  interpretResponse,
  uploadRun,
  type FetchLike,
} from "../src/upload";
import { captureIO, githubToken, makeFixture, scramble, type Fixture } from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

const SALT_HEX = "ab".repeat(32);
const NO_WAIT = async () => {};

function group(over: Partial<EndpointGroup> = {}): EndpointGroup {
  return {
    fingerprint: "a".repeat(32),
    ruleId: "github-personal-access-token",
    severity: "high",
    preview: "gh••••…ab",
    copies: 2,
    locations: [
      { path: "~/Documents/client-acme/.env", locationClass: "documents", line: 3 },
      { path: "/opt/other/.env", locationClass: "documents" },
    ],
    locationClasses: { documents: 2 },
    ...over,
  };
}

function result(groups: EndpointGroup[], over: Partial<ScanResult> = {}): ScanResult {
  return {
    scope: "full",
    startedAt: "2026-06-01T00:00:00.000Z",
    finishedAt: "2026-06-01T00:00:30.000Z",
    groups,
    stats: {
      files: 10,
      skippedDirs: 1,
      skippedCloud: 2,
      skippedLarge: 0,
      skippedBinary: 0,
      skippedFiles: 0,
      skippedPlaceholders: 0,
      skippedUnknownAttrs: 0,
      errors: 0,
      deniedByTop: {},
    },
    notes: [],
    ...over,
  };
}

const opts = { cliVersion: "0.1.0", platform: "linux" as NodeJS.Platform, sharePaths: false };

describe("buildIngestBody", () => {
  it("builds the § A3.2 shape from a scan", () => {
    const b = buildIngestBody(result([group()]), {
      ...opts,
      runId: "11111111-1111-4111-8111-111111111111",
    });
    expect(b).toMatchObject({
      schemaVersion: 1,
      runId: "11111111-1111-4111-8111-111111111111",
      cliVersion: "0.1.0",
      os: "linux",
      scope: "full",
      stats: { files: 10, skippedDirs: 1, skippedCloud: 2 },
    });
    expect(b.findings[0]).toEqual({
      fingerprint: "a".repeat(32),
      ruleId: "github-personal-access-token",
      severity: "high",
      preview: "gh••••…ab",
      copies: 2,
      locationClasses: { documents: 2 },
    });
  });

  it("generates a fresh uuid runId per build", () => {
    const a = buildIngestBody(result([]), opts).runId;
    const b = buildIngestBody(result([]), opts).runId;
    expect(a).toMatch(/^[0-9a-f-]{36}$/);
    expect(a).not.toBe(b);
  });

  it("NEVER sends paths unless sharePaths is on", () => {
    const off = buildIngestBody(result([group()]), opts);
    expect(JSON.stringify(off)).not.toContain("client-acme");
    expect(off.findings[0]!.paths).toBeUndefined();
  });

  it("with sharePaths, sends home-relative paths only — never an absolute one", () => {
    const on = buildIngestBody(result([group()]), { ...opts, sharePaths: true });
    expect(on.findings[0]!.paths).toEqual(["~/Documents/client-acme/.env"]);
    expect(JSON.stringify(on)).not.toContain("/opt/other");
  });

  it("caps paths per finding and findings per upload", () => {
    const many = Array.from({ length: 50 }, (_, i) => ({
      path: `~/p/${i}`,
      locationClass: "documents" as const,
    }));
    const on = buildIngestBody(result([group({ locations: many, copies: 50 })]), {
      ...opts,
      sharePaths: true,
    });
    expect(on.findings[0]!.paths).toHaveLength(MAX_UPLOAD_PATHS);

    const groups = Array.from({ length: MAX_UPLOAD_FINDINGS + 5 }, (_, i) =>
      group({ fingerprint: i.toString(16).padStart(32, "0") }),
    );
    expect(buildIngestBody(result(groups), opts).findings).toHaveLength(MAX_UPLOAD_FINDINGS);
  });

  it("REFUSES to build when a preview is not mask-shaped (a raw secret must never go out)", () => {
    const raw = githubToken();
    expect(() => buildIngestBody(result([group({ preview: raw })]), opts)).toThrow(
      /non-masked preview/,
    );
    expect(() => buildIngestBody(result([group({ preview: "" })]), opts)).not.toThrow();
  });

  it("carries interactive validity results and maps non-linux/darwin/win32 to linux", () => {
    const v = new Map([["a".repeat(32), "live" as const]]);
    expect(buildIngestBody(result([group()]), { ...opts, validity: v }).findings[0]!.validity).toBe(
      "live",
    );
    expect(buildIngestBody(result([]), { ...opts, platform: "freebsd" }).os).toBe("linux");
    expect(buildIngestBody(result([]), { ...opts, platform: "darwin" }).os).toBe("darwin");
  });
});

describe("interpretResponse", () => {
  it("treats 202 and 200 as accepted, flagging a duplicate", () => {
    expect(interpretResponse(202, { ok: true, data: { accepted: true } }).ok).toBe(true);
    const dup = interpretResponse(202, { ok: true, data: { duplicate: true } });
    expect(dup).toMatchObject({ ok: true, message: "already received" });
    expect(interpretResponse(200, {}).ok).toBe(true);
  });
  it("maps 402 with the upgrade URL, 401, 429 and 5xx", () => {
    const pay = interpretResponse(402, {
      error: "Device limit reached",
      upgradeUrl: "https://repowrapped.com/pricing",
    });
    expect(pay).toMatchObject({
      ok: false,
      status: 402,
      upgradeUrl: "https://repowrapped.com/pricing",
      message: "Device limit reached",
    });
    expect(interpretResponse(401, { error: "revoked" })).toMatchObject({
      ok: false,
      message: "revoked",
    });
    expect(interpretResponse(401, {}).message).toMatch(/Re-enrol/);
    expect(interpretResponse(429, {}).message).toMatch(/Rate limited/);
    expect(interpretResponse(503, {}).ok).toBe(false);
    expect(interpretResponse(418, {}).message).toMatch(/418/);
  });
});

function fakeFetch(
  responses: { status: number; body?: unknown }[],
): FetchLike & { calls: { url: string; init: Parameters<FetchLike>[1] }[] } {
  const calls: { url: string; init: Parameters<FetchLike>[1] }[] = [];
  let i = 0;
  const f = (async (url: string, init: Parameters<FetchLike>[1]) => {
    calls.push({ url, init });
    const r = responses[Math.min(i++, responses.length - 1)]!;
    if (r.status === 0) throw new Error("ECONNRESET");
    return { status: r.status, json: async () => r.body ?? {} };
  }) as FetchLike & { calls: typeof calls };
  f.calls = calls;
  return f;
}

describe("uploadRun", () => {
  const device = { apiBase: "https://example.test", deviceToken: "rwd_" + "x".repeat(43) };
  const body = buildIngestBody(result([group()]), opts);

  it("POSTs JSON with the bearer token to /api/endpoint/ingest", async () => {
    const f = fakeFetch([{ status: 202, body: { ok: true, data: { accepted: true } } }]);
    const r = await uploadRun(device, body, { fetch: f, sleep: NO_WAIT });
    expect(r.ok).toBe(true);
    expect(f.calls[0]!.url).toBe("https://example.test/api/endpoint/ingest");
    expect(f.calls[0]!.init.method).toBe("POST");
    expect(f.calls[0]!.init.headers.authorization).toBe(`Bearer ${device.deviceToken}`);
    expect(JSON.parse(f.calls[0]!.init.body)).toEqual(JSON.parse(JSON.stringify(body)));
  });

  it("retries a transient failure once with the SAME runId, then succeeds", async () => {
    const f = fakeFetch([{ status: 503 }, { status: 202, body: { ok: true, data: {} } }]);
    const r = await uploadRun(device, body, { fetch: f, sleep: NO_WAIT });
    expect(r.ok).toBe(true);
    expect(f.calls).toHaveLength(2);
    expect(JSON.parse(f.calls[0]!.init.body).runId).toBe(JSON.parse(f.calls[1]!.init.body).runId);
  });

  it("retries a network error, and gives up with a message after two tries", async () => {
    const f = fakeFetch([{ status: 0 }, { status: 0 }]);
    const r = await uploadRun(device, body, { fetch: f, sleep: NO_WAIT });
    expect(r).toMatchObject({ ok: false, status: 0 });
    expect(r.message).toMatch(/network error/);
    expect(f.calls).toHaveLength(2);
  });

  it("does NOT retry a 401 or 402", async () => {
    for (const status of [401, 402]) {
      const f = fakeFetch([{ status }]);
      expect((await uploadRun(device, body, { fetch: f, sleep: NO_WAIT })).ok).toBe(false);
      expect(f.calls).toHaveLength(1);
    }
  });
});

describe("device.json + MDM + api base", () => {
  it("round-trips an owner-only device file and rejects a malformed one", () => {
    fx = makeFixture();
    expect(loadDevice(fx.env)).toBeNull();
    const dev = {
      apiBase: "https://x.test",
      deviceId: "d1",
      deviceToken: "rwd_t",
      saltHex: SALT_HEX,
      orgLogin: "acme",
      sharePaths: false,
      enrolledAt: "2026-06-01T00:00:00.000Z",
    };
    saveDevice(fx.env, dev);
    expect(loadDevice(fx.env)).toEqual(dev);
    if (process.platform !== "win32")
      expect(fs.statSync(devicePath(fx.env)).mode & 0o777).toBe(0o600);
    fs.writeFileSync(devicePath(fx.env), JSON.stringify({ ...dev, saltHex: "short" }));
    expect(loadDevice(fx.env)).toBeNull();
    fs.writeFileSync(devicePath(fx.env), "{nope");
    expect(loadDevice(fx.env)).toBeNull();
  });

  it("reads the MDM config and ignores junk", () => {
    fx = makeFixture();
    const file = path.join(fx.root, "mdm.json");
    fx.env.mdmConfigPath = file;
    expect(loadMdmConfig(fx.env)).toBeNull();
    fs.writeFileSync(
      file,
      JSON.stringify({
        enrolToken: "rwo_x",
        schedule: true,
        upload: true,
        sharePaths: false,
        extra: 1,
      }),
    );
    expect(loadMdmConfig(fx.env)).toEqual({
      enrolToken: "rwo_x",
      schedule: true,
      upload: true,
      sharePaths: false,
    });
    fs.writeFileSync(file, JSON.stringify({ enrolToken: 5, upload: "yes" }));
    expect(loadMdmConfig(fx.env)).toEqual({});
    fs.writeFileSync(file, "[]");
    expect(loadMdmConfig(fx.env)).toBeNull();
    fs.writeFileSync(file, "{bad");
    expect(loadMdmConfig(fx.env)).toBeNull();
    expect(loadMdmConfig({ mdmConfigPath: undefined })).toBeNull();
  });

  it("resolves the API base: flag > env var > device > default, no trailing slash", () => {
    expect(resolveApiBase({ processEnv: {} })).toBe("https://repowrapped.com");
    expect(resolveApiBase({ device: { apiBase: "https://d.test/" }, processEnv: {} })).toBe(
      "https://d.test",
    );
    expect(
      resolveApiBase({
        device: { apiBase: "https://d.test" },
        processEnv: { REPO_WRAPPED_URL: "http://localhost:3000/" },
      }),
    ).toBe("http://localhost:3000");
    expect(
      resolveApiBase({
        flag: "https://f.test///",
        device: { apiBase: "https://d.test" },
        processEnv: { REPO_WRAPPED_URL: "x" },
      }),
    ).toBe("https://f.test");
  });
});

// ---------------------------------------------------------------------------
// End-to-end through main(): enrol → sweep → upload, with a fake server.
// ---------------------------------------------------------------------------

function server(
  handlers: Record<
    string,
    (
      body: Record<string, unknown>,
      headers: Record<string, string>,
    ) => { status: number; body: unknown }
  >,
) {
  const seen: { path: string; body: Record<string, unknown>; headers: Record<string, string> }[] =
    [];
  const fetchImpl = (async (url: string, init: Parameters<FetchLike>[1]) => {
    const p = new URL(url).pathname;
    const body = JSON.parse(init.body) as Record<string, unknown>;
    seen.push({ path: p, body, headers: init.headers });
    const h = handlers[p];
    const r = h ? h(body, init.headers) : { status: 404, body: { ok: false, error: "nope" } };
    return { status: r.status, json: async () => r.body };
  }) as FetchLike;
  return { fetch: fetchImpl, seen };
}

async function run(args: string[], srv: ReturnType<typeof server>) {
  const io = captureIO();
  io.fetch = srv.fetch;
  io.sleep = NO_WAIT;
  const code = await main(args, io, fx.env);
  return { code, out: io.out(), err: io.err() };
}

const enrolOk = (over: Record<string, unknown> = {}) => ({
  status: 200,
  body: {
    ok: true,
    data: {
      deviceId: "dev-1",
      deviceToken: "rwd_" + "z".repeat(43),
      orgLogin: "acme",
      sharePaths: false,
      saltHex: SALT_HEX,
      ...over,
    },
  },
});

describe("enrol command", () => {
  it("writes device.json, drops the (now meaningless) baseline and explains path sharing", async () => {
    fx = makeFixture();
    fs.mkdirSync(fx.env.configDir, { recursive: true });
    fs.writeFileSync(defaultBaselinePath(fx.env), "{}");
    const srv = server({ "/api/endpoint/enrol": () => enrolOk() });
    const r = await run(
      ["enrol", "rwo_" + "q".repeat(43), "--label", "work-laptop", "--api", "https://x.test"],
      srv,
    );
    expect(r.code).toBe(0);
    expect(r.out).toContain("Enrolled with acme");
    expect(r.out).toContain("NOT shared");
    expect(srv.seen[0]!.body).toMatchObject({
      token: "rwo_" + "q".repeat(43),
      label: "work-laptop",
      cliVersion: expect.any(String),
    });
    expect(loadDevice(fx.env)).toMatchObject({
      apiBase: "https://x.test",
      deviceId: "dev-1",
      orgLogin: "acme",
      saltHex: SALT_HEX,
    });
    expect(fs.existsSync(defaultBaselinePath(fx.env))).toBe(false);
    expect(r.out + r.err).not.toContain("z".repeat(43)); // the device token is never printed
    expect(r.out + r.err).not.toContain(SALT_HEX);
  });

  it("shows the user when the admin turned path sharing on", async () => {
    fx = makeFixture();
    const srv = server({ "/api/endpoint/enrol": () => enrolOk({ sharePaths: true }) });
    const r = await run(["enrol", "rwo_" + "q".repeat(43)], srv);
    expect(r.out).toContain("home-relative paths (~/…) are shared");
    expect(loadDevice(fx.env)!.sharePaths).toBe(true);
  });

  it("passes --share-paths for a personal token", async () => {
    fx = makeFixture();
    const srv = server({ "/api/endpoint/enrol": () => enrolOk({ orgLogin: null }) });
    await run(["enrol", "rwd_" + "q".repeat(43), "--share-paths"], srv);
    expect(srv.seen[0]!.body.sharePaths).toBe(true);
    const r = await run(["enrol", "rwd_" + "q".repeat(43)], srv);
    expect(r.out).toContain("Enrolled. Findings are grouped across your own devices");
    expect("sharePaths" in srv.seen[1]!.body).toBe(false);
  });

  it("prints the server's message and the upgrade URL on a 402", async () => {
    fx = makeFixture();
    const srv = server({
      "/api/endpoint/enrol": () => ({
        status: 402,
        body: {
          ok: false,
          error: "Pro includes 3 devices.",
          upgradeUrl: "https://repowrapped.com/pricing",
        },
      }),
    });
    const r = await run(["enrol", "rwd_" + "q".repeat(43)], srv);
    expect(r.code).toBe(2);
    expect(r.err).toContain("Pro includes 3 devices.");
    expect(r.err).toContain("Upgrade: https://repowrapped.com/pricing");
    expect(loadDevice(fx.env)).toBeNull();
  });

  it("rejects a malformed server response and a missing token", async () => {
    fx = makeFixture();
    const srv = server({
      "/api/endpoint/enrol": () => ({ status: 200, body: { ok: true, data: { deviceId: "d" } } }),
    });
    expect((await run(["enrol", "rwd_" + "q".repeat(43)], srv)).code).toBe(2);
    expect((await run(["enrol"], srv)).code).toBe(2);
    expect(loadDevice(fx.env)).toBeNull();
  });
});

describe("--upload through main()", () => {
  function enrolled(sharePaths = false) {
    saveDevice(fx.env, {
      apiBase: "https://x.test",
      deviceId: "dev-1",
      deviceToken: "rwd_" + "z".repeat(43),
      saltHex: SALT_HEX,
      orgLogin: "acme",
      sharePaths,
      enrolledAt: "2026-06-01T00:00:00.000Z",
    });
  }

  it("sweeps with the device's salt and uploads metadata only (no paths by default)", async () => {
    fx = makeFixture();
    enrolled(false);
    const tok = githubToken();
    fx.write("client-acme/.env", `API_TOKEN=${tok}\n`);
    const srv = server({
      "/api/endpoint/ingest": () => ({ status: 202, body: { ok: true, data: { accepted: true } } }),
    });
    const r = await run(["--root", fx.home, "--upload", "--fail-on", "none"], srv);
    expect(r.code).toBe(0);
    expect(r.err).toContain("uploaded 1 finding (metadata only, no paths)");
    const sent = srv.seen[0]!;
    expect(sent.path).toBe("/api/endpoint/ingest");
    expect(sent.headers.authorization).toBe(`Bearer rwd_${"z".repeat(43)}`);
    const wire = JSON.stringify(sent.body);
    expect(wire).not.toContain(tok);
    expect(wire).not.toContain(tok.slice(3, -3));
    expect(wire).not.toContain("client-acme"); // paths off
    expect((sent.body.findings as unknown[]).length).toBe(1);
    // The local random salt was never created: the device salt was used.
    expect(fs.existsSync(path.join(fx.env.configDir, "sweep-salt"))).toBe(false);
  });

  it("includes home-relative paths when the enrolment shares them", async () => {
    fx = makeFixture();
    enrolled(true);
    fx.write("client-acme/.env", `API_TOKEN=${githubToken()}\n`);
    const srv = server({
      "/api/endpoint/ingest": () => ({ status: 202, body: { ok: true, data: {} } }),
    });
    const r = await run(["--root", fx.home, "--upload", "--fail-on", "none"], srv);
    expect(r.err).toContain("with home-relative paths");
    const findings = srv.seen[0]!.body.findings as { paths?: string[] }[];
    expect(findings[0]!.paths).toEqual(["~/client-acme/.env"]);
    expect(JSON.stringify(srv.seen[0]!.body)).not.toContain(fx.home.replace(/\\/g, "/"));
  });

  it("is a no-op with a hint when the machine is not enrolled; exit code unaffected", async () => {
    fx = makeFixture();
    fx.write("a/.env", `API_TOKEN=${githubToken()}\n`);
    const srv = server({});
    const r = await run(["--root", fx.home, "--upload"], srv);
    expect(r.code).toBe(1); // the finding, not the upload
    expect(r.err).toContain("not enrolled");
    expect(srv.seen).toHaveLength(0);
  });

  it("reports a rejected token without changing the exit code", async () => {
    fx = makeFixture();
    enrolled();
    const srv = server({
      "/api/endpoint/ingest": () => ({
        status: 401,
        body: { ok: false, error: "This device was revoked." },
      }),
    });
    const r = await run(["--root", fx.home, "--upload"], srv);
    expect(r.code).toBe(0);
    expect(r.err).toContain("upload failed: This device was revoked.");
  });

  it("does not upload without --upload", async () => {
    fx = makeFixture();
    enrolled();
    const srv = server({});
    await run(["--root", fx.home], srv);
    expect(srv.seen).toHaveLength(0);
  });

  it("an MDM config with an enrol token enrols on first run and uploads", async () => {
    fx = makeFixture();
    const mdm = path.join(fx.root, "mdm.json");
    fx.env.mdmConfigPath = mdm;
    fs.writeFileSync(mdm, JSON.stringify({ enrolToken: "rwo_" + "m".repeat(43), upload: true }));
    fx.write("a/.env", `API_TOKEN=${githubToken()}\n`);
    const srv = server({
      "/api/endpoint/enrol": () => enrolOk(),
      "/api/endpoint/ingest": () => ({ status: 202, body: { ok: true, data: {} } }),
    });
    const r = await run(["--root", fx.home, "--fail-on", "none", "--quiet"], srv);
    expect(r.code).toBe(0);
    expect(srv.seen.map((s) => s.path)).toEqual(["/api/endpoint/enrol", "/api/endpoint/ingest"]);
    expect(loadDevice(fx.env)).not.toBeNull();
    // second run: already enrolled, no second enrol
    await run(["--root", fx.home, "--fail-on", "none", "--quiet"], srv);
    expect(srv.seen.filter((s) => s.path === "/api/endpoint/enrol")).toHaveLength(1);
  });

  it("a scheduled/MDM run never validates: no provider is contacted", async () => {
    fx = makeFixture();
    enrolled();
    fx.write("a/.env", `API_TOKEN=${githubToken()}\n`);
    const fetchSpy = vi.fn();
    const srv = server({
      "/api/endpoint/ingest": () => ({ status: 202, body: { ok: true, data: {} } }),
    });
    const real = srv.fetch;
    srv.fetch = (async (u: string, i: Parameters<FetchLike>[1]) => {
      fetchSpy(new URL(u).hostname);
      return real(u, i);
    }) as FetchLike;
    await run(["--root", fx.home, "--upload", "--quiet"], srv);
    expect([...new Set(fetchSpy.mock.calls.map((c) => c[0]))]).toEqual(["x.test"]);
    expect(scramble(1)).toBeTruthy();
  });
});
