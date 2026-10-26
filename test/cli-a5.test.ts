import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../src/cli";
import { saveDevice } from "../src/device";
import type { Exec, Prompter } from "../src/platform";
import { systemdDir } from "../src/schedule";
import type { FetchLike } from "../src/upload";
import type { HttpFetch } from "../src/validate";
import { captureIO, githubToken, makeFixture, scramble, type Fixture } from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

interface Run {
  code: number;
  out: string;
  err: string;
}

async function run(
  args: string[],
  extra: {
    validateFetch?: HttpFetch;
    fetch?: FetchLike;
    exec?: Exec;
    prompt?: Prompter;
  } = {},
): Promise<Run> {
  const io = captureIO();
  Object.assign(io, extra, { sleep: async () => {} });
  const code = await main(args, io, fx.env);
  return { code, out: io.out(), err: io.err() };
}

function validateFetchFor(statusByHost: Record<string, number>) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const f: HttpFetch = async (url, init) => {
    calls.push({ url, headers: init.headers });
    const status = statusByHost[new URL(url).hostname] ?? 404;
    return { status, json: async () => ({ ok: status === 200 }) };
  };
  return { f, calls };
}

describe("--validate", () => {
  it("refuses to run in a scheduled/MDM run (decision E3) and contacts nobody", async () => {
    fx = makeFixture();
    fx.write("a/.env", `API_TOKEN=${githubToken()}\n`);
    const v = validateFetchFor({ "api.github.com": 200 });
    const r = await run(["--root", fx.home, "--validate", "--scheduled"], { validateFetch: v.f });
    expect(r.code).toBe(2);
    expect(r.err).toContain("cannot be used in a scheduled run");
    expect(v.calls).toHaveLength(0);
  });

  it("asks the key's own provider, warns once, floats live keys first and reports validity", async () => {
    fx = makeFixture();
    const gh = githubToken(1);
    const dead = "sk_" + "live_" + scramble(24);
    fx.write("a/.env", `API_TOKEN=${gh}\n`);
    fx.write("b/.env", `STRIPE_KEY=${dead}\nAWS_NOTE=nothing\n`);
    fx.write("c/aws.txt", `aws_access_key_id = AKI${"A"}B9D2F7H4K6N1Q8S3\n`);
    const v = validateFetchFor({ "api.github.com": 200, "api.stripe.com": 401 });
    const r = await run(["--root", fx.home, "--validate", "--json", "--fail-on", "none"], {
      validateFetch: v.f,
    });
    expect(r.code).toBe(0);

    const j = JSON.parse(r.out);
    const byRule = (id: string) => j.findings.find((f: { ruleId: string }) => f.ruleId === id);
    expect(byRule("github-personal-access-token").validity).toBe("live");
    expect(byRule("stripe-secret-key").validity).toBe("revoked");
    expect(byRule("aws-access-key-id").validity).toBe("unknown");
    // live key ranks first even though the stripe key is "critical" too
    expect(j.findings[0].ruleId).toBe("github-personal-access-token");

    // only providers with an endpoint were contacted; each once; AWS never
    expect(v.calls.map((c) => new URL(c.url).hostname).sort()).toEqual([
      "api.github.com",
      "api.stripe.com",
    ]);
    expect(r.err.match(/sends each recognised key to its own provider/g)).toHaveLength(1);
    // the secrets reached their providers' headers only — never any output
    expect(v.calls.some((c) => JSON.stringify(c.headers).includes(gh))).toBe(true);
    expect(r.out + r.err).not.toContain(gh);
    expect(r.out + r.err).not.toContain(dead);
  });

  it("uploads the validity it found, only when --validate ran", async () => {
    fx = makeFixture();
    saveDevice(fx.env, {
      apiBase: "https://x.test",
      deviceId: "d1",
      deviceToken: "rwd_" + "z".repeat(43),
      saltHex: "ab".repeat(32),
      orgLogin: null,
      sharePaths: false,
      enrolledAt: "2026-06-01T00:00:00.000Z",
    });
    fx.write("a/.env", `API_TOKEN=${githubToken(2)}\n`);
    const bodies: Record<string, unknown>[] = [];
    const fetch: FetchLike = async (_u, init) => {
      bodies.push(JSON.parse(init.body));
      return { status: 202, json: async () => ({ ok: true, data: {} }) };
    };
    const v = validateFetchFor({ "api.github.com": 200 });
    await run(["--root", fx.home, "--upload", "--validate", "--quiet", "--fail-on", "none"], {
      fetch,
      validateFetch: v.f,
    });
    expect((bodies[0]!.findings as { validity?: string }[])[0]!.validity).toBe("live");

    await run(["--root", fx.home, "--upload", "--quiet", "--fail-on", "none"], { fetch });
    expect((bodies[1]!.findings as { validity?: string }[])[0]!.validity).toBeUndefined();
  });

  it("a scheduled upload sends no validity and contacts no provider", async () => {
    fx = makeFixture();
    saveDevice(fx.env, {
      apiBase: "https://x.test",
      deviceId: "d1",
      deviceToken: "rwd_" + "z".repeat(43),
      saltHex: "ab".repeat(32),
      orgLogin: "acme",
      sharePaths: false,
      enrolledAt: "2026-06-01T00:00:00.000Z",
    });
    fx.write("a/.env", `API_TOKEN=${githubToken(3)}\n`);
    const hosts = new Set<string>();
    const fetch: FetchLike = async (u) => {
      hosts.add(new URL(u).hostname);
      return { status: 202, json: async () => ({ ok: true, data: {} }) };
    };
    const v = validateFetchFor({ "api.github.com": 200 });
    await run(["--root", fx.home, "--quiet", "--scheduled", "--upload", "--fail-on", "none"], {
      fetch,
      validateFetch: v.f,
    });
    expect([...hosts]).toEqual(["x.test"]);
    expect(v.calls).toHaveLength(0);
  });
});

describe("fix through main()", () => {
  function execThatTrashes(deleted: string[]): {
    exec: Exec;
    calls: { cmd: string; args: string[]; input?: string }[];
  } {
    const calls: { cmd: string; args: string[]; input?: string }[] = [];
    const exec: Exec = async (cmd, args, opts) => {
      calls.push({ cmd, args, input: opts?.input });
      if (cmd === "gio") {
        const target = args.at(-1)!;
        fs.rmSync(target);
        deleted.push(target);
      }
      return { code: 0, stdout: "", stderr: "" };
    };
    return { exec, calls };
  }

  it("sweeps, then fixes a finding: keychain via stdin, Trash via gio, resolved", async () => {
    fx = makeFixture();
    fx.env.platform = "linux";
    const tok = githubToken(4);
    const env1 = fx.write("a/.env", `API_TOKEN=${tok}\n`);
    fx.write("b/.env.bak", `API_TOKEN=${tok}\n`);

    const sweep = await run(["--root", fx.home, "--json", "--fail-on", "none"]);
    const fp = JSON.parse(sweep.out).findings[0].fingerprint as string;

    const deleted: string[] = [];
    const { exec, calls } = execThatTrashes(deleted);
    const asked: string[] = [];
    const prompt: Prompter = { confirm: async (q) => (asked.push(q), true) };
    const r = await run(["fix", fp.slice(0, 8)], { exec, prompt });

    expect(r.code).toBe(0);
    expect(deleted.map((p) => path.basename(p)).sort()).toEqual([".env", ".env.bak"]);
    expect(fs.existsSync(env1)).toBe(false);
    // the keychain step used secret-tool with the secret on STDIN, not argv
    const store = calls.find((c) => c.cmd === "secret-tool")!;
    expect(store.input).toBe(tok);
    expect(store.args.join(" ")).not.toContain(tok);
    expect(r.out + r.err).not.toContain(tok);
    expect(r.out).toContain("marked resolved");
    expect(asked[0]).toMatch(/Store this secret/);
  });

  it("with no TTY (the default prompter) nothing is moved or stored", async () => {
    fx = makeFixture();
    fx.env.platform = "linux";
    const f = fx.write("a/.env", `API_TOKEN=${githubToken(5)}\n`);
    const sweep = await run(["--root", fx.home, "--json", "--fail-on", "none"]);
    const fp = JSON.parse(sweep.out).findings[0].fingerprint as string;
    const calls: string[] = [];
    const exec: Exec = async (cmd) => (calls.push(cmd), { code: 0, stdout: "", stderr: "" });
    const r = await run(["fix", fp], { exec }); // io.prompt unset → ttyPrompter() → no TTY in tests
    expect(r.code).toBe(1);
    expect(calls).toEqual([]);
    expect(fs.existsSync(f)).toBe(true);
  });

  it("usage errors", async () => {
    fx = makeFixture();
    expect((await run(["fix"])).code).toBe(2);
    expect((await run(["fix", "abcdef"])).code).toBe(2);
  });
});

describe("schedule through main()", () => {
  function recorder(): { exec: Exec; calls: string[] } {
    const calls: string[] = [];
    return {
      calls,
      exec: async (cmd, args) => (
        calls.push([cmd, ...args].join(" ")),
        { code: 0, stdout: "", stderr: "" }
      ),
    };
  }

  it("install --daily writes the Linux units and enables the timer; uninstall removes them", async () => {
    fx = makeFixture();
    fx.env.platform = "linux";
    const { exec, calls } = recorder();
    const r = await run(["schedule", "install", "--daily", "--upload"], { exec });
    expect(r.code).toBe(0);
    expect(r.out).toContain("Installed systemd user timer");
    const service = fs.readFileSync(
      path.join(systemdDir(fx.env), "repo-wrapped-sweep.service"),
      "utf8",
    );
    expect(service).toContain("--quiet --scheduled --upload");
    expect(calls).toContain("systemctl --user enable --now repo-wrapped-sweep.timer");

    expect((await run(["schedule", "status"], { exec })).code).toBe(0);
    const u = await run(["schedule", "uninstall"], { exec });
    expect(u.out).toContain("Removed");
    expect(fs.existsSync(path.join(systemdDir(fx.env), "repo-wrapped-sweep.timer"))).toBe(false);
  });

  it("requires --daily and a valid subcommand", async () => {
    fx = makeFixture();
    const { exec } = recorder();
    expect((await run(["schedule", "install"], { exec })).code).toBe(2);
    expect((await run(["schedule", "nope"], { exec })).code).toBe(2);
    expect((await run(["schedule"], { exec })).code).toBe(2);
  });

  it("MDM `schedule: true` installs the daily task once on first run", async () => {
    fx = makeFixture();
    fx.env.platform = "linux";
    const mdm = path.join(fx.root, "mdm.json");
    fx.env.mdmConfigPath = mdm;
    fs.writeFileSync(mdm, JSON.stringify({ schedule: true, upload: true }));
    const { exec, calls } = recorder();
    await run(["--root", fx.home, "--quiet", "--fail-on", "none"], { exec });
    expect(calls.filter((c) => c.includes("enable --now"))).toHaveLength(1);
    await run(["--root", fx.home, "--quiet", "--fail-on", "none"], { exec });
    expect(calls.filter((c) => c.includes("enable --now"))).toHaveLength(1); // already installed
    const service = fs.readFileSync(
      path.join(systemdDir(fx.env), "repo-wrapped-sweep.service"),
      "utf8",
    );
    expect(service).toContain("--upload");
  });
});
