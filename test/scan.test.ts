import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SECRET_RULES } from "@/lib/native-scan/secret-rules";
import { fingerprint } from "@/lib/native-scan/fingerprint";
import { LINE_CAP_CHARS, readCappedLines, scan, type ScanOptions } from "../src/scan";
import { githubToken, makeFixture, pemKey, scramble, type Fixture } from "./helpers";

const SALT = new Uint8Array(32).fill(3);
let fx: Fixture;
afterEach(() => {
  vi.restoreAllMocks();
  fx?.cleanup();
});

function opts(over: Partial<ScanOptions> = {}): ScanOptions {
  return {
    env: fx.env,
    roots: [fx.home],
    quick: false,
    excludeGlobs: [],
    includeCloud: false,
    concurrency: 4,
    salt: SALT,
    ...over,
  };
}

describe("scan — grouping and path rules", () => {
  it("groups one PEM saved in three places into a single finding", async () => {
    fx = makeFixture();
    const key = pemKey();
    fx.write("docs/test_harness_backup/server.pem", key);
    fx.write("docs/notes.txt", `my key, don't lose it:\n${key}\n`);
    fx.write(".ssh/id_work", key.replace(/\n/g, "\r\n"));
    const r = await scan(opts());
    expect(r.groups).toHaveLength(1);
    expect(r.groups[0]).toMatchObject({ copies: 3, severity: "critical" });
    expect(r.groups[0]!.locations.map((l) => l.path).sort()).toEqual([
      "~/.ssh/id_work",
      "~/docs/notes.txt",
      "~/docs/test_harness_backup/server.pem",
    ]);
  });

  it("ignores .env.example but flags a real .env", async () => {
    fx = makeFixture();
    const tok = githubToken();
    fx.write("app/.env.example", `GITHUB_TOKEN=${tok}\n`);
    fx.write("app/.env.sample", `GITHUB_TOKEN=${tok}\n`);
    let r = await scan(opts());
    expect(r.groups).toHaveLength(0);
    fx.write("app/.env", `NODE_ENV=production\nGITHUB_TOKEN=${tok}\n`);
    r = await scan(opts());
    expect(r.groups).toHaveLength(1);
    expect(r.groups[0]!.ruleId).toBe("github-personal-access-token");
  });

  it("reports a certificate-only .pem as nothing", async () => {
    fx = makeFixture();
    fx.write(
      "certs/fullchain.pem",
      `-----BEGIN CERTIFICATE-----\n${scramble(60)}\n-----END CERTIFICATE-----\n`,
    );
    expect((await scan(opts())).groups).toHaveLength(0);
  });

  it("flags a service-account JSON and a cookie jar by filename + content", async () => {
    fx = makeFixture();
    fx.write("gcp/app-secret.json", JSON.stringify({ client_secret: scramble(30) }));
    fx.write("dl/cookies.txt", "# Netscape HTTP Cookie File\n");
    const r = await scan(opts());
    expect(r.groups.map((g) => g.ruleId).sort()).toEqual([
      "path.cookie-jar",
      "path.service-account",
    ]);
    expect(r.groups.find((g) => g.ruleId === "path.service-account")?.severity).toBe("critical");
  });

  it("reports a long-lived AWS key in ~/.aws/credentials as an expected-store hit, an STS key as low", async () => {
    fx = makeFixture();
    const akia = "AKI" + "A" + "B9D2F7H4K6N1Q8S3";
    const asia = "ASI" + "A" + "B9D2F7H4K6N1Q8S3";
    fx.write(
      ".aws/credentials",
      `[default]\naws_access_key_id = ${akia}\naws_secret_access_key = ${scramble(40)}\n`,
    );
    let r = await scan(opts());
    // credential-store: one step down from high; the content-rule duplicates are shadowed.
    expect(
      r.groups.some((g) => g.locations.some((l) => l.locationClass === "credential-store")),
    ).toBe(true);
    const aws = r.groups.filter((g) => g.locations[0]!.path === "~/.aws/credentials");
    expect(aws.every((g) => g.severity !== "critical")).toBe(true);
    fs.writeFileSync(
      path.join(fx.home, ".aws", "credentials"),
      `[sso]\naws_access_key_id = ${asia}\n`,
    );
    r = await scan(opts());
    expect(r.groups.find((g) => g.ruleId === "path.aws-long-lived")?.severity).toBe("low");
  });

  it("raises a hit in a backup-named path by one step", async () => {
    fx = makeFixture();
    // a medium (jwt) finding → high in a backup folder
    const jwt = `eyJ${scramble(15)}.eyJ${scramble(15, 5)}.${scramble(20)}`;
    fx.write("a/config.txt", `t=${jwt}\n`);
    fx.write("a/old_backup/config.txt", `t=${jwt}\n`);
    const r = await scan(opts());
    expect(r.groups).toHaveLength(1);
    expect(r.groups[0]!.copies).toBe(2);
    expect(r.groups[0]!.severity).toBe("high");
  });

  it("skips lockfiles, binary blobs and node_modules", async () => {
    fx = makeFixture();
    const tok = githubToken();
    fx.write("p/node_modules/x/leak.txt", `t=${tok}\n`);
    fx.write("p/package-lock.json", `{"t":"${tok}"}`);
    fx.write("p/blob.bin", Buffer.concat([Buffer.from([0, 1, 2, 0]), Buffer.from(tok)]));
    fx.write("p/dist/out.txt", `t=${tok}\n`);
    const r = await scan(opts());
    expect(r.groups).toHaveLength(0);
  });
});

describe("scan — cloud-sync roots", () => {
  it("skips a cloud root by default, counts it, and scans it with includeCloud", async () => {
    fx = makeFixture();
    const cloud = path.join(fx.home, "OneDrive");
    fx.env.cloudRoots = [cloud];
    fx.write("OneDrive/Documents/leak.txt", `t=${githubToken()}\n`);
    fx.write("local/ok.txt", "nothing\n");
    const skipped = await scan(opts());
    expect(skipped.groups).toHaveLength(0);
    expect(skipped.stats.skippedCloud).toBe(1);
    expect(skipped.notes.join(" ")).toMatch(/cloud-sync/);
    const included = await scan(opts({ includeCloud: true }));
    expect(included.groups).toHaveLength(1);
    expect(included.stats.skippedCloud).toBe(0);
  });

  it("skips an explicit root that lives inside a cloud root", async () => {
    fx = makeFixture();
    fx.env.cloudRoots = [path.join(fx.home, "OneDrive")];
    fx.write("OneDrive/proj/leak.txt", `t=${githubToken()}\n`);
    const r = await scan(opts({ roots: [path.join(fx.home, "OneDrive", "proj")] }));
    expect(r.groups).toHaveLength(0);
    expect(r.stats.skippedCloud).toBe(1);
  });

  it("detects folders named OneDrive* directly under home", async () => {
    fx = makeFixture();
    fx.write("OneDrive - Contoso/x/leak.txt", `t=${githubToken()}\n`);
    const r = await scan(opts());
    expect(r.groups).toHaveLength(0);
    expect(r.stats.skippedCloud).toBe(1);
  });
});

describe("scan — permissions", () => {
  it("counts an unreadable directory without failing the sweep", async () => {
    fx = makeFixture();
    fx.write("open/leak.txt", `t=${githubToken()}\n`);
    fx.write("locked/leak.txt", `t=${githubToken(1)}\n`);
    const real = fs.promises.opendir.bind(fs.promises);
    vi.spyOn(fs.promises, "opendir").mockImplementation(((
      p: fs.PathLike,
      o?: fs.OpenDirOptions,
    ) => {
      if (String(p).endsWith(`${path.sep}locked`)) {
        return Promise.reject(Object.assign(new Error("EPERM"), { code: "EPERM" }));
      }
      return real(p, o);
    }) as typeof fs.promises.opendir);
    const r = await scan(opts());
    expect(r.groups).toHaveLength(1); // the readable one
    expect(r.stats.skippedDirs).toBe(1);
    expect(Object.keys(r.stats.deniedByTop)).toHaveLength(1);
    expect(r.stats.errors).toBe(0);
  });

  it("counts an unreadable file as skipped, not as an error", async () => {
    fx = makeFixture();
    fx.write("a/leak.txt", `t=${githubToken()}\n`);
    fx.write("a/locked.txt", `t=${githubToken(1)}\n`);
    const realStat = fs.promises.stat.bind(fs.promises);
    vi.spyOn(fs.promises, "stat").mockImplementation(((p: fs.PathLike, o?: fs.StatOptions) => {
      if (String(p).endsWith("locked.txt")) {
        return Promise.reject(Object.assign(new Error("EACCES"), { code: "EACCES" }));
      }
      return realStat(p, o as never);
    }) as typeof fs.promises.stat);
    const r = await scan(opts());
    expect(r.groups).toHaveLength(1);
    expect(r.stats.skippedFiles).toBe(1);
    expect(r.stats.errors).toBe(0);
  });
});

describe("scan — streaming and windows", () => {
  it("finds a token on line 40,000 of a jsonl transcript, with that line number", async () => {
    fx = makeFixture();
    const tok = githubToken();
    const lines: string[] = [];
    for (let i = 1; i < 40_000; i++) lines.push(`{"role":"user","n":${i},"text":"hello world"}`);
    lines.push(`{"role":"user","text":"export TOKEN=${tok}"}`);
    lines.push('{"role":"assistant","text":"done"}');
    fx.write(".claude/projects/demo/session.jsonl", lines.join("\n"));
    const r = await scan(opts());
    expect(r.groups).toHaveLength(1);
    const g = r.groups[0]!;
    expect(g.ruleId).toBe("github-personal-access-token");
    expect(g.locations[0]).toMatchObject({ locationClass: "agent-transcript", line: 40_000 });
    // already critical; an agent-transcript copy stays capped at critical
    expect(g.severity).toBe("critical");
  });

  it("scans a >256 KB plain file in overlapping windows without losing a match at a cut", async () => {
    fx = makeFixture();
    const filler = "const a = 1; // padding line to push the file over the window threshold\n";
    const before = filler.repeat(4500); // ~315 KB → first window flushes inside it
    const tok = githubToken(2);
    const after = filler.repeat(10);
    fx.write("code/big.ts", `${before}const t = "${tok}";\n${after}`);
    const r = await scan(opts());
    expect(r.groups).toHaveLength(1);
    expect(r.groups[0]!.copies).toBe(1);
  });

  it("does not double-report a secret that falls in the window overlap", async () => {
    fx = makeFixture();
    const filler = "x".repeat(150) + "\n";
    // Put the secret near where the first 192 KB window is cut.
    const idx = Math.floor((192 * 1024) / filler.length) - 5;
    const lines = Array.from({ length: idx * 2 }, () => filler);
    lines[idx] = `const t = "${githubToken(3)}";\n`;
    fx.write("code/edge.ts", lines.join(""));
    const r = await scan(opts());
    expect(r.groups).toHaveLength(1);
    expect(r.groups[0]!.copies).toBe(1);
  });

  it("skips a >5 MB non-streamed file but streams a big shell history", async () => {
    fx = makeFixture();
    const tok = githubToken();
    const pad = "y".repeat(1000) + "\n";
    fx.write("code/huge.txt", pad.repeat(5400) + `t=${tok}\n`);
    fx.write(".bash_history", pad.repeat(5400) + `export T=${tok}\n`);
    const r = await scan(opts());
    expect(r.stats.skippedLarge).toBe(1);
    expect(r.groups).toHaveLength(1);
    expect(r.groups[0]!.locations[0]!.locationClass).toBe("shell-history");
  });
});

describe("readCappedLines", () => {
  async function collect(chunks: string[], cap: number) {
    async function* gen() {
      for (const c of chunks) yield c;
    }
    const out: string[] = [];
    for await (const l of readCappedLines(gen(), cap)) out.push(l);
    return out;
  }
  it("splits across chunk boundaries and strips CR", async () => {
    expect(await collect(["ab", "c\r\nde", "f\n", "g"], 100)).toEqual(["abc", "def", "g"]);
  });
  it("drops everything past the cap on a line but resumes on the next", async () => {
    const out = await collect(["x".repeat(50), "y".repeat(50), "\nshort\n"], 60);
    expect(out[0]).toHaveLength(60);
    expect(out[1]).toBe("short");
    expect(LINE_CAP_CHARS).toBe(64 * 1024);
  });
});

describe("the raw secret never leaves scan()", () => {
  it("is absent from every exported object and from any serialization of it", async () => {
    fx = makeFixture();
    const tok = githubToken(4);
    const key = pemKey(1);
    fx.write("a/.env", `API_TOKEN=${tok}\n`);
    fx.write("a/id_rsa", key);
    fx.write(".npmrc", `//registry.npmjs.org/:_authToken=${scramble(36, 11)}\n`);
    const r = await scan(opts());
    const blob = JSON.stringify(r);
    expect(r.groups.length).toBeGreaterThan(0);
    for (const secret of [tok, scramble(36, 11), scramble(64, 7)]) {
      expect(blob.includes(secret)).toBe(false);
      expect(blob.includes(secret.slice(4, -4))).toBe(false);
    }
    // Fingerprints are salted HMACs of the secret, not the secret.
    expect(r.groups.some((g) => g.fingerprint === fingerprint(SALT, tok))).toBe(true);
  });
});

describe("rule parity with the app's SECRET_RULES", () => {
  it("bundles the same content rules (one source of truth, not a fork)", async () => {
    const { build } = await import("tsup");
    const out = fs.mkdtempSync(path.join(os.tmpdir(), "sweep-bundle-"));
    try {
      await build({
        config: false,
        entry: [path.resolve(__dirname, "../src/index.ts").split(path.sep).join("/")],
        outDir: out,
        format: ["esm"],
        platform: "node",
        silent: true,
        tsconfig: path.resolve(__dirname, "../tsconfig.json"),
        clean: true,
      });
      const bundle = fs.readFileSync(path.join(out, "index.js"), "utf8");
      const ids = [...new Set(SECRET_RULES.map((r) => r.id))];
      for (const id of ids) expect(bundle).toContain(`id: "${id}"`);
      // Exactly one rule table in the bundle — never a second, forked copy.
      expect(bundle.match(/SECRET_RULES = \[/g)).toHaveLength(1);
      // And the bundled table lists exactly the app's ids.
      const bundled = [...bundle.matchAll(/^\s{4}id: "([a-z0-9-]+)",\n\s{4}severity:/gm)].map(
        (m) => m[1],
      );
      expect(new Set(bundled)).toEqual(new Set(ids));
    } finally {
      fs.rmSync(out, { recursive: true, force: true });
    }
  });
});
