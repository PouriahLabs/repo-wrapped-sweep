import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { adjustSeverity, raiseSeverity } from "@/lib/native-scan/path-rules";
import { SECRET_RULES } from "@/lib/native-scan/secret-rules";
import type { Severity } from "@/lib/org-security";
import { main } from "../src/cli";
import { isConfigLikeFile, isInstalledSoftwareDir, underFixtureDir } from "../src/locations";
import { buildJsonReport, locationLabel, renderTable } from "../src/report";
import { scan, type ScanOptions } from "../src/scan";
import type { SweepEnv } from "../src/env";
import { buildA10Tree, fileUri, stripeLiveKey } from "./a10-fixture";
import { captureIO, githubToken, makeFixture, pemKey, scramble, type Fixture } from "./helpers";

const SALT = new Uint8Array(32).fill(5);
let fx: Fixture;
afterEach(() => fx?.cleanup());

const opts = (over: Partial<ScanOptions> = {}): ScanOptions => ({
  env: fx.env,
  roots: [], // a FULL sweep of the home directory
  quick: false,
  excludeGlobs: [],
  includeCloud: false,
  concurrency: 4,
  salt: SALT,
  placeholders: null,
  ...over,
});

const ruleSeverity = (id: string): Severity => SECRET_RULES.find((r) => r.id === id)!.severity;
const group = (r: Awaited<ReturnType<typeof scan>>, suffix: string) =>
  r.groups.find((g) => g.locations.some((l) => l.path.endsWith(suffix)));

// ---------------------------------------------------------------------------
// The acceptance tree
// ---------------------------------------------------------------------------

describe("a full sweep of a noisy dev machine", () => {
  it("reports none of the installed-software, cache, fixture-shaped or source-file noise", async () => {
    fx = makeFixture({ platform: "win32" });
    const tree = buildA10Tree(fx.home, "win32");
    const r = await scan(opts());

    // Every file in `noise` carries a secret the pre-A10 sweep reported. None may surface.
    const leaked = r.groups.flatMap((g) => g.locations.map((l) => l.path));
    for (const rel of tree.noise) {
      expect(
        leaked.some((p) => p === `~/${rel}`),
        rel,
      ).toBe(false);
    }
    // …and the only findings are the four real ones.
    expect(r.groups).toHaveLength(4);
  });

  it("still reports the real cases at their original severity", async () => {
    fx = makeFixture({ platform: "win32" });
    const tree = buildA10Tree(fx.home, "win32");
    const r = await scan(opts());

    // ghp_ in a VS Code history copy of a .prod file
    const hist = group(r, "History/-6a9ea81e/9ya8.prod")!;
    expect(hist.ruleId).toBe("github-personal-access-token");
    expect(hist.severity).toBe(
      adjustSeverity(ruleSeverity("github-personal-access-token"), "editor-history"),
    );
    expect(hist.locations[0]!.origin).toBe("~/Documents/proj/.env.prod");

    // sk_live in an .env backup
    const bak = group(r, tree.real.envBackup)!;
    expect(bak.ruleId).toBe("stripe-secret-key");
    expect(bak.severity).toBe(raiseSeverity(ruleSeverity("stripe-secret-key")));

    // a PAT in ~/.claude/history.jsonl
    const claude = group(r, tree.real.claudeHistory)!;
    expect(claude.ruleId).toBe("github-personal-access-token");
    expect(claude.severity).toBe(
      adjustSeverity(ruleSeverity("github-personal-access-token"), "agent-transcript"),
    );
    expect(claude.locations[0]!.locationClass).toBe("agent-transcript");

    // a prod .pem in Documents
    const pem = group(r, tree.real.prodPem)!;
    expect(pem.ruleId).toBe("path.private-key");
    expect(pem.severity).toBe("critical");
  });

  it("--no-default-excludes (noDefaultExcludes) walks the installed-software trees again", async () => {
    fx = makeFixture({ platform: "win32" });
    buildA10Tree(fx.home, "win32");
    const quiet = await scan(opts());
    const loud = await scan(opts({ noDefaultExcludes: true }));
    expect(loud.groups.length).toBeGreaterThanOrEqual(quiet.groups.length + 8);
    const paths = loud.groups.flatMap((g) => g.locations.map((l) => l.path));
    // installed software is back…
    expect(paths).toContain("~/AppData/Local/Programs/Foo/resources/app/.env");
    expect(paths).toContain("~/.nuget/packages/foo/1.0.0/x.env");
    expect(paths).toContain("~/.vscode/extensions/acme.ext-1.0.0/keys/server.pem");
    // …but the always-on excludes (node_modules, .git, OS caches) are not part of this switch
    fx.write("proj/node_modules/pkg/x.env", `T=${githubToken(900)}\n`);
    const again = await scan(opts({ noDefaultExcludes: true }));
    expect(again.groups.flatMap((g) => g.locations.map((l) => l.path))).not.toContain(
      "~/proj/node_modules/pkg/x.env",
    );
  });
});

// ---------------------------------------------------------------------------
// Default excludes, per OS
// ---------------------------------------------------------------------------

describe("isInstalledSoftwareDir", () => {
  const env = (platform: NodeJS.Platform, home: string): SweepEnv => ({
    platform,
    home,
    cloudRoots: [],
    configDir: "/cfg",
  });
  const win = env("win32", "C:\\Users\\me");
  const mac = env("darwin", "/Users/me");
  const lin = env("linux", "/home/me");

  it("Windows: installed programs, Microsoft/Google/Epic data, GitHub Desktop releases, browser profiles", () => {
    for (const rel of [
      "AppData/Local/Programs",
      "AppData/Local/Microsoft",
      "AppData/Local/Google/Cloud SDK",
      "AppData/Roaming/gcloud/logs",
      "AppData/Local/Epic Games",
      "AppData/Local/GitHubDesktop/app-3.4.2",
      "AppData/Local/Microsoft/Edge/User Data",
      "AppData/Local/Google/Chrome/User Data",
      "AppData/Local/BraveSoftware/Brave-Browser/User Data",
      "AppData/Local/Vivaldi/User Data",
      ".vscode/extensions",
      ".cursor/extensions",
      "scoop/apps",
      "scoop/buckets",
      "go/pkg/mod",
    ]) {
      expect(isInstalledSoftwareDir(`C:\\Users\\me\\${rel.replace(/\//g, "\\")}`, win), rel).toBe(
        true,
      );
    }
    expect(isInstalledSoftwareDir("C:\\Program Files", win)).toBe(true);
    expect(isInstalledSoftwareDir("C:\\Program Files (x86)", win)).toBe(true);
    expect(isInstalledSoftwareDir("c:\\program files", win)).toBe(true);
  });
  it("Windows: what a person wrote — and the places secrets really sit — are left alone", () => {
    for (const rel of [
      "Documents",
      "AppData/Roaming/Code/User/History",
      "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine",
      "AppData/Roaming/gcloud",
      "AppData/Local/GitHubDesktop",
      "AppData/Local/Programs-notes",
      "scoop",
      ".claude/projects",
      ".ssh",
      "code/app",
    ]) {
      expect(isInstalledSoftwareDir(`C:\\Users\\me\\${rel.replace(/\//g, "\\")}`, win), rel).toBe(
        false,
      );
    }
    expect(isInstalledSoftwareDir("C:\\Program Files Backup", win)).toBe(false);
    expect(isInstalledSoftwareDir("C:\\Users\\me\\Program Files", win)).toBe(false);
  });
  it("macOS: /Applications, Homebrew, and Application Support — except the editors' User/History", () => {
    for (const p of [
      "/Applications",
      "/opt/homebrew/Cellar",
      "/opt/homebrew/Caskroom",
      "/usr/local/Cellar",
      "/usr/local/Caskroom",
      "/Users/me/Library/Application Support/Slack",
      "/Users/me/Library/Application Support/Google",
      "/Users/me/Library/Application Support/Code/Cache",
      "/Users/me/Library/Application Support/Code/User/globalStorage",
      "/Users/me/Library/Application Support/Code/User/workspaceStorage",
      "/Users/me/Library/Application Support/Cursor/CachedData",
    ]) {
      expect(isInstalledSoftwareDir(p, mac), p).toBe(true);
    }
    for (const p of [
      "/Users/me/Library/Application Support",
      "/Users/me/Library/Application Support/Code",
      "/Users/me/Library/Application Support/Code/User",
      "/Users/me/Library/Application Support/Code/User/History",
      "/Users/me/Library/Application Support/Code/User/History/-6a9ea81e",
      "/Users/me/Library/Application Support/Code - Insiders/User/History",
      "/Users/me/Library/Application Support/Cursor/User/History",
      "/Users/me/Library/Application Support/Windsurf/User/History",
      "/Users/me/Library/Application Support/VSCodium/User/History",
      "/Users/me/Documents",
      "/Users/me/Library/Preferences",
    ]) {
      expect(isInstalledSoftwareDir(p, mac), p).toBe(false);
    }
  });
  it("every OS: package caches and toolchains under the home directory, and site-packages anywhere", () => {
    for (const [e, home] of [
      [win, "C:\\Users\\me"],
      [mac, "/Users/me"],
      [lin, "/home/me"],
    ] as const) {
      const sep = e.platform === "win32" ? "\\" : "/";
      for (const rel of [
        ".cargo/registry",
        ".rustup",
        ".m2",
        ".gradle",
        ".nuget",
        ".npm/_cacache",
        "go/pkg/mod",
        ".vscode/extensions",
      ]) {
        expect(
          isInstalledSoftwareDir(`${home}${sep}${rel.replace(/\//g, sep)}`, e),
          `${e.platform} ${rel}`,
        ).toBe(true);
      }
      expect(
        isInstalledSoftwareDir(`${home}${sep}proj${sep}.venv${sep}lib${sep}site-packages`, e),
      ).toBe(true);
      expect(isInstalledSoftwareDir(`${home}${sep}.cargo${sep}bin`, e)).toBe(false);
      expect(isInstalledSoftwareDir(`${home}${sep}.m2-notes`, e)).toBe(false);
    }
  });
  it("Linux has no Application Support special-casing and keeps ~/.config editor history reachable", () => {
    expect(isInstalledSoftwareDir("/home/me/.config/Code/User/History/-abc", lin)).toBe(false);
    expect(isInstalledSoftwareDir("/home/me/Library/Application Support/Slack", lin)).toBe(false);
  });
  it("an explicit root inside an excluded tree is still walked", async () => {
    fx = makeFixture({ platform: "win32" });
    fx.write(".nuget/packages/x.env", `T=${githubToken(901)}\n`);
    const viaHome = await scan(opts());
    expect(viaHome.groups).toHaveLength(0);
    const viaRoot = await scan(opts({ roots: [path.join(fx.home, ".nuget")] }));
    expect(viaRoot.groups).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Fixture / vendor downgrade
// ---------------------------------------------------------------------------

describe("test and vendor fixtures drop to low", () => {
  it("underFixtureDir looks at directory segments only", () => {
    for (const p of [
      "~/proj/test/x.pem",
      "~/proj/Tests/x.pem",
      "~/proj/__tests__/x.js",
      "~/proj/testdata/k",
      "~/proj/test_data/k",
      "~/proj/src/fixtures/k",
      "~/proj/third_party/k",
      "~/proj/vendor/k",
      "~/proj/dummyserver/k",
      "~/proj/examples/k",
      "C:\\Users\\me\\proj\\Vendor\\k",
    ]) {
      expect(underFixtureDir(p), p).toBe(true);
    }
    for (const p of [
      "~/proj/test",
      "~/proj/testing/k",
      "~/proj/latest/k",
      "~/proj/src/k",
      "~/proj/contest/k",
    ]) {
      expect(underFixtureDir(p), p).toBe(false);
    }
  });

  it("downgrades every kind of hit — path rules included — to low", async () => {
    fx = makeFixture();
    fx.write("proj/tests/fixtures/server.pem", pemKey(2)); // a path-rule hit (critical)
    fx.write("proj/vendor/lib/.env", `STRIPE=${stripeLiveKey(2)}\n`); // content + env rule
    fx.write("proj/examples/app/config.json", `{"token": "${githubToken(910)}"}\n`);
    fx.write("proj/src/real.pem", pemKey(3));
    const r = await scan(opts({ roots: [path.join(fx.home, "proj")] }));
    expect(r.groups).toHaveLength(4);
    const sev = (suffix: string) => group(r, suffix)!.severity;
    expect(sev("tests/fixtures/server.pem")).toBe("low");
    expect(sev("vendor/lib/.env")).toBe("low");
    expect(sev("examples/app/config.json")).toBe("low");
    expect(sev("src/real.pem")).toBe("critical");
  });

  it("never downgrades an agent transcript, whatever the path says", async () => {
    fx = makeFixture();
    const line = JSON.stringify({ display: `token ${githubToken(911)}` });
    fx.write(".claude/projects/tests/session.jsonl", `${line}\n`);
    fx.write(
      ".claude/projects/vendor/other.jsonl",
      `${JSON.stringify({ display: `t ${githubToken(912)}` })}\n`,
    );
    const r = await scan(opts());
    expect(r.groups).toHaveLength(2);
    for (const g of r.groups) {
      expect(g.severity).toBe(
        adjustSeverity(ruleSeverity("github-personal-access-token"), "agent-transcript"),
      );
    }
  });

  it("judges an editor-history snapshot by the file it was a copy OF", async () => {
    fx = makeFixture();
    const sampleSrc = path.join(fx.home, "proj/tests/fixtures/.env.local");
    const realSrc = path.join(fx.home, "proj/.env.production");
    const hist = "AppData/Roaming/Code/User/History";
    fx.write(`${hist}/-aa11/one.local`, `T=${githubToken(920)}\n`);
    fx.write(
      `${hist}/-aa11/entries.json`,
      JSON.stringify({ version: 1, resource: fileUri(sampleSrc), entries: [] }),
    );
    fx.write(`${hist}/-bb22/two.production`, `T=${githubToken(921)}\n`);
    fx.write(
      `${hist}/-bb22/entries.json`,
      JSON.stringify({ version: 1, resource: fileUri(realSrc), entries: [] }),
    );
    // no index at all: opaque, so no fixture judgement either way
    fx.write(`${hist}/-cc33/three.txt`, `T=${githubToken(922)}\n`);
    const r = await scan(opts());
    const expected = adjustSeverity(ruleSeverity("github-personal-access-token"), "editor-history");
    expect(group(r, "-aa11/one.local")!.severity).toBe("low");
    expect(group(r, "-bb22/two.production")!.severity).toBe(expected);
    expect(group(r, "-cc33/three.txt")!.severity).toBe(expected);
    expect(group(r, "-cc33/three.txt")!.locations[0]!.origin).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The generic rule
// ---------------------------------------------------------------------------

describe("generic-secret-assignment in a full sweep", () => {
  const secret = () => scramble(32, 11);
  const assignment = (v: string) => `password = "${v}"\n`;

  it("fires in config-like files, shell history, transcripts and editor history only", async () => {
    fx = makeFixture();
    const fires: Record<string, string> = {
      "cfg/app.json": `{\n  "password": "${secret()}"\n}\n`,
      "cfg/app.yaml": `password: "${secret()}"\n`,
      "cfg/app.yml": `password: "${secret()}"\n`,
      "cfg/app.toml": assignment(secret()),
      "cfg/app.ini": assignment(secret()),
      "cfg/app.properties": assignment(secret()),
      "cfg/app.conf": assignment(secret()),
      "cfg/app.config": assignment(secret()),
      "cfg/app.xml": `<a password="${secret()}"/>\n`,
      "cfg/.env": `password="${secret()}"\n`,
      "cfg/.env.local": `password="${secret()}"\n`,
      "cfg/.myapprc": assignment(secret()),
      ".bash_history": `mysql --password="${secret()}"\n`,
      ".claude/projects/p/s.jsonl": `${JSON.stringify({ text: `password: ${secret()}` })}\n`,
    };
    // values must differ per file so each is its own finding
    let i = 0;
    for (const [rel, body] of Object.entries(fires)) {
      fx.write(rel, body.replace(/[A-Za-z0-9]{32}/, scramble(32, 13 + 2 * i++)));
    }
    const r = await scan(opts());
    const hit = new Set(r.groups.flatMap((g) => g.locations.map((l) => l.path)));
    for (const rel of Object.keys(fires)) expect(hit.has(`~/${rel}`), rel).toBe(true);
  });

  it("does not fire in source files, markdown or logs", async () => {
    fx = makeFixture();
    for (const rel of [
      "src/a.ts",
      "src/b.js",
      "src/c.py",
      "src/d.go",
      "docs/e.md",
      "x/f.txt",
      "x/g.log",
      "x/h.sh",
    ]) {
      fx.write(rel, assignment(secret()));
    }
    expect((await scan(opts())).groups).toHaveLength(0);
  });

  it("is a full-sweep rule: an explicit --root scans everything under it", async () => {
    fx = makeFixture();
    fx.write("src/a.ts", assignment(secret()));
    expect((await scan(opts({ roots: [fx.home] }))).groups).toHaveLength(1);
  });

  it("skips a line over 1,000 characters even in a config file — but not a provider token on it", async () => {
    fx = makeFixture();
    const pad = "x".repeat(1100);
    fx.write("cfg/bundle.json", `{"blob":"${pad}","password":"${secret()}"}\n`);
    fx.write("cfg/ok.json", `{"password":"${secret()}"}\n`);
    fx.write("cfg/long-provider.json", `{"blob":"${pad}","gh":"${githubToken(930)}"}\n`);
    const r = await scan(opts());
    const paths = r.groups.flatMap((g) => g.locations.map((l) => l.path));
    expect(paths).toContain("~/cfg/ok.json");
    expect(paths).not.toContain("~/cfg/bundle.json");
    expect(paths).toContain("~/cfg/long-provider.json");
  });

  it("provider rules fire everywhere: source, markdown and logs", async () => {
    fx = makeFixture();
    fx.write("src/a.ts", `const t = "${githubToken(940)}";\n`);
    fx.write("docs/b.md", `use ${githubToken(941)}\n`);
    fx.write("x/c.log", `${githubToken(942)}\n`);
    expect((await scan(opts())).groups).toHaveLength(3);
  });

  it("isConfigLikeFile", () => {
    expect(isConfigLikeFile("~/a/x.json", "documents")).toBe(true);
    expect(isConfigLikeFile("~/a/.env.production", "documents")).toBe(true);
    expect(isConfigLikeFile("~/a/prod.env", "documents")).toBe(true);
    expect(isConfigLikeFile("~/.npmrc", "credential-store")).toBe(true);
    expect(isConfigLikeFile("~/a/x.ts", "documents")).toBe(false);
    expect(isConfigLikeFile("~/a/x.ts", "shell-history")).toBe(true);
    expect(isConfigLikeFile("~/a/x.ts", "agent-transcript")).toBe(true);
    expect(isConfigLikeFile("~/a/opaque.prod", "editor-history")).toBe(true);
    expect(isConfigLikeFile("~/a/x.md", "documents")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

describe("low findings are collapsed unless --all", () => {
  const build = async () => {
    fx = makeFixture();
    fx.write("proj/src/real.pem", pemKey(4));
    fx.write("proj/tests/fixtures/sample.pem", pemKey(6));
    fx.write("proj/vendor/x.env", `T=${githubToken(950)}\n`);
    return scan(opts({ roots: [path.join(fx.home, "proj")] }));
  };
  const ctx = (r: Awaited<ReturnType<typeof scan>>) => ({
    version: "t",
    os: "linux",
    diff: { baselineExisted: false, newFingerprints: new Set<string>(), gone: [] },
    validity: undefined,
  });

  it("the table lists one finding and a single line for the rest", async () => {
    const r = await build();
    const table = renderTable(r, ctx(r), { color: false, width: 140 });
    expect(table).toContain("real.pem");
    expect(table).not.toContain("sample.pem");
    expect(table).not.toContain("vendor");
    expect(table).toContain("2 low-severity findings not listed");
    expect(table).toContain("--all");
    // the totals still tell the truth
    expect(table).toContain("3 findings (1 critical, 2 low)");
  });
  it("--all lists everything", async () => {
    const r = await build();
    const table = renderTable(r, ctx(r), { color: false, width: 140, all: true });
    expect(table).toContain("sample.pem");
    expect(table).not.toContain("not listed");
  });
  it("only low findings: says so rather than printing an empty table", async () => {
    fx = makeFixture();
    fx.write("proj/vendor/x.env", `T=${githubToken(951)}\n`);
    const r = await scan(opts({ roots: [path.join(fx.home, "proj")] }));
    const table = renderTable(r, ctx(r), { color: false, width: 140 });
    expect(table).toContain("No findings above low severity");
    expect(table).toContain("1 low-severity finding not listed");
  });
  it("--json is never collapsed", async () => {
    const r = await build();
    expect(buildJsonReport(r, ctx(r)).findings).toHaveLength(3);
  });
  it("exit code and --fail-on still see the collapsed findings", async () => {
    fx = makeFixture();
    fx.write("proj/vendor/x.env", `T=${githubToken(952)}\n`);
    const io = captureIO();
    const code = await main(
      ["--root", path.join(fx.home, "proj"), "--no-update", "--fail-on", "low"],
      io,
      fx.env,
      fx.home,
    );
    expect(code).toBe(1);
    expect(io.out()).toContain("not listed");
  });
});

describe("VS Code history in a report", () => {
  it("names the original file, not the opaque snapshot", async () => {
    fx = makeFixture();
    const tree = buildA10Tree(fx.home, "win32");
    const r = await scan(opts());
    const g = group(r, tree.real.historyProd)!;
    expect(locationLabel(g.locations[0]!)).toBe("VS Code history of ~/Documents/proj/.env.prod");
    const ctx = {
      version: "t",
      os: "linux",
      diff: { baselineExisted: false, newFingerprints: new Set<string>(), gone: [] },
      validity: undefined,
    };
    const table = renderTable(r, ctx, { color: false, width: 160 });
    expect(table).toContain("VS Code history of ~/Documents/proj/.env.prod");
    expect(table).not.toContain("9ya8.prod");
    // the real path is still in the JSON, for `fix`
    const json = buildJsonReport(r, ctx).findings.find((f) => f.fingerprint === g.fingerprint)!;
    expect(json.locations[0]).toMatchObject({
      path: "~/AppData/Roaming/Code/User/History/-6a9ea81e/9ya8.prod",
      origin: "~/Documents/proj/.env.prod",
    });
  });
  it("a copy of an example env file is not a finding", async () => {
    fx = makeFixture();
    const hist = "AppData/Roaming/Code/User/History/-ee55";
    fx.write(`${hist}/abcd.example`, `T=${githubToken(960)}\n`);
    fx.write(
      `${hist}/entries.json`,
      JSON.stringify({
        version: 1,
        resource: fileUri(path.join(fx.home, "app/.env.example")),
        entries: [],
      }),
    );
    expect((await scan(opts())).groups).toHaveLength(0);
  });
});

describe("the new flags, through the CLI", () => {
  const run = async (args: string[]) => {
    const io = captureIO();
    const code = await main(["--no-update", ...args], io, fx.env, fx.home);
    return { code, out: io.out(), err: io.err() };
  };

  it("--no-default-excludes walks the installed-software trees; the default does not", async () => {
    fx = makeFixture({ platform: "win32" });
    fx.write(".nuget/packages/foo/x.env", `T=${githubToken(970)}\n`);
    fx.write("code/.env", `T=${githubToken(971)}\n`);
    const quiet = JSON.parse((await run(["--json"])).out);
    expect(
      quiet.findings.map((f: { locations: { path: string }[] }) => f.locations[0]!.path),
    ).toEqual(["~/code/.env"]);
    const loud = JSON.parse((await run(["--json", "--no-default-excludes"])).out);
    expect(loud.summary.total).toBe(2);
  });

  it("--all lists the low-severity findings the table otherwise folds away", async () => {
    fx = makeFixture({ platform: "win32" });
    fx.write("code/.env", `T=${githubToken(972)}\n`);
    fx.write("code/vendor/lib/.env", `T=${githubToken(973)}\n`);
    const folded = (await run([])).out;
    expect(folded).toContain("1 low-severity finding not listed");
    expect(folded).not.toContain("vendor");
    const all = (await run(["--all"])).out;
    expect(all).toContain("vendor");
    expect(all).not.toContain("not listed");
  });

  it("documents both flags in --help", async () => {
    fx = makeFixture();
    const help = (await run(["--help"])).out;
    expect(help).toContain("--no-default-excludes");
    expect(help).toContain("--all");
  });
});
