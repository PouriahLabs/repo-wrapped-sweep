import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../src/cli";
import { defaultBaselinePath, saveBaseline, updateBaseline } from "../src/baseline";
import {
  HOOK_COMMAND,
  HOOK_MATCHER,
  extractCandidates,
  hookInstalled,
  installHook,
  isOurCommand,
  runHookCheck,
  settingsPath,
  tokenizeShell,
  uninstallHook,
} from "../src/hook";
import {
  captureIO,
  githubToken,
  makeFixture,
  openSshKey,
  pemFooter,
  pemHeader,
  scramble,
  type Fixture,
} from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

function call(tool: string, toolInput: Record<string, unknown>, cwd?: string) {
  return JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: tool,
    tool_input: toolInput,
    cwd,
  });
}
const check = (stdin: string, cwd = fx.home) => runHookCheck(stdin, fx.env, cwd);
const bash = (command: string) => check(call("Bash", { command }, fx.home));

describe("tokenizeShell", () => {
  it("splits words, quotes, pipes, redirects and subshells", () => {
    expect(tokenizeShell(`cat ".env local" | grep x > out.txt`)).toEqual([
      "cat",
      ".env local",
      "grep",
      "x",
      "out.txt",
    ]);
    expect(tokenizeShell("echo hi>.env")).toEqual(["echo", "hi", ".env"]);
    expect(tokenizeShell("cat $(ls ~/.ssh/id_rsa)")).toEqual(["cat", "$", "ls", "~/.ssh/id_rsa"]);
    expect(tokenizeShell("a;b&&c||d")).toEqual(["a", "b", "c", "d"]);
    expect(tokenizeShell("cat 'it is'")).toEqual(["cat", "it is"]);
  });
  it("keeps Windows backslashes literal", () => {
    expect(tokenizeShell("type C:\\Users\\me\\.env")).toEqual(["type", "C:\\Users\\me\\.env"]);
  });
});

describe("extractCandidates", () => {
  it("reads file_path, path, notebook_path and bash tokens (incl. --flag=value)", () => {
    expect(extractCandidates({ tool_input: { file_path: "/a/b" } })).toEqual(["/a/b"]);
    expect(extractCandidates({ tool_input: { path: "/x", pattern: "t" } })).toEqual(["/x"]);
    expect(extractCandidates({ tool_input: { command: "curl --data=@.env -o out" } })).toContain(
      "@.env",
    );
    expect(extractCandidates({ tool_input: { command: "cmd --file=.env" } })).toContain(".env");
    expect(extractCandidates({})).toEqual([]);
  });
});

describe("hook check — denies", () => {
  it("denies `cat .env.local`", () => {
    fx = makeFixture();
    fx.write(".env.local", `API_TOKEN=${githubToken()}\n`);
    const r = bash("cat .env.local");
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("~/.env.local");
    expect(r.stderr).toContain("environment file");
    expect(r.stderr).not.toContain(githubToken());
  });

  it("denies Read of ~/.ssh/id_ed25519 (an unencrypted OpenSSH key)", () => {
    fx = makeFixture();
    fx.write(".ssh/id_ed25519", openSshKey());
    const r = check(call("Read", { file_path: path.join(fx.home, ".ssh", "id_ed25519") }));
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("private key");
  });

  it("denies `grep -r token ~/Documents/x/.env.prod`", () => {
    fx = makeFixture();
    fx.write("Documents/x/.env.prod", "X=1\n");
    expect(bash("grep -r token ~/Documents/x/.env.prod").code).toBe(2);
  });

  it("denies via Edit, Grep path, redirects and $HOME expansion", () => {
    fx = makeFixture();
    fx.write(".env", "X=1\n");
    expect(check(call("Edit", { file_path: path.join(fx.home, ".env") })).code).toBe(2);
    expect(check(call("Grep", { path: path.join(fx.home, ".env"), pattern: "x" })).code).toBe(2);
    expect(bash("sort < .env").code).toBe(2);
    expect(bash("cat $HOME/.env").code).toBe(2);
    expect(bash("cat ${HOME}/.env").code).toBe(2);
    expect(bash("FOO=.env cat $FOO").code).toBe(2);
  });

  it("denies the credential-store files and cookie/service-account names", () => {
    fx = makeFixture();
    for (const f of [
      ".aws/credentials",
      ".npmrc",
      ".docker/config.json",
      ".netrc",
      ".git-credentials",
      ".kube/config",
    ]) {
      fx.write(f, "x\n");
      expect(bash(`cat ~/${f}`).code, f).toBe(2);
    }
    fx.write("dl/cookies.txt", "x\n");
    fx.write("gcp/my-service-account.json", "{}\n");
    fx.write("server.p12", "x");
    expect(bash("cat ~/dl/cookies.txt").code).toBe(2);
    expect(bash("cat ./gcp/my-service-account.json").code).toBe(2);
    expect(bash("cat server.p12").code).toBe(2);
  });

  it("does not block files a sweep rated low (test fixtures, samples)", () => {
    fx = makeFixture();
    const fixture = fx.write("proj/test/scan.test.ts", "const k = 'fake';\n");
    const real = fx.write("proj/notes.txt", "token\n");
    const entry = (loc: string, severity?: "low" | "high") => ({
      ruleId: "github-personal-access-token",
      copies: 1,
      locations: [loc],
      ...(severity ? { severity } : {}),
      firstSeen: "2026-10-26T00:00:00.000Z",
      lastSeen: "2026-10-26T00:00:00.000Z",
    });
    saveBaseline(defaultBaselinePath(fx.env), {
      schemaVersion: 1,
      updatedAt: "2026-10-26T00:00:00.000Z",
      findings: {
        a: entry("~/proj/test/scan.test.ts", "low"),
        b: entry("~/proj/notes.txt"), // pre-severity baseline entry → still blocks
      },
    });
    expect(bash(`cat ${fixture}`).code).toBe(0);
    expect(bash(`cat ${real}`).code).toBe(2);
  });

  it("allows text that only names a credential file that does not exist", () => {
    fx = makeFixture();
    // a heredoc body / inline script mentioning .env.local — nothing to leak
    expect(bash("node - <<'EOF'\nconst f = '.env.local';\nEOF").code).toBe(0);
    expect(bash("cat .env.local").code).toBe(0);
    fx.write(".env.local", "X=1\n");
    expect(bash("cat .env.local").code).toBe(2);
  });

  it("expands a wildcard token", () => {
    fx = makeFixture();
    fx.write(".env.production", "X=1\n");
    expect(bash("cat .env*").code).toBe(2);
    expect(bash("cat nothing*").code).toBe(0);
  });

  it("denies a private-key .pem but allows a certificate-only .pem", () => {
    fx = makeFixture();
    fx.write(
      "certs/server.pem",
      `${pemHeader("RSA PRIVATE KEY")}\n${scramble(60)}\n${pemFooter("RSA PRIVATE KEY")}\n`,
    );
    fx.write(
      "certs/fullchain.pem",
      `${pemHeader("CERTIFICATE")}\n${scramble(60)}\n${pemFooter("CERTIFICATE")}\n`,
    );
    expect(bash("cat certs/server.pem").code).toBe(2);
    expect(bash("cat certs/fullchain.pem").code).toBe(0);
  });

  it("denies a file a previous sweep found secrets in (baseline location list)", () => {
    fx = makeFixture();
    const abs = fx.write("code/config.ts", "export const x = 1;\n");
    const baseline = updateBaseline(
      [
        {
          fingerprint: "f1",
          ruleId: "github-personal-access-token",
          severity: "high",
          preview: "",
          copies: 1,
          locations: [{ path: "~/code/config.ts", locationClass: "documents" }],
          locationClasses: { documents: 1 },
        },
      ],
      null,
      "full",
      "2026-01-01T00:00:00.000Z",
    );
    saveBaseline(defaultBaselinePath(fx.env), baseline);
    const r = check(call("Read", { file_path: abs }));
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("previous sweep");
    // …but not once it is marked resolved
    baseline.findings.f1!.resolvedAt = "2026-01-02T00:00:00.000Z";
    saveBaseline(defaultBaselinePath(fx.env), baseline);
    expect(check(call("Read", { file_path: abs })).code).toBe(0);
  });
});

describe("hook check — allows", () => {
  it("allows .env.example / .env.sample / .env.template", () => {
    fx = makeFixture();
    for (const f of [".env.example", ".env.sample", ".env.template"]) {
      fx.write(f, `T=${githubToken()}\n`);
      expect(bash(`cat ${f}`).code, f).toBe(0);
    }
  });

  it("allows ls, git, normal source files and a public key", () => {
    fx = makeFixture();
    fx.write("src/app.ts", "export {}\n");
    fx.write(".ssh/id_rsa.pub", "ssh-rsa AAAA me@host\n");
    fx.write(".ssh/config", "Host x\n");
    fx.write(".ssh/known_hosts", "x\n");
    for (const cmd of [
      "ls",
      "ls -la",
      "git status",
      "cat src/app.ts",
      "npm run build",
      "cat ~/.ssh/id_rsa.pub",
      "cat ~/.ssh/config",
    ]) {
      expect(bash(cmd).code, cmd).toBe(0);
    }
    expect(check(call("Read", { file_path: path.join(fx.home, "src", "app.ts") })).code).toBe(0);
  });

  it("allows an ambiguous *env*.json and a project .npmrc (not read unread)", () => {
    fx = makeFixture();
    fx.write("app/environment.json", "{}");
    fx.write("proj/.npmrc", "registry=https://r.example.org\n");
    expect(bash("cat app/environment.json").code).toBe(0);
    expect(bash("cat proj/.npmrc").code).toBe(0);
  });

  it("allows a key path that does not exist (nothing to protect)", () => {
    fx = makeFixture();
    expect(bash("cat ~/.ssh/id_rsa").code).toBe(0);
    expect(bash("ssh-keygen -f ~/.ssh/id_new").code).toBe(0);
  });

  it("ignores URLs", () => {
    fx = makeFixture();
    expect(bash("curl https://example.org/files/server.pem").code).toBe(0);
  });

  it("honours hookAllow globs", () => {
    fx = makeFixture();
    fx.write(".env.test", "X=1\n");
    fx.write("keep/.env", "X=1\n");
    expect(bash("cat .env.test").code).toBe(2);
    fs.mkdirSync(fx.env.configDir, { recursive: true });
    fs.writeFileSync(
      path.join(fx.env.configDir, "sweep.json"),
      JSON.stringify({ hookAllow: ["~/.env.test", "**/keep/.env"] }),
    );
    expect(bash("cat .env.test").code).toBe(0);
    expect(bash("cat keep/.env").code).toBe(0);
  });
});

describe("hook check — failure modes", () => {
  it("fails open on malformed stdin, empty stdin and odd shapes", () => {
    fx = makeFixture();
    for (const stdin of [
      "",
      "not json",
      "null",
      "[]",
      "42",
      '{"tool_input":"str"}',
      '{"tool_input":{"command":5}}',
    ]) {
      expect(check(stdin).code, stdin).toBe(0);
    }
    expect(check("not json").stderr).toContain("malformed");
  });

  it("stays well inside the 50 ms budget per call", () => {
    fx = makeFixture();
    fx.write(".env", "X=1\n");
    const stdin = call("Bash", { command: "cat .env && ls -la && git status" }, fx.home);
    check(stdin); // warm
    const t0 = performance.now();
    for (let i = 0; i < 20; i++) check(stdin);
    expect((performance.now() - t0) / 20).toBeLessThan(50);
  });
});

describe("hook install / uninstall / status", () => {
  it("creates the entry, and installing twice leaves exactly one", () => {
    fx = makeFixture();
    const file = settingsPath("user", fx.env, fx.home);
    expect(installHook(file).changed).toBe(true);
    expect(installHook(file).changed).toBe(false);
    const s = JSON.parse(fs.readFileSync(file, "utf8"));
    expect(s.hooks.PreToolUse).toHaveLength(1);
    expect(s.hooks.PreToolUse[0]).toEqual({
      matcher: HOOK_MATCHER,
      hooks: [{ type: "command", command: HOOK_COMMAND }],
    });
    expect(HOOK_MATCHER).toBe("Read|Bash|PowerShell|Grep|Edit|MultiEdit|NotebookEdit");
    expect(HOOK_COMMAND).toBe("repo-wrapped-sweep hook check");
    expect(hookInstalled(file)).toBe(true);
  });

  it("merges without clobbering other settings or hooks", () => {
    fx = makeFixture();
    const file = settingsPath("user", fx.env, fx.home);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const existing = {
      model: "opus",
      permissions: { allow: ["Bash(ls)"] },
      hooks: {
        PreToolUse: [{ matcher: "Write", hooks: [{ type: "command", command: "my-linter" }] }],
        PostToolUse: [{ hooks: [{ type: "command", command: "notify" }] }],
      },
    };
    fs.writeFileSync(file, JSON.stringify(existing));
    installHook(file);
    const s = JSON.parse(fs.readFileSync(file, "utf8"));
    expect(s.model).toBe("opus");
    expect(s.permissions).toEqual(existing.permissions);
    expect(s.hooks.PostToolUse).toEqual(existing.hooks.PostToolUse);
    expect(s.hooks.PreToolUse).toHaveLength(2);
    expect(s.hooks.PreToolUse[0].hooks[0].command).toBe("my-linter");
  });

  it("uninstall removes only our entry (and tidies up what it created)", () => {
    fx = makeFixture();
    const file = settingsPath("user", fx.env, fx.home);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(
      file,
      JSON.stringify({
        hooks: {
          PreToolUse: [{ matcher: "Write", hooks: [{ type: "command", command: "my-linter" }] }],
        },
      }),
    );
    installHook(file);
    expect(uninstallHook(file).removed).toBe(1);
    const s = JSON.parse(fs.readFileSync(file, "utf8"));
    expect(s.hooks.PreToolUse).toEqual([
      { matcher: "Write", hooks: [{ type: "command", command: "my-linter" }] },
    ]);
    expect(uninstallHook(file).removed).toBe(0);

    // on a file we created, uninstall leaves no empty hooks key behind
    const other = settingsPath("project", fx.env, path.join(fx.root, "proj"));
    installHook(other);
    uninstallHook(other);
    expect(JSON.parse(fs.readFileSync(other, "utf8"))).toEqual({});
  });

  it("removes our command from a shared entry without dropping its siblings", () => {
    fx = makeFixture();
    const file = settingsPath("user", fx.env, fx.home);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(
      file,
      JSON.stringify({
        hooks: {
          PreToolUse: [
            {
              matcher: "Bash",
              hooks: [
                { type: "command", command: "other-tool" },
                { type: "command", command: "npx repo-wrapped-sweep hook check" },
              ],
            },
          ],
        },
      }),
    );
    expect(uninstallHook(file).removed).toBe(1);
    expect(JSON.parse(fs.readFileSync(file, "utf8")).hooks.PreToolUse[0].hooks).toEqual([
      { type: "command", command: "other-tool" },
    ]);
  });

  it("refuses to touch a settings file it cannot parse", () => {
    fx = makeFixture();
    const file = settingsPath("user", fx.env, fx.home);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, "{ // jsonc\n}");
    expect(() => installHook(file)).toThrow(/not valid JSON/);
    expect(fs.readFileSync(file, "utf8")).toBe("{ // jsonc\n}");
    expect(hookInstalled(file)).toBe(false);
  });

  it("recognises our command in its variants only", () => {
    expect(isOurCommand("repo-wrapped-sweep hook check")).toBe(true);
    expect(isOurCommand("npx -y repo-wrapped-sweep hook check")).toBe(true);
    expect(isOurCommand("/usr/local/bin/sweep hook check")).toBe(true);
    expect(isOurCommand("some-other hook check")).toBe(false);
    expect(isOurCommand("repo-wrapped-sweep scan")).toBe(false);
    expect(isOurCommand(undefined)).toBe(false);
  });

  it("works through the CLI: project scope, status, uninstall, bad scope, check", async () => {
    fx = makeFixture();
    const proj = path.join(fx.root, "proj");
    fs.mkdirSync(proj);
    const run = async (args: string[], stdin?: string) => {
      const io = captureIO();
      io.readStdin = async () => stdin ?? "";
      const code = await main(args, io, fx.env, proj);
      return { code, out: io.out(), err: io.err() };
    };
    expect((await run(["hook", "install", "--scope", "project"])).out).toContain("installed");
    expect(fs.existsSync(path.join(proj, ".claude", "settings.json"))).toBe(true);
    expect((await run(["hook", "install", "--scope", "project"])).out).toContain(
      "already installed",
    );
    const status = (await run(["hook", "status"])).out;
    expect(status).toMatch(/project\s+installed/);
    expect(status).toMatch(/user\s+not installed/);
    expect((await run(["hook", "uninstall", "--scope", "project"])).out).toContain("removed");
    expect((await run(["hook", "install", "--scope", "galaxy"])).code).toBe(2);
    expect((await run(["hook", "wat"])).code).toBe(2);

    fx.write(".env", "X=1\n");
    const denied = await run(["hook", "check"], call("Bash", { command: "cat .env" }, fx.home));
    expect(denied.code).toBe(2);
    expect(denied.err).toContain("blocked");
    expect((await run(["hook", "check"], "garbage")).code).toBe(0);
  });
});
