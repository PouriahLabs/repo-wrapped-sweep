import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  keychainFor,
  keychainService,
  linuxKeychain,
  linuxTrash,
  macKeychain,
  macTrash,
  onePasswordHint,
  trashFor,
  ttyPrompter,
  uniqueTrashName,
  windowsKeychain,
  windowsTrash,
  type Exec,
  type ExecOptions,
} from "../src/platform";
import { makeFixture, scramble, type Fixture } from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

interface Call {
  cmd: string;
  args: string[];
  opts?: ExecOptions;
}
function mockExec(
  results: Record<string, { code: number; stderr?: string; stdout?: string }> = {},
) {
  const calls: Call[] = [];
  const exec: Exec = async (cmd, args, opts) => {
    calls.push({ cmd, args, opts });
    const r = results[cmd] ?? { code: 0 };
    return { code: r.code, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
  };
  return { exec, calls };
}

describe("uniqueTrashName", () => {
  it("keeps a free name and numbers collisions, preserving the extension", () => {
    expect(uniqueTrashName("a.env", () => false)).toBe("a.env");
    const taken = new Set(["a.env", "a 2.env"]);
    expect(uniqueTrashName("a.env", (n) => taken.has(n))).toBe("a 3.env");
    expect(uniqueTrashName("noext", (n) => n === "noext")).toBe("noext 2");
  });
});

describe("macTrash — moves into ~/.Trash, never unlinks", () => {
  it("renames the file into the Trash and keeps the content", async () => {
    fx = makeFixture();
    const file = fx.write("docs/id_rsa", "KEY");
    const { exec, calls } = mockExec();
    const r = await macTrash(fx.env, exec).trash(file);
    expect(r.ok).toBe(true);
    expect(fs.existsSync(file)).toBe(false);
    expect(fs.readFileSync(path.join(fx.home, ".Trash", "id_rsa"), "utf8")).toBe("KEY");
    expect(calls).toHaveLength(0);
  });

  it("does not overwrite an item already in the Trash", async () => {
    fx = makeFixture();
    fx.write(".Trash/x.env", "OLD");
    const file = fx.write("a/x.env", "NEW");
    await macTrash(fx.env, mockExec().exec).trash(file);
    expect(fs.readFileSync(path.join(fx.home, ".Trash", "x.env"), "utf8")).toBe("OLD");
    expect(fs.readFileSync(path.join(fx.home, ".Trash", "x 2.env"), "utf8")).toBe("NEW");
  });

  it("falls back to Finder (path as an argument) across volumes, and reports a refusal", async () => {
    fx = makeFixture();
    const file = fx.write("a/y.env", "Z");
    const realRename = fs.promises.rename;
    vi.spyOn(fs.promises, "rename").mockImplementation((async () => {
      throw Object.assign(new Error("cross-device"), { code: "EXDEV" });
    }) as typeof fs.promises.rename);
    const ok = mockExec();
    expect((await macTrash(fx.env, ok.exec).trash(file)).ok).toBe(true);
    expect(ok.calls[0]!.cmd).toBe("osascript");
    expect(ok.calls[0]!.args.at(-1)).toBe(file); // the path is its own argv element
    expect(ok.calls[0]!.args.join(" ")).not.toMatch(/delete POSIX file ".*y\.env"/);
    const bad = mockExec({ osascript: { code: 1, stderr: "not allowed" } });
    expect(await macTrash(fx.env, bad.exec).trash(file)).toMatchObject({
      ok: false,
      message: "not allowed",
    });
    vi.restoreAllMocks();
    void realRename;
  });

  it("reports a non-EXDEV failure instead of falling through to deletion", async () => {
    fx = makeFixture();
    const { exec, calls } = mockExec();
    const r = await macTrash(fx.env, exec).trash(path.join(fx.home, "missing.env"));
    expect(r.ok).toBe(false);
    expect(calls).toHaveLength(0);
  });
});

describe("windowsTrash — Recycle Bin via PowerShell", () => {
  it("sends to the Recycle Bin and hands the path over in the ENVIRONMENT, not the command", async () => {
    const { exec, calls } = mockExec();
    const evil = "C:\\Users\\me\\a'; Remove-Item -Recurse C:\\ ; '.env";
    const r = await windowsTrash(exec).trash(evil);
    expect(r.ok).toBe(true);
    const c = calls[0]!;
    expect(c.cmd).toBe("powershell.exe");
    const script = c.args.at(-1)!;
    expect(script).toContain("SendToRecycleBin");
    expect(script).toContain("Microsoft.VisualBasic.FileIO.FileSystem");
    expect(script).not.toContain("Remove-Item");
    expect(script).not.toContain(evil);
    expect(c.opts!.env!.SWEEP_TRASH_PATH).toBe(evil);
    expect(c.args).toContain("-NoProfile");
    expect(c.args).toContain("-NonInteractive");
  });
  it("surfaces PowerShell's error", async () => {
    const { exec } = mockExec({ "powershell.exe": { code: 1, stderr: "access denied" } });
    expect(await windowsTrash(exec).trash("C:\\x")).toMatchObject({
      ok: false,
      message: "access denied",
    });
  });
});

describe("linuxTrash — gio then trash-put, never rm", () => {
  it("uses gio trash with -- before the path", async () => {
    const { exec, calls } = mockExec();
    expect((await linuxTrash(exec).trash("/home/me/-rf")).ok).toBe(true);
    expect(calls).toEqual([{ cmd: "gio", args: ["trash", "--", "/home/me/-rf"], opts: undefined }]);
  });
  it("falls back to trash-put, then explains instead of deleting", async () => {
    const fb = mockExec({ gio: { code: 1 } });
    expect((await linuxTrash(fb.exec).trash("/x")).ok).toBe(true);
    expect(fb.calls.map((c) => c.cmd)).toEqual(["gio", "trash-put"]);
    const none = mockExec({ gio: { code: 127 }, "trash-put": { code: 127 } });
    const r = await linuxTrash(none.exec).trash("/x");
    expect(r.ok).toBe(false);
    expect(r.message).toMatch(/nothing was deleted/);
    expect(none.calls.map((c) => c.cmd)).not.toContain("rm");
  });
});

describe("trashFor / keychainFor pick the right adapter per OS", () => {
  const { exec } = mockExec();
  it("selects by platform", () => {
    expect(trashFor({ platform: "darwin", home: "/h" }, exec).destination).toBe("the Trash");
    expect(trashFor({ platform: "win32", home: "C:\\h" }, exec).destination).toBe(
      "the Recycle Bin",
    );
    expect(trashFor({ platform: "linux", home: "/h" }, exec).destination).toBe("the Trash");
    expect(keychainFor({ platform: "darwin" }, exec).name).toBe("macOS Keychain");
    expect(keychainFor({ platform: "win32" }, exec).name).toBe("Windows Credential Manager");
    expect(keychainFor({ platform: "linux" }, exec).name).toMatch(/secret-tool/);
  });
});

describe("keychain adapters", () => {
  const secret = "gh" + "p_" + scramble(36);

  it("macOS: security add-generic-password under repo-wrapped/<label>", async () => {
    const { exec, calls } = mockExec();
    expect((await macKeychain(exec, "alice").store("github-1234abcd", secret)).ok).toBe(true);
    expect(calls[0]).toMatchObject({ cmd: "security" });
    expect(calls[0]!.args).toEqual([
      "add-generic-password",
      "-U",
      "-a",
      "alice",
      "-s",
      "repo-wrapped/github-1234abcd",
      "-w",
      secret,
    ]);
  });

  it("Windows: cmdkey /generic:repo-wrapped/<label>", async () => {
    const { exec, calls } = mockExec();
    await windowsKeychain(exec, "alice").store("github-1234abcd", secret);
    expect(calls[0]!.cmd).toBe("cmdkey");
    expect(calls[0]!.args[0]).toBe("/generic:repo-wrapped/github-1234abcd");
    expect(calls[0]!.args).toContain("/user:alice");
    expect(calls[0]!.args).toContain(`/pass:${secret}`);
  });

  it("Linux: secret-tool reads the secret from STDIN — never from argv", async () => {
    const { exec, calls } = mockExec();
    await linuxKeychain(exec).store("github-1234abcd", secret);
    expect(calls[0]!.cmd).toBe("secret-tool");
    expect(calls[0]!.args.join(" ")).not.toContain(secret);
    expect(calls[0]!.opts!.input).toBe(secret);
    expect(calls[0]!.args).toContain("service");
    expect(calls[0]!.args).toContain("repo-wrapped/github-1234abcd");
  });

  it("reports a keychain failure with the tool's message", async () => {
    const { exec } = mockExec({ security: { code: 1, stderr: "denied" } });
    expect(await macKeychain(exec, "a").store("x", secret)).toEqual({
      ok: false,
      message: "denied",
    });
    const none = mockExec({ "secret-tool": { code: 127, stderr: "" } });
    expect((await linuxKeychain(none.exec).store("x", secret)).message).toMatch(/libsecret/);
  });

  it("names items repo-wrapped/<label> and the 1Password hint holds no secret", () => {
    expect(keychainService("a-1")).toBe("repo-wrapped/a-1");
    const hint = onePasswordHint("stripe-secret-key-1234abcd");
    expect(hint).toContain("op item create");
    expect(hint).toContain("repo-wrapped/stripe-secret-key-1234abcd");
    expect(hint).toContain("<paste the secret here>");
  });
});

describe("ttyPrompter", () => {
  it("answers NO when there is no TTY, so a destructive step never proceeds on a guess", async () => {
    const p = ttyPrompter({ isTTY: false } as unknown as NodeJS.ReadableStream & {
      isTTY?: boolean;
    });
    expect(await p.confirm("Delete everything?")).toBe(false);
  });
});
