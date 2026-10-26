import { EventEmitter } from "node:events";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  FILE_ATTRIBUTE_OFFLINE,
  FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
  FILE_ATTRIBUTE_RECALL_ON_OPEN,
  LISTER_SCRIPT,
  createPowerShellProvider,
  encodeDirRequest,
  isPlaceholderAttr,
  parseAttributeLine,
  parseAttributeListing,
  type HelperProcess,
  type PlaceholderProvider,
} from "../src/placeholders";
import { scan, type ScanOptions } from "../src/scan";
import { redirectedKnownFolders } from "../src/walk";
import { githubToken, makeFixture, type Fixture } from "./helpers";

const SALT = new Uint8Array(32).fill(9);
let fx: Fixture;
afterEach(() => {
  vi.restoreAllMocks();
  fx?.cleanup();
});

const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");

// ---------------------------------------------------------------------------
// Attribute decoding
// ---------------------------------------------------------------------------

describe("isPlaceholderAttr", () => {
  const NORMAL = 0x20; // ARCHIVE
  const DIRECTORY = 0x10;
  const HIDDEN = 0x2;
  it("flags OFFLINE, RECALL_ON_OPEN and RECALL_ON_DATA_ACCESS — and nothing else", () => {
    expect(isPlaceholderAttr(FILE_ATTRIBUTE_OFFLINE)).toBe(true);
    expect(isPlaceholderAttr(FILE_ATTRIBUTE_RECALL_ON_OPEN)).toBe(true);
    expect(isPlaceholderAttr(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)).toBe(true);
    expect(isPlaceholderAttr(NORMAL | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)).toBe(true);
    expect(isPlaceholderAttr(DIRECTORY | FILE_ATTRIBUTE_RECALL_ON_OPEN | HIDDEN)).toBe(true);
    for (const a of [
      0,
      NORMAL,
      DIRECTORY,
      HIDDEN,
      NORMAL | HIDDEN,
      0x400 /* reparse point */,
      0x80000 /* pinned */,
    ]) {
      expect(isPlaceholderAttr(a), String(a)).toBe(false);
    }
  });
  it("uses the documented Win32 values", () => {
    expect(FILE_ATTRIBUTE_OFFLINE).toBe(0x1000);
    expect(FILE_ATTRIBUTE_RECALL_ON_OPEN).toBe(0x40000);
    expect(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS).toBe(0x400000);
  });
});

describe("the helper's wire format", () => {
  it("parses `attributes:base64(name)` lines, including unicode and spaces", () => {
    expect(parseAttributeLine(`32:${b64("report.docx")}`)).toEqual(["report.docx", 32]);
    expect(parseAttributeLine(`4194336:${b64("Résumé – final.docx")}`)).toEqual([
      "Résumé – final.docx",
      4194336,
    ]);
  });
  it("rejects anything else", () => {
    for (const bad of [
      "",
      "32",
      "x:abc",
      "32:",
      ":abc",
      "-1:abc",
      "32:not base64!",
      "99999999999999999999:aGk=",
    ]) {
      expect(parseAttributeLine(bad), bad).toBeNull();
    }
  });
  it("a listing is all-or-nothing: one malformed line makes the whole directory unknown", () => {
    expect(parseAttributeListing([`32:${b64("a")}`, `4194304:${b64("b")}`])).toEqual(
      new Map([
        ["a", 32],
        ["b", 4194304],
      ]),
    );
    expect(parseAttributeListing([`32:${b64("a")}`, "garbage"])).toBeNull();
    expect(parseAttributeListing([])).toEqual(new Map());
    expect(parseAttributeListing(["", "  "])).toEqual(new Map());
  });
  it("encodes a request as one base64 line", () => {
    expect(encodeDirRequest("C:\\Users\\me\\OneDrive\\Documents")).toBe(
      `${b64("C:\\Users\\me\\OneDrive\\Documents")}\n`,
    );
  });
  it("the PowerShell loop lists metadata only, and answers in the same format", () => {
    expect(LISTER_SCRIPT).toContain("Get-ChildItem -LiteralPath");
    expect(LISTER_SCRIPT).toContain("-Force");
    expect(LISTER_SCRIPT).toContain("[int]$e.Attributes");
    expect(LISTER_SCRIPT).toContain("ToBase64String");
    expect(LISTER_SCRIPT).toContain("<<END>>");
    expect(LISTER_SCRIPT).toContain("<<ERR>>");
    // never reads a file's contents
    for (const verb of ["Get-Content", "ReadAll", "OpenRead", "Select-String", "Invoke-Item"]) {
      expect(LISTER_SCRIPT).not.toContain(verb);
    }
  });
});

// ---------------------------------------------------------------------------
// The PowerShell provider, against a fake child process
// ---------------------------------------------------------------------------

class FakeChild extends EventEmitter {
  stdout = new EventEmitter();
  stdin = { write: vi.fn(), end: vi.fn() };
  kill = vi.fn();
  unref = vi.fn();
  /** Reply to each request line with `reply(directory)` (chunked at `chunk` characters). */
  respondWith(reply: (dir: string) => string | null, chunk = 1000) {
    this.stdin.write.mockImplementation((line: string) => {
      const dir = Buffer.from(line.trim(), "base64").toString("utf8");
      const out = reply(dir);
      if (out === null) return;
      setTimeout(() => {
        for (let i = 0; i < out.length; i += chunk)
          this.stdout.emit("data", out.slice(i, i + chunk));
      }, 0);
    });
  }
}

function provider(over: { timeoutMs?: number; make?: () => FakeChild } = {}) {
  const children: FakeChild[] = [];
  const spawn = vi.fn((_exe: string, _args: string[]) => {
    const c = over.make ? over.make() : new FakeChild();
    children.push(c);
    return c as unknown as HelperProcess;
  });
  const p = createPowerShellProvider({
    spawn,
    exe: "powershell.exe",
    timeoutMs: over.timeoutMs ?? 2000,
  });
  return { p, spawn, children };
}

const listing = (entries: Record<string, number>) =>
  Object.entries(entries)
    .map(([n, a]) => `${a}:${b64(n)}`)
    .concat("<<END>>")
    .join("\n") + "\n";

describe("createPowerShellProvider", () => {
  it("starts nothing until a directory is asked about", async () => {
    const { p, spawn } = provider();
    await p.close();
    expect(spawn).not.toHaveBeenCalled();
  });

  it("starts one PowerShell with an encoded command, and returns each directory's attributes", async () => {
    const listings: Record<string, Record<string, number>> = {
      "C:\\od\\Docs": { "a.txt": 32, "online.pdf": 0x400020, sub: 0x10 },
      "C:\\od\\Docs\\sub": { "b.txt": 32 },
    };
    const { p, spawn } = provider({
      make: () => {
        const c = new FakeChild();
        c.respondWith((d) => listing(listings[d]!));
        return c;
      },
    });
    expect(await p.attributes("C:\\od\\Docs")).toEqual(
      new Map(Object.entries(listings["C:\\od\\Docs"]!)),
    );
    expect(await p.attributes("C:\\od\\Docs\\sub")).toEqual(new Map([["b.txt", 32]]));

    expect(spawn).toHaveBeenCalledTimes(1);
    const [exe, args] = spawn.mock.calls[0]!;
    expect(exe).toBe("powershell.exe");
    expect(args).toEqual([
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      expect.any(String),
    ]);
    expect(Buffer.from(args[4]!, "base64").toString("utf16le")).toBe(LISTER_SCRIPT);
  });

  it("reassembles a reply that arrives in small chunks, split mid-line", async () => {
    const { p } = provider({
      make: () => {
        const c = new FakeChild();
        c.respondWith(() => listing({ "Résumé.docx": 0x400000, "x.txt": 32 }), 7);
        return c;
      },
    });
    expect(await p.attributes("C:\\od")).toEqual(
      new Map([
        ["Résumé.docx", 0x400000],
        ["x.txt", 32],
      ]),
    );
    await p.close();
  });

  it("answers null when PowerShell reports an error for the directory — and keeps working", async () => {
    let n = 0;
    const { p } = provider({
      make: () => {
        const c = new FakeChild();
        c.respondWith(() => (n++ === 0 ? "<<ERR>>\n" : listing({ "a.txt": 32 })));
        return c;
      },
    });
    expect(await p.attributes("C:\\od\\denied")).toBeNull();
    expect(await p.attributes("C:\\od\\fine")).toEqual(new Map([["a.txt", 32]]));
    await p.close();
  });

  it("answers null for a half-understood listing rather than guessing", async () => {
    const { p } = provider({
      make: () => {
        const c = new FakeChild();
        c.respondWith(() => `32:${b64("ok.txt")}\nthis is not a listing line\n<<END>>\n`);
        return c;
      },
    });
    expect(await p.attributes("C:\\od")).toBeNull();
    await p.close();
  });

  it("gives up on a hung helper, kills it, and starts a fresh one for the next directory", async () => {
    let created = 0;
    const { p, spawn, children } = provider({
      timeoutMs: 40,
      make: () => {
        const c = new FakeChild();
        if (created++ > 0) c.respondWith(() => listing({ "a.txt": 32 }));
        return c; // the first child never answers
      },
    });
    expect(await p.attributes("C:\\od\\hang")).toBeNull();
    expect(children[0]!.kill).toHaveBeenCalled();
    expect(await p.attributes("C:\\od\\ok")).toEqual(new Map([["a.txt", 32]]));
    expect(spawn).toHaveBeenCalledTimes(2);
    await p.close();
  });

  it("treats every directory as unreadable when PowerShell cannot be started", async () => {
    const spawn = vi.fn(() => {
      throw new Error("spawn powershell.exe ENOENT");
    });
    const p = createPowerShellProvider({ spawn });
    expect(await p.attributes("C:\\od")).toBeNull();
    expect(await p.attributes("C:\\od\\b")).toBeNull();
    expect(spawn).toHaveBeenCalledTimes(1); // not retried: it will not appear mid-sweep
  });

  it("and when the process errors after spawning (ENOENT arrives as an event)", async () => {
    const { p, children } = provider({
      make: () => {
        const c = new FakeChild();
        setTimeout(() => c.emit("error", new Error("ENOENT")), 0);
        return c;
      },
    });
    expect(await p.attributes("C:\\od")).toBeNull();
    expect(children).toHaveLength(1);
    expect(await p.attributes("C:\\od\\b")).toBeNull();
    expect(children).toHaveLength(1);
  });

  it("answers null if the process exits mid-request", async () => {
    const { p, children } = provider({
      make: () => {
        const c = new FakeChild();
        c.stdin.write.mockImplementation(() => setTimeout(() => c.emit("exit"), 0));
        return c;
      },
    });
    expect(await p.attributes("C:\\od")).toBeNull();
    expect(children).toHaveLength(1);
  });

  it("asks one directory at a time, in order, even when called concurrently", async () => {
    const order: string[] = [];
    const { p } = provider({
      make: () => {
        const c = new FakeChild();
        c.respondWith((d) => {
          order.push(`req:${d}`);
          return listing({ [d]: 32 });
        });
        return c;
      },
    });
    const all = await Promise.all(["C:\\a", "C:\\b", "C:\\c"].map((d) => p.attributes(d)));
    expect(order).toEqual(["req:C:\\a", "req:C:\\b", "req:C:\\c"]);
    expect(all.map((m) => [...m!.keys()][0])).toEqual(["C:\\a", "C:\\b", "C:\\c"]);
    await p.close();
  });

  it("close() ends the helper's input so it exits", async () => {
    const { p, children } = provider({
      make: () => {
        const c = new FakeChild();
        c.respondWith(() => listing({}));
        return c;
      },
    });
    await p.attributes("C:\\od");
    await p.close();
    expect(children[0]!.stdin.end).toHaveBeenCalled();
    await p.close(); // twice is fine
  });
});

describe.runIf(process.platform === "win32")("the real PowerShell lister (Windows)", () => {
  it("reports the attributes of a real directory's entries without reading them", async () => {
    fx = makeFixture();
    fx.write("dir/plain.txt", "hello");
    fx.write("dir/Résumé final.txt", "x");
    fs.mkdirSync(path.join(fx.home, "dir", "sub"));
    const p = createPowerShellProvider({ timeoutMs: 20_000 });
    try {
      const attrs = await p.attributes(path.join(fx.home, "dir"));
      expect(attrs).not.toBeNull();
      expect([...attrs!.keys()].sort()).toEqual(["Résumé final.txt", "plain.txt", "sub"]);
      expect(attrs!.get("sub")! & 0x10).toBe(0x10); // DIRECTORY
      expect(attrs!.get("plain.txt")! & 0x20).toBe(0x20); // ARCHIVE
      for (const a of attrs!.values()) expect(isPlaceholderAttr(a)).toBe(false);
      // a second directory on the SAME process, and a directory that does not exist
      expect((await p.attributes(path.join(fx.home, "dir", "sub")))!.size).toBe(0);
      expect(await p.attributes(path.join(fx.home, "no-such-dir"))).toBeNull();
    } finally {
      await p.close();
    }
  }, 60_000);
});

// ---------------------------------------------------------------------------
// The sweep, with a mocked provider
// ---------------------------------------------------------------------------

/** A provider whose "online-only" set is given by absolute path. Records every directory asked about. */
function mockProvider(onlineOnly: Iterable<string> = [], unreadable: Iterable<string> = []) {
  const recall = new Set([...onlineOnly].map((p) => path.normalize(p)));
  const bad = new Set([...unreadable].map((p) => path.normalize(p)));
  const asked: string[] = [];
  const impl: PlaceholderProvider = {
    async attributes(dir) {
      asked.push(path.normalize(dir));
      if (bad.has(path.normalize(dir))) return null;
      const out = new Map<string, number>();
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const abs = path.normalize(path.join(dir, e.name));
        out.set(
          e.name,
          (e.isDirectory() ? 0x10 : 0x20) |
            (recall.has(abs) ? FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS : 0),
        );
      }
      return out;
    },
    async close() {},
  };
  return { impl, asked };
}

function cloudFixture() {
  fx = makeFixture({ platform: "win32" });
  fx.env.cloudRoots = [path.join(fx.home, "OneDrive")];
  const tok = (n: number) => `T=${githubToken(700 + n)}\n`;
  return {
    hydrated: fx.write("OneDrive/Documents/proj/.env", tok(1)),
    onlineFile: fx.write("OneDrive/Documents/proj/archive.env", tok(2)),
    onlineDirFile: fx.write("OneDrive/Documents/Cloud Only/.env", tok(3)),
    brokenDirFile: fx.write("OneDrive/Documents/broken/.env", tok(4)),
    desktop: fx.write("OneDrive/Desktop/notes.env", tok(5)),
    other: fx.write("OneDrive/Other/x.env", tok(6)),
    local: fx.write("code/.env", tok(7)),
  };
}

const sweepOpts = (over: Partial<ScanOptions>): ScanOptions => ({
  env: fx.env,
  roots: [],
  quick: false,
  excludeGlobs: [],
  includeCloud: false,
  concurrency: 4,
  salt: SALT,
  ...over,
});

describe("Windows Known Folder Move", () => {
  it("finds the Known Folders that were redirected into cloud sync", async () => {
    const f = cloudFixture();
    const found = await redirectedKnownFolders(fx.env);
    expect(found.map((x) => x.name).sort()).toEqual(["Desktop", "Documents"]);
    expect(found.map((x) => path.normalize(x.path)).sort()).toEqual(
      [path.dirname(f.desktop), path.dirname(path.dirname(f.hydrated))]
        .map((p) => path.normalize(fs.realpathSync(p)))
        .sort(),
    );
    // a Documents folder that is NOT in the cloud is the walk's job already
    fx.cleanup();
    fx = makeFixture({ platform: "win32" });
    fx.write("Documents/x.txt", "x");
    expect(await redirectedKnownFolders(fx.env)).toEqual([]);
  });

  it("scans the redirected Documents/Desktop but not the rest of OneDrive", async () => {
    const f = cloudFixture();
    const { impl } = mockProvider();
    const r = await scan(sweepOpts({ placeholders: impl }));
    const paths = r.groups.flatMap((g) => g.locations.map((l) => l.path));
    expect(paths).toContain("~/OneDrive/Documents/proj/.env");
    expect(paths).toContain("~/OneDrive/Desktop/notes.env");
    expect(paths).toContain("~/code/.env"); // the ordinary home walk is unchanged
    expect(paths).not.toContain("~/OneDrive/Other/x.env"); // not a Known Folder: still skipped
    expect(r.stats.skippedCloud).toBeGreaterThan(0);
    expect(r.notes.join("\n")).toContain("online-only files were skipped without being downloaded");
    void f;
  });

  it("never opens an online-only file or enters an online-only folder", async () => {
    const f = cloudFixture();
    const { impl } = mockProvider([f.onlineFile, path.dirname(f.onlineDirFile)]);
    const read = vi.spyOn(fs.promises, "readFile");
    const stat = vi.spyOn(fs.promises, "stat");
    const open = vi.spyOn(fs.promises, "open");
    const opendir = vi.spyOn(fs.promises, "opendir");
    const stream = vi.spyOn(fs, "createReadStream");

    const r = await scan(sweepOpts({ placeholders: impl }));
    const paths = r.groups.flatMap((g) => g.locations.map((l) => l.path));
    expect(paths).toContain("~/OneDrive/Documents/proj/.env");
    expect(paths).not.toContain("~/OneDrive/Documents/proj/archive.env");
    expect(paths).not.toContain("~/OneDrive/Documents/Cloud Only/.env");
    expect(r.stats.skippedPlaceholders).toBe(2);

    const touched = (calls: unknown[][]) => calls.map((c) => String(c[0]));
    const forbidden = [f.onlineFile, path.dirname(f.onlineDirFile), f.onlineDirFile];
    for (const spy of [read, stat, open, opendir, stream]) {
      for (const t of touched(spy.mock.calls as unknown[][])) {
        for (const bad of forbidden)
          expect(t.startsWith(bad), `${spy.getMockName()} ${t}`).toBe(false);
      }
    }
  });

  it("skips a folder whose attributes cannot be read, and says so", async () => {
    const f = cloudFixture();
    const { impl } = mockProvider([], [path.dirname(f.brokenDirFile)]);
    const r = await scan(sweepOpts({ placeholders: impl }));
    const paths = r.groups.flatMap((g) => g.locations.map((l) => l.path));
    expect(paths).not.toContain("~/OneDrive/Documents/broken/.env");
    expect(paths).toContain("~/OneDrive/Documents/proj/.env"); // the rest of Documents is fine
    expect(r.stats.skippedUnknownAttrs).toBe(1);
    expect(r.notes.join("\n")).toContain("could not be read");
  });

  it("only asks about directories inside a cloud-sync root", async () => {
    const f = cloudFixture();
    const { impl, asked } = mockProvider();
    await scan(sweepOpts({ placeholders: impl }));
    expect(asked.length).toBeGreaterThan(0);
    const od = path.normalize(path.join(fx.home, "OneDrive"));
    for (const dir of asked) expect(dir.startsWith(od), dir).toBe(true);
    expect(asked.some((d) => d === path.normalize(path.join(fx.home, "code")))).toBe(false);
    void f;
  });

  it("with --include-cloud the whole of OneDrive is swept, still skipping placeholders", async () => {
    const f = cloudFixture();
    const { impl } = mockProvider([f.onlineFile]);
    const r = await scan(sweepOpts({ placeholders: impl, includeCloud: true }));
    const paths = r.groups.flatMap((g) => g.locations.map((l) => l.path));
    expect(paths).toContain("~/OneDrive/Other/x.env");
    expect(paths).toContain("~/OneDrive/Documents/proj/.env");
    expect(paths).not.toContain("~/OneDrive/Documents/proj/archive.env");
    // no folder is reached twice
    expect(paths.filter((p) => p === "~/OneDrive/Documents/proj/.env")).toHaveLength(1);
    expect(r.stats.skippedPlaceholders).toBe(1);
  });

  it("without a provider (macOS, Linux, or tests) the cloud skip is exactly as before", async () => {
    cloudFixture();
    const r = await scan(sweepOpts({ placeholders: null }));
    const paths = r.groups.flatMap((g) => g.locations.map((l) => l.path));
    expect(paths).toEqual(["~/code/.env"]);
    expect(r.stats.skippedPlaceholders).toBe(0);
    expect(r.notes.join("\n")).toContain("were skipped");
  });

  it("an explicit --root is never rewritten into the Known Folders", async () => {
    const f = cloudFixture();
    const { impl } = mockProvider();
    const r = await scan(sweepOpts({ placeholders: impl, roots: [path.join(fx.home, "code")] }));
    expect(r.groups.flatMap((g) => g.locations.map((l) => l.path))).toEqual(["~/code/.env"]);
    void f;
  });
});
