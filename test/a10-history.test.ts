import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createHistoryResolver,
  isHistorySnapshot,
  parseEntriesResource,
  resourceToPath,
} from "../src/vscode-history";
import { scan } from "../src/scan";
import { buildA10Tree, historyBase } from "./a10-fixture";
import { adjustSeverity } from "@/lib/native-scan/path-rules";
import { SECRET_RULES } from "@/lib/native-scan/secret-rules";
import { makeFixture, type Fixture } from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

describe("parseEntriesResource", () => {
  it("reads the resource of an entries.json", () => {
    expect(
      parseEntriesResource(
        JSON.stringify({ version: 1, resource: "file:///c%3A/Users/me/p/.env", entries: [] }),
      ),
    ).toBe("file:///c%3A/Users/me/p/.env");
  });
  it("is null for anything else", () => {
    for (const bad of ["", "not json", "[]", "{}", '{"resource": 3}', '{"resource": ""}', "null"]) {
      expect(parseEntriesResource(bad), bad).toBeNull();
    }
  });
});

describe("resourceToPath", () => {
  it("Windows: a drive-letter URI becomes a drive path", () => {
    expect(resourceToPath("file:///c%3A/Users/me/proj/.env.prod", "win32")).toBe(
      "c:/Users/me/proj/.env.prod",
    );
    expect(resourceToPath("file:///C%3A/Users/me/My%20Proj/.env", "win32")).toBe(
      "C:/Users/me/My Proj/.env",
    );
  });
  it("Windows: a UNC share", () => {
    expect(resourceToPath("file://server/share/dir/x.env", "win32")).toBe(
      "//server/share/dir/x.env",
    );
  });
  it("macOS and Linux: a POSIX path", () => {
    expect(resourceToPath("file:///Users/me/proj/.env.prod", "darwin")).toBe(
      "/Users/me/proj/.env.prod",
    );
    expect(resourceToPath("file:///home/me/my%20proj/.env", "linux")).toBe("/home/me/my proj/.env");
  });
  it("a remote resource has no local path, and is never mistaken for one", () => {
    expect(resourceToPath("vscode-remote://ssh-remote%2Bdevbox/home/me/app/.env", "win32")).toBe(
      "vscode-remote:ssh-remote+devbox/home/me/app/.env",
    );
  });
  it("rejects what is not a URI, and bad escapes", () => {
    expect(resourceToPath("/just/a/path", "linux")).toBeNull();
    expect(resourceToPath("file:///c%3A/%E0%A4%A", "win32")).toBeNull();
  });
});

describe("isHistorySnapshot", () => {
  it("is a file directly inside History/<id>/", () => {
    expect(
      isHistorySnapshot(
        "C:\\Users\\me\\AppData\\Roaming\\Code\\User\\History\\-6a9ea81e\\9ya8.prod",
      ),
    ).toBe(true);
    expect(isHistorySnapshot("/h/.config/Code/User/history/-abc/x.json")).toBe(true);
    expect(isHistorySnapshot("/h/proj/src/x.json")).toBe(false);
    expect(isHistorySnapshot("/h/.config/Code/User/History/x.json")).toBe(false);
    expect(isHistorySnapshot("x.json")).toBe(false);
  });
});

describe("createHistoryResolver", () => {
  const env = { platform: "win32" as const, home: "C:\\Users\\me" };
  const index = JSON.stringify({ version: 1, resource: "file:///c%3A/Users/me/proj/.env.prod" });

  it("resolves a snapshot to the home-relative original path, reading each index once", async () => {
    const readText = vi.fn(async () => index);
    const resolve = createHistoryResolver(env, readText);
    const dir = "C:\\Users\\me\\AppData\\Roaming\\Code\\User\\History\\-6a9ea81e";
    expect(await resolve(`${dir}\\9ya8.prod`)).toBe("~/proj/.env.prod");
    expect(await resolve(`${dir}\\Ab12.prod`)).toBe("~/proj/.env.prod");
    expect(await resolve(`${dir}\\Cd34.prod`)).toBe("~/proj/.env.prod");
    expect(readText).toHaveBeenCalledTimes(1);
    expect(readText).toHaveBeenCalledWith(path.join(dir, "entries.json"));
  });
  it("a different directory is a different file", async () => {
    const readText = vi.fn(async () => index);
    const resolve = createHistoryResolver(env, readText);
    await resolve("C:\\h\\Code\\User\\History\\-a\\1.txt");
    await resolve("C:\\h\\Code\\User\\History\\-b\\1.txt");
    expect(readText).toHaveBeenCalledTimes(2);
  });
  it("falls back to null (the opaque path) when there is no usable index", async () => {
    for (const text of [null, "garbage", '{"version":1}']) {
      const resolve = createHistoryResolver(env, async () => text);
      expect(await resolve("C:\\h\\Code\\User\\History\\-a\\1.txt")).toBeNull();
    }
  });
  it("does not read anything for a file that is not a snapshot", async () => {
    const readText = vi.fn(async () => index);
    const resolve = createHistoryResolver(env, readText);
    expect(await resolve("C:\\Users\\me\\proj\\x.env")).toBeNull();
    expect(readText).not.toHaveBeenCalled();
  });
  it("shows a path outside the home directory as itself", async () => {
    const resolve = createHistoryResolver(env, async () =>
      JSON.stringify({ resource: "file:///d%3A/work/app/.env" }),
    );
    expect(await resolve("C:\\h\\Code\\User\\History\\-a\\1.txt")).toBe("d:/work/app/.env");
  });
});

describe("the acceptance tree on macOS and Linux", () => {
  const ghp = adjustSeverity(
    SECRET_RULES.find((r) => r.id === "github-personal-access-token")!.severity,
    "editor-history",
  );

  for (const platform of ["darwin", "linux"] as const) {
    it(`${platform}: the noise is excluded and the real cases are reported`, async () => {
      fx = makeFixture({ platform });
      const tree = buildA10Tree(fx.home, platform);
      const r = await scan({
        env: fx.env,
        roots: [],
        quick: false,
        excludeGlobs: [],
        includeCloud: false,
        concurrency: 4,
        salt: new Uint8Array(32).fill(2),
        placeholders: null,
      });
      expect(r.groups).toHaveLength(4);
      const hist = r.groups.find((g) => g.locations.some((l) => l.path.endsWith("9ya8.prod")))!;
      expect(hist.severity).toBe(ghp);
      expect(hist.locations[0]!.path).toContain(historyBase(platform).replace(/ /g, " "));
      // A drive-letter fixture path cannot be a POSIX resource, so this half of the
      // check only means something on a host of the simulated family.
      if (process.platform !== "win32") {
        expect(hist.locations[0]!.origin).toBe("~/Documents/proj/.env.prod");
      }
      void tree;
    });
  }
});
