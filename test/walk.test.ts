import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { walk } from "../src/walk";
import { makeFixture, type Fixture } from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

async function files(over: Partial<Parameters<typeof walk>[0]> = {}) {
  const seen: string[] = [];
  const stats = await walk({
    roots: [fx.home],
    env: fx.env,
    excludeGlobs: [],
    includeCloud: false,
    concurrency: 4,
    onFile: async (f) => {
      seen.push(path.relative(fx.home, f.path).split(path.sep).join("/"));
    },
    ...over,
  });
  return { seen: seen.sort(), stats };
}

describe("walk", () => {
  it("visits files, skipping default-excluded directories", async () => {
    fx = makeFixture();
    fx.write("a.txt", "x");
    fx.write("src/b.ts", "x");
    fx.write("node_modules/p/c.js", "x");
    fx.write(".git/config", "x");
    fx.write("app/dist/d.js", "x");
    fx.write("Foo.app/Contents/e", "x");
    const { seen } = await files();
    expect(seen).toEqual(["a.txt", "src/b.ts"]);
  });

  it("applies --exclude globs to files and directories", async () => {
    fx = makeFixture();
    fx.write("keep.txt", "x");
    fx.write("drop.log", "x");
    fx.write("secrets/s.txt", "x");
    const { seen } = await files({ excludeGlobs: ["*.log", "secrets"] });
    expect(seen).toEqual(["keep.txt"]);
  });

  it("accepts a file as a root and ignores a missing root", async () => {
    fx = makeFixture();
    const f = fx.write("only.txt", "x");
    const { seen } = await files({ roots: [f, path.join(fx.home, "nope")] });
    expect(seen).toEqual(["only.txt"]);
  });

  it("does not follow symlinks", async () => {
    fx = makeFixture();
    fx.write("real/r.txt", "x");
    try {
      fs.symlinkSync(path.join(fx.home, "real"), path.join(fx.home, "link"), "junction");
    } catch {
      return; // symlinks unavailable on this host
    }
    const { seen } = await files();
    expect(seen).toEqual(["real/r.txt"]);
  });

  it("keeps going when a file callback throws, and counts it", async () => {
    fx = makeFixture();
    fx.write("a.txt", "x");
    fx.write("b.txt", "x");
    let n = 0;
    const stats = await walk({
      roots: [fx.home],
      env: fx.env,
      excludeGlobs: [],
      includeCloud: false,
      concurrency: 1,
      onFile: async () => {
        n++;
        throw new Error("boom");
      },
    });
    expect(n).toBe(2);
    expect(stats.errors).toBe(2);
  });

  it("honours the concurrency bound", async () => {
    fx = makeFixture();
    for (let i = 0; i < 20; i++) fx.write(`f${i}.txt`, "x");
    let active = 0;
    let peak = 0;
    await walk({
      roots: [fx.home],
      env: fx.env,
      excludeGlobs: [],
      includeCloud: false,
      concurrency: 3,
      onFile: async () => {
        active++;
        peak = Math.max(peak, active);
        await new Promise((r) => setTimeout(r, 5));
        active--;
      },
    });
    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThan(1);
  });
});
