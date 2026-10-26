import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { EndpointGroup } from "@/lib/native-scan/fingerprint";
import {
  MAX_BASELINE_LOCATIONS,
  diffAgainstBaseline,
  loadBaseline,
  saveBaseline,
  updateBaseline,
  type Baseline,
} from "../src/baseline";
import { loadConfig, loadOrCreateSalt } from "../src/state";
import { makeFixture, type Fixture } from "./helpers";

let fx: Fixture;
afterEach(() => fx?.cleanup());

function g(fp: string, paths: string[], ruleId = "jwt"): EndpointGroup {
  return {
    fingerprint: fp,
    ruleId,
    severity: "high",
    preview: "ab••••…cd",
    copies: paths.length,
    locations: paths.map((p) => ({ path: p, locationClass: "documents" })),
    locationClasses: { documents: paths.length },
  };
}

const T1 = "2026-01-01T00:00:00.000Z";
const T2 = "2026-01-02T00:00:00.000Z";

describe("baseline diff + update", () => {
  it("everything is NEW against no baseline, and nothing is GONE", () => {
    const d = diffAgainstBaseline([g("f1", ["~/a"])], null, "full");
    expect(d.baselineExisted).toBe(false);
    expect([...d.newFingerprints]).toEqual(["f1"]);
    expect(d.gone).toEqual([]);
  });

  it("a full sweep replaces the baseline and reports what is gone", () => {
    const first = updateBaseline(
      [g("f1", ["~/a"]), g("f2", ["~/b"], "stripe-secret-key")],
      null,
      "full",
      T1,
    );
    const groups = [g("f1", ["~/a", "~/c"]), g("f3", ["~/d"])];
    const d = diffAgainstBaseline(groups, first, "full");
    expect([...d.newFingerprints]).toEqual(["f3"]);
    expect(d.gone).toEqual([{ fingerprint: "f2", ruleId: "stripe-secret-key" }]);
    const next = updateBaseline(groups, first, "full", T2);
    expect(Object.keys(next.findings).sort()).toEqual(["f1", "f3"]);
    expect(next.findings.f1).toMatchObject({ firstSeen: T1, lastSeen: T2, copies: 2 });
    expect(next.findings.f3!.firstSeen).toBe(T2);
  });

  it("a partial sweep never reports GONE and only merges what it saw", () => {
    const first = updateBaseline([g("f1", ["~/a"]), g("f2", ["~/b"])], null, "full", T1);
    const d = diffAgainstBaseline([g("f1", ["~/z"])], first, "quick");
    expect(d.gone).toEqual([]);
    const next = updateBaseline([g("f1", ["~/z"])], first, "quick", T2);
    expect(Object.keys(next.findings).sort()).toEqual(["f1", "f2"]);
    expect(next.findings.f1!.locations.sort()).toEqual(["~/a", "~/z"]);
  });

  it("a resolved fingerprint that reappears is NEW again", () => {
    const resolved: Baseline = {
      schemaVersion: 1,
      updatedAt: T1,
      findings: {
        f1: {
          ruleId: "jwt",
          copies: 1,
          locations: ["~/a"],
          firstSeen: T1,
          lastSeen: T1,
          resolvedAt: T1,
        },
      },
    };
    const d = diffAgainstBaseline([g("f1", ["~/a"])], resolved, "full");
    expect(d.newFingerprints.has("f1")).toBe(true);
    const next = updateBaseline([g("f1", ["~/a"])], resolved, "full", T2);
    expect(next.findings.f1!.resolvedAt).toBeUndefined();
    expect(next.findings.f1!.firstSeen).toBe(T2);
  });

  it("does not report an already-resolved entry as GONE", () => {
    const resolved: Baseline = {
      schemaVersion: 1,
      updatedAt: T1,
      findings: {
        f9: {
          ruleId: "jwt",
          copies: 1,
          locations: [],
          firstSeen: T1,
          lastSeen: T1,
          resolvedAt: T1,
        },
      },
    };
    expect(diffAgainstBaseline([], resolved, "full").gone).toEqual([]);
  });

  it("bounds the stored paths", () => {
    const many = Array.from({ length: MAX_BASELINE_LOCATIONS + 50 }, (_, i) => `~/h/${i}`);
    const b = updateBaseline([g("f1", many)], null, "full", T1);
    expect(b.findings.f1!.locations).toHaveLength(MAX_BASELINE_LOCATIONS);
  });

  it("stores no preview and no secret — only ids, counts and paths", () => {
    const b = updateBaseline([g("f1", ["~/a"])], null, "full", T1);
    expect(JSON.stringify(b)).not.toContain("ab••••");
    expect(Object.keys(b.findings.f1!).sort()).toEqual([
      "copies",
      "firstSeen",
      "lastSeen",
      "locations",
      "ruleId",
      "severity",
    ]);
  });
});

describe("baseline file", () => {
  it("round-trips and tolerates a missing or corrupt file", () => {
    fx = makeFixture();
    const file = path.join(fx.env.configDir, "sweep-baseline.json");
    expect(loadBaseline(file)).toBeNull();
    const b = updateBaseline([g("f1", ["~/a"])], null, "full", T1);
    saveBaseline(file, b);
    expect(loadBaseline(file)).toEqual(b);
    fs.writeFileSync(file, "{not json");
    expect(loadBaseline(file)).toBeNull();
    fs.writeFileSync(file, JSON.stringify({ schemaVersion: 99, findings: {} }));
    expect(loadBaseline(file)).toBeNull();
  });
});

describe("salt + config", () => {
  it("creates a 32-byte salt once and reuses it", () => {
    fx = makeFixture();
    const a = loadOrCreateSalt(fx.env);
    const b = loadOrCreateSalt(fx.env);
    expect(a).toHaveLength(32);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
    const file = path.join(fx.env.configDir, "sweep-salt");
    expect(fs.readFileSync(file, "utf8")).toMatch(/^[0-9a-f]{64}$/);
    if (process.platform !== "win32") expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  it("regenerates a corrupt salt file", () => {
    fx = makeFixture();
    fs.mkdirSync(fx.env.configDir, { recursive: true });
    fs.writeFileSync(path.join(fx.env.configDir, "sweep-salt"), "garbage");
    const s = loadOrCreateSalt(fx.env);
    expect(s).toHaveLength(32);
    expect(fs.readFileSync(path.join(fx.env.configDir, "sweep-salt"), "utf8")).toMatch(
      /^[0-9a-f]{64}$/,
    );
  });

  it("loads sweep.json, ignoring junk and malformed files", () => {
    fx = makeFixture();
    fs.mkdirSync(fx.env.configDir, { recursive: true });
    const file = path.join(fx.env.configDir, "sweep.json");
    fs.writeFileSync(
      file,
      JSON.stringify({ exclude: ["*.log", 5], hookAllow: ["~/x"], roots: "no" }),
    );
    expect(loadConfig(fx.env)).toEqual({ exclude: ["*.log"], hookAllow: ["~/x"], roots: [] });
    fs.writeFileSync(file, "{bad");
    const warnings: string[] = [];
    expect(loadConfig(fx.env, (m) => warnings.push(m))).toEqual({
      exclude: [],
      hookAllow: [],
      roots: [],
    });
    expect(warnings).toHaveLength(1);
    fs.rmSync(file);
    expect(loadConfig(fx.env)).toEqual({ exclude: [], hookAllow: [], roots: [] });
  });
});
