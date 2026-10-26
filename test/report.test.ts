import { describe, expect, it } from "vitest";
import type { EndpointGroup } from "@/lib/native-scan/fingerprint";
import type { BaselineDiff } from "../src/baseline";
import {
  buildJsonReport,
  escapeHtml,
  exitCodeFor,
  parseFailOn,
  REPORT_MAX_LOCATIONS,
  renderHtml,
  renderTable,
  severityCounts,
  topLocationClass,
  truncatePath,
} from "../src/report";
import type { ScanResult } from "../src/scan";

function group(over: Partial<EndpointGroup> = {}): EndpointGroup {
  return {
    fingerprint: "a".repeat(32),
    ruleId: "github-personal-access-token",
    severity: "high",
    preview: "gh••••…ab",
    copies: 2,
    locations: [
      { path: "~/docs/.env", locationClass: "documents", line: 3 },
      { path: "~/.claude/projects/p/s.jsonl", locationClass: "agent-transcript", line: 9 },
    ],
    locationClasses: { documents: 1, "agent-transcript": 1 },
    ...over,
  };
}

function result(groups: EndpointGroup[]): ScanResult {
  return {
    scope: "full",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:05.000Z",
    groups,
    stats: {
      files: 1234,
      skippedDirs: 0,
      skippedCloud: 0,
      skippedLarge: 0,
      skippedBinary: 0,
      skippedFiles: 0,
      skippedPlaceholders: 0,
      skippedUnknownAttrs: 0,
      errors: 0,
      deniedByTop: {},
    },
    notes: [],
  };
}

const noDiff: BaselineDiff = { baselineExisted: false, newFingerprints: new Set(), gone: [] };
const ctx = (diff = noDiff) => ({ version: "9.9.9", os: "linux", diff });

describe("exit codes / --fail-on", () => {
  it("parses levels and rejects junk", () => {
    expect(parseFailOn(undefined)).toBe("high");
    expect(parseFailOn("CRITICAL")).toBe("critical");
    expect(parseFailOn("new")).toBe("new");
    expect(parseFailOn("none")).toBe("none");
    expect(parseFailOn("nope")).toBeNull();
  });
  it("fails at or above the threshold only", () => {
    const high = [group()];
    expect(exitCodeFor(high, "high", noDiff)).toBe(1);
    expect(exitCodeFor(high, "critical", noDiff)).toBe(0);
    expect(exitCodeFor(high, "low", noDiff)).toBe(1);
    expect(exitCodeFor([group({ severity: "medium" })], "high", noDiff)).toBe(0);
    expect(exitCodeFor(high, "none", noDiff)).toBe(0);
    expect(exitCodeFor([], "low", noDiff)).toBe(0);
  });
  it("--fail-on new fires only on fingerprints missing from the baseline", () => {
    const g = group();
    const seen: BaselineDiff = { baselineExisted: true, newFingerprints: new Set(), gone: [] };
    const fresh: BaselineDiff = {
      baselineExisted: true,
      newFingerprints: new Set([g.fingerprint]),
      gone: [],
    };
    expect(exitCodeFor([g], "new", seen)).toBe(0);
    expect(exitCodeFor([g], "new", fresh)).toBe(1);
  });
});

describe("helpers", () => {
  it("truncates paths keeping the tail", () => {
    expect(truncatePath("~/short", 20)).toBe("~/short");
    const t = truncatePath("~/a/very/long/path/to/some/file.env", 14);
    expect(t).toHaveLength(14);
    expect(t.startsWith("…")).toBe(true);
    expect(t.endsWith("file.env")).toBe(true);
  });
  it("finds the dominant location class and counts severities", () => {
    expect(
      topLocationClass(group({ locationClasses: { "editor-history": 5, documents: 1 } })),
    ).toBe("editor-history");
    expect(severityCounts([group(), group({ severity: "critical" })])).toEqual({
      critical: 1,
      high: 1,
      medium: 0,
      low: 0,
    });
  });
  it("escapes html", () => {
    expect(escapeHtml(`<a href="x">&'`)).toBe("&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
  });
});

describe("terminal table", () => {
  it("renders findings worst-first with a summary and NEW markers", () => {
    const g = group({ fingerprint: "b".repeat(32) });
    const diff: BaselineDiff = {
      baselineExisted: true,
      newFingerprints: new Set([g.fingerprint]),
      gone: [{ fingerprint: "c".repeat(32), ruleId: "jwt" }],
    };
    const out = renderTable(result([g]), ctx(diff), { color: false, width: 120 });
    expect(out).toContain("SEV");
    expect(out).toContain("github-personal-access-token");
    expect(out).toContain("gh••••…ab");
    expect(out).toContain("NEW");
    expect(out).toContain("1 finding (1 high)");
    expect(out).toContain("1,234 files scanned");
    expect(out).toContain("1 finding gone since the last run");
    expect(out).not.toContain("\x1b[");
  });
  it("does not mark NEW when there was no baseline to compare with", () => {
    const g = group();
    const out = renderTable(
      result([g]),
      ctx({ baselineExisted: false, newFingerprints: new Set([g.fingerprint]), gone: [] }),
      { color: false, width: 120 },
    );
    expect(out).not.toContain("NEW");
  });
  it("says so when clean, and reports permission skips", () => {
    const r = result([]);
    r.stats.skippedDirs = 2;
    r.stats.deniedByTop = { "/a": 1, "/b": 1 };
    r.notes = ["a note"];
    const out = renderTable(r, ctx(), { color: false, width: 120 });
    expect(out).toContain("No plaintext secrets found");
    expect(out).toContain("skipped 2 unreadable paths in 2 folders");
    expect(out).toContain("a note");
  });
  it("colorises only when asked", () => {
    expect(renderTable(result([group()]), ctx(), { color: true, width: 120 })).toContain("\x1b[");
  });
});

describe("json report", () => {
  it("has a stable schemaVersion 1 shape", () => {
    const g = group();
    const j = buildJsonReport(
      result([g]),
      ctx({ baselineExisted: true, newFingerprints: new Set([g.fingerprint]), gone: [] }),
    );
    expect(j.schemaVersion).toBe(1);
    expect(j.tool).toBe("repo-wrapped-sweep");
    expect(j.version).toBe("9.9.9");
    expect(j.summary).toEqual({ critical: 0, high: 1, medium: 0, low: 0, total: 1 });
    expect(j.findings[0]).toMatchObject({
      fingerprint: g.fingerprint,
      ruleId: "github-personal-access-token",
      severity: "high",
      preview: "gh••••…ab",
      copies: 2,
      isNew: true,
      locationsTruncated: false,
    });
    expect(j.findings[0]!.rotationUrl).toMatch(/^https:\/\/github\.com\//);
    expect(Object.keys(j).sort()).toEqual(
      [
        "finishedAt",
        "findings",
        "gone",
        "notes",
        "os",
        "schemaVersion",
        "scope",
        "startedAt",
        "stats",
        "summary",
        "tool",
        "version",
      ].sort(),
    );
  });
  it("caps listed locations but keeps the true copy count", () => {
    const many = Array.from({ length: 140 }, (_, i) => ({
      path: `~/h/${i}`,
      locationClass: "editor-history" as const,
    }));
    const j = buildJsonReport(result([group({ copies: 140, locations: many })]), ctx());
    expect(j.findings[0]!.locations).toHaveLength(REPORT_MAX_LOCATIONS);
    expect(j.findings[0]!.locationsTruncated).toBe(true);
    expect(j.findings[0]!.copies).toBe(140);
  });
});

describe("html report", () => {
  it("is self-contained, escapes content and carries no external resources", () => {
    const evil = group({
      locations: [{ path: "~/<script>alert(1)</script>", locationClass: "documents" }],
    });
    const html = renderHtml(result([evil]), ctx());
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toMatch(/<(?:link|script)[^>]+(?:src|href)=["']https?:/);
    expect(html).toContain("--sev-critical");
    expect(html).toContain("prefers-color-scheme");
  });
  it("renders the clean state", () => {
    expect(renderHtml(result([]), ctx())).toContain("No plaintext secrets found");
  });
});
