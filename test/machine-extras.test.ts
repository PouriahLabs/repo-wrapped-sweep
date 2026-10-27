import { describe, expect, it } from "vitest";
import {
  bitlockerState,
  codexMcpCount,
  gitRegexEscape,
  linuxPrettyName,
  macLastUpdateMs,
  netshFirewall,
  windowsName,
} from "../src/insights/machine-extras";
import { projectExtremes } from "../src/insights/upload";

describe("device basics parsers", () => {
  it("names Windows 11 from the build, not the stale registry ProductName", () => {
    expect(windowsName("Windows 10 Pro", "24H2", "10.0.26100")).toBe("Windows 11 Pro 24H2");
    expect(windowsName("Windows 10 Pro", "22H2", "10.0.19045")).toBe("Windows 10 Pro 22H2");
    expect(windowsName("Windows Server 2022", null, "10.0.20348")).toBe("Windows Server 2022");
  });
  it("reads PRETTY_NAME quoted or not", () => {
    expect(linuxPrettyName('NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n')).toBe(
      "Ubuntu 24.04.1 LTS",
    );
    expect(linuxPrettyName("PRETTY_NAME=Arch Linux\n")).toBe("Arch Linux");
    expect(linuxPrettyName("NAME=x\n")).toBeNull();
  });
});

describe("posture parsers", () => {
  it("BitLocker shell property", () => {
    expect(bitlockerState("1\r\n")).toBe("on");
    expect(bitlockerState("2")).toBe("off");
    expect(bitlockerState("")).toBe("unknown");
    expect(bitlockerState(null)).toBe("unknown");
  });
  it("netsh: on only when every profile is on", () => {
    const all =
      "Domain Profile Settings:\nState                                 ON\n\nPrivate Profile Settings:\nState                                 ON\n";
    expect(netshFirewall(all)).toBe("on");
    expect(netshFirewall(all.replace(/ON\n$/, "OFF\n"))).toBe("off");
    expect(netshFirewall("Access is denied.")).toBe("unknown");
  });
  it("macOS install history: newest Software Update entry", () => {
    const json = JSON.stringify([
      { date: "2026-09-01T10:00:00Z", processName: "softwareupdated" },
      { date: "2026-10-01T10:00:00Z", processName: "App Store" },
      { date: "2026-09-20T10:00:00Z", processName: "macOS Installer" },
    ]);
    expect(macLastUpdateMs(json)).toBe(Date.parse("2026-09-20T10:00:00Z"));
    expect(macLastUpdateMs("not json")).toBeNull();
  });
});

describe("AI + activity helpers", () => {
  it("counts Codex MCP tables once each", () => {
    expect(
      codexMcpCount('[mcp_servers.a]\ncommand="x"\n[mcp_servers.b]\n[mcp_servers.a.env]\n'),
    ).toBe(2);
  });
  it("escapes an email for git's --author regex", () => {
    expect(gitRegexEscape("a.b+c@x.io")).toBe("a\\.b+c@x\\.io");
  });
  it("finds the biggest and longest-untouched project", () => {
    const p = (path: string, bytes: number | null, lastTouched: number | null) =>
      ({ path, bytes, lastTouched }) as never;
    expect(
      projectExtremes({
        projects: [p("/a", 10, 300), p("/b", 50, 200), p("/c", null, 100)],
        summary: {} as never,
      }),
    ).toEqual({ biggest: { path: "/b", bytes: 50 }, oldest: { path: "/c", lastTouched: 100 } });
    expect(projectExtremes(undefined)).toEqual({ biggest: null, oldest: null });
  });
});
