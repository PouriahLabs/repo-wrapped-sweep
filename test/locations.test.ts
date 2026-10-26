import { describe, expect, it } from "vitest";
import type { SweepEnv } from "../src/env";
import { displayPath, expandPath, isUnder, normPath } from "../src/env";
import {
  classifyLocation,
  compileGlob,
  highRiskTargets,
  isCloudRoot,
  isDefaultExcludedDir,
  isInCloud,
  isNoiseFile,
} from "../src/locations";

const linux: SweepEnv = {
  platform: "linux",
  home: "/home/me",
  cloudRoots: [],
  configDir: "/home/me/.repo-wrapped",
};
const mac: SweepEnv = {
  platform: "darwin",
  home: "/Users/me",
  cloudRoots: [],
  configDir: "/Users/me/.repo-wrapped",
};
const win: SweepEnv = {
  platform: "win32",
  home: "C:\\Users\\me",
  appData: "C:\\Users\\me\\AppData\\Roaming",
  cloudRoots: ["C:\\Users\\me\\OneDrive"],
  configDir: "C:\\Users\\me\\.repo-wrapped",
};

describe("classifyLocation", () => {
  it("classifies each § A2.1 class on posix", () => {
    const c = (p: string, env = linux) => classifyLocation(p, env);
    expect(c("/home/me/.ssh/id_ed25519")).toBe("ssh");
    expect(c("/home/me/.config/Code/User/History/abc/x.env")).toBe("editor-history");
    expect(c("/home/me/.config/Cursor/User/History/abc/x.ts")).toBe("editor-history");
    expect(c("/home/me/.claude/projects/p/s.jsonl")).toBe("agent-transcript");
    expect(c("/home/me/.codex/sessions/2026/s.json")).toBe("agent-transcript");
    expect(c("/home/me/.zsh_history")).toBe("shell-history");
    expect(c("/home/me/.local/share/fish/fish_history")).toBe("shell-history");
    expect(c("/home/me/.aws/credentials")).toBe("credential-store");
    expect(c("/home/me/.npmrc")).toBe("credential-store");
    expect(c("/home/me/.docker/config.json")).toBe("credential-store");
    expect(c("/home/me/Downloads/x.txt")).toBe("downloads-desktop");
    expect(c("/home/me/Desktop/x.txt")).toBe("downloads-desktop");
    expect(c("/home/me/Documents/x.txt")).toBe("documents");
    expect(c("/etc/passwd")).toBe("documents");
  });

  it("treats a project's own .npmrc as a copy, not the credential store", () => {
    expect(classifyLocation("/home/me/proj/.npmrc", linux)).toBe("documents");
  });

  it("handles macOS and Windows layouts, case-insensitively", () => {
    expect(
      classifyLocation("/Users/me/Library/Application Support/Code/User/History/a/b.json", mac),
    ).toBe("editor-history");
    expect(
      classifyLocation("C:\\Users\\me\\AppData\\Roaming\\Code\\User\\History\\a\\b.env", win),
    ).toBe("editor-history");
    expect(classifyLocation("c:\\users\\ME\\.SSH\\id_rsa", win)).toBe("ssh");
    expect(classifyLocation("C:\\Users\\me\\.claude\\projects\\p\\s.jsonl", win)).toBe(
      "agent-transcript",
    );
    expect(
      classifyLocation(
        "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        win,
      ),
    ).toBe("shell-history");
    expect(classifyLocation("C:\\Users\\me\\.aws\\credentials", win)).toBe("credential-store");
  });
});

describe("highRiskTargets", () => {
  it("lists the per-OS editor history and the shared dotfile stores", () => {
    expect(highRiskTargets(linux)).toContain("/home/me/.config/Code/User/History");
    expect(highRiskTargets(linux)).toContain("/home/me/.config/Cursor/User/History");
    expect(highRiskTargets(mac)).toContain(
      "/Users/me/Library/Application Support/Code/User/History",
    );
    const w = highRiskTargets(win);
    expect(w).toContain("C:\\Users\\me\\AppData\\Roaming/Code/User/History");
    expect(w.some((p) => p.endsWith("ConsoleHost_history.txt"))).toBe(true);
    for (const env of [linux, mac, win]) {
      const t = highRiskTargets(env).join("\n");
      for (const needle of [
        ".claude/projects",
        ".codex/sessions",
        ".zsh_history",
        ".aws/credentials",
        ".ssh",
        "Downloads",
        "Desktop",
      ]) {
        expect(t).toContain(needle);
      }
    }
  });
});

describe("cloud roots", () => {
  it("recognises env roots, ~/OneDrive*, iCloud and CloudStorage children", () => {
    expect(isCloudRoot("C:\\Users\\me\\OneDrive", "OneDrive", win)).toBe(true);
    expect(isCloudRoot("C:\\Users\\me\\OneDrive - Contoso", "OneDrive - Contoso", win)).toBe(true);
    expect(isCloudRoot("C:\\Users\\me\\Documents", "Documents", win)).toBe(false);
    expect(isCloudRoot("/Users/me/Library/Mobile Documents", "Mobile Documents", mac)).toBe(true);
    expect(isCloudRoot("/Users/me/Library/CloudStorage/GoogleDrive-x", "GoogleDrive-x", mac)).toBe(
      true,
    );
    expect(isCloudRoot("/Users/me/Library/CloudStorage/GoogleDrive-x/sub", "sub", mac)).toBe(false);
  });
  it("isInCloud covers anything beneath a cloud root", () => {
    expect(isInCloud("C:\\Users\\me\\OneDrive\\Documents\\p", win)).toBe(true);
    expect(isInCloud("C:\\Users\\me\\Documents\\p", win)).toBe(false);
    expect(isInCloud("/Users/me/Library/CloudStorage/Dropbox/x", mac)).toBe(true);
  });
});

describe("excludes", () => {
  it("excludes build/tooling dirs, app bundles, caches and browser profiles", () => {
    for (const n of [
      "node_modules",
      ".git",
      ".next",
      "dist",
      "build",
      ".turbo",
      ".venv",
      "venv",
      "__pycache__",
      ".cache",
      ".pnpm-store",
      "Foo.app",
    ]) {
      expect(isDefaultExcludedDir(n, `/home/me/x/${n}`)).toBe(true);
    }
    expect(isDefaultExcludedDir("Caches", "/Users/me/Library/Caches")).toBe(true);
    expect(isDefaultExcludedDir("Temp", "c:/users/me/appdata/local/temp")).toBe(true);
    expect(
      isDefaultExcludedDir("User Data", "c:/users/me/appdata/local/google/chrome/user data"),
    ).toBe(true);
    expect(
      isDefaultExcludedDir("Profiles", "c:/users/me/appdata/roaming/mozilla/firefox/profiles"),
    ).toBe(true);
    expect(isDefaultExcludedDir("src", "/home/me/proj/src")).toBe(false);
    expect(isDefaultExcludedDir(".ssh", "/home/me/.ssh")).toBe(false);
    expect(isDefaultExcludedDir("projects", "/home/me/.claude/projects")).toBe(false);
  });

  it("compiles user globs", () => {
    expect(compileGlob("*.log").test("/a/b/x.log")).toBe(true);
    expect(compileGlob("*.log").test("/a/b/x.txt")).toBe(false);
    expect(compileGlob("secrets").test("/a/secrets")).toBe(true);
    expect(compileGlob("**/vendor/**").test("/a/vendor/x/y")).toBe(true);
    expect(compileGlob("vendor/**").test("/a/vendor/x/y")).toBe(true);
    expect(compileGlob("old?.txt").test("/a/old1.txt")).toBe(true);
    expect(compileGlob("Old*.TXT").test("/a/oldfile.txt")).toBe(true);
  });

  it("filters lockfiles and generated bundles", () => {
    for (const n of [
      "package-lock.json",
      "pnpm-lock.yaml",
      "yarn.lock",
      "app.min.js",
      "a.js.map",
    ]) {
      expect(isNoiseFile(n)).toBe(true);
    }
    expect(isNoiseFile("package.json")).toBe(false);
  });
});

describe("path helpers", () => {
  it("normPath folds case only on case-insensitive platforms", () => {
    expect(normPath("C:\\Users\\Me\\", "win32")).toBe("c:/users/me");
    expect(normPath("/Home/Me", "linux")).toBe("/Home/Me");
    expect(isUnder("c:\\users\\me\\x", "C:\\Users\\Me", "win32")).toBe(true);
    expect(isUnder("/home/mee", "/home/me", "linux")).toBe(false);
  });
  it("displayPath hides the home directory and expandPath inverts it", () => {
    expect(displayPath("/home/me/docs/x", linux)).toBe("~/docs/x");
    expect(displayPath("C:\\Users\\me\\docs\\x.env", win)).toBe("~/docs/x.env");
    expect(displayPath("/etc/hosts", linux)).toBe("/etc/hosts");
    expect(expandPath("~/docs/x", { home: "/home/me" }).replace(/\\/g, "/")).toBe(
      "/home/me/docs/x",
    );
    expect(expandPath("/abs/p", { home: "/home/me" })).toBe("/abs/p");
  });
});
