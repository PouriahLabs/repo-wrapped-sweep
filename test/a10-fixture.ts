// The A10 acceptance tree: a home directory that mimics the noise a real full sweep
// of a Windows dev machine produced (installed software, package caches, browser
// profiles, vendored fixtures, scoop manifests, source files with `apiKey = "…"`),
// plus the real cases that must still be reported. Secrets are assembled at runtime
// from fragments (helpers.ts) so no committed literal looks like a credential.

import fs from "node:fs";
import path from "node:path";
import { githubToken, pemKey, scramble } from "./helpers";

/** `file:///c%3A/Users/me/x y/.env` — how VS Code records a history entry's resource. */
export function fileUri(abs: string): string {
  const fwd = abs.replace(/\\/g, "/");
  const drive = /^([A-Za-z]):\/(.*)$/.exec(fwd);
  if (drive) return `file:///${drive[1]!.toLowerCase()}%3A/${encodeURI(drive[2]!)}`;
  return `file://${encodeURI(fwd)}`;
}

export const stripeLiveKey = (seed = 0) => "sk" + "_live_" + scramble(28, 5 + seed * 2);

export interface A10Tree {
  /** Files that exist only to be excluded — every one carries a secret the OLD sweep reported. */
  noise: string[];
  /** Real cases, by name. */
  real: { historyProd: string; envBackup: string; claudeHistory: string; prodPem: string };
}

/** Where this OS's VS Code keeps local history (relative to home). */
export const historyBase = (platform: NodeJS.Platform) =>
  platform === "win32"
    ? "AppData/Roaming/Code/User/History"
    : platform === "darwin"
      ? "Library/Application Support/Code/User/History"
      : ".config/Code/User/History";

export function buildA10Tree(home: string, platform: NodeJS.Platform = "win32"): A10Tree {
  const noise: string[] = [];
  const put = (rel: string, content: string, isNoise = true) => {
    const abs = path.join(home, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
    if (isNoise) noise.push(rel);
    return abs;
  };
  let seed = 100;
  const token = () => githubToken(seed++);
  const env = () => `NODE_ENV=production\nGITHUB_TOKEN=${token()}\n`;

  // --- installed software (Windows) -----------------------------------------------
  if (platform === "win32") {
    put("AppData/Local/Programs/Foo/resources/app/.env", env());
    put(
      "AppData/Local/Microsoft/Edge/User Data/Default/Local Storage/leveldb/000003.log",
      `t ${token()}`,
    );
    put("AppData/Local/Microsoft/WindowsApps/note.txt", `t ${token()}`);
    put(
      "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Preferences.txt",
      `t ${token()}`,
    );
    put("AppData/Local/Google/Cloud SDK/google-cloud-sdk/lib/third_party/x.env", env());
    put("AppData/Roaming/gcloud/logs/2026.01.01/12.00.00.000000.log", `auth ${token()}`);
    put("AppData/Local/Epic Games/Launcher/Saved/x.env", env());
    put("AppData/Local/GitHubDesktop/app-3.4.2/resources/app/x.env", env());
    put(".vscode/extensions/ms-python.python-2024.1/python_files/x.env", env());
    put(".vscode/extensions/acme.ext-1.0.0/keys/server.pem", pemKey(1));
    put(".cursor/extensions/foo.bar-2.0.0/.env", env());
    put("scoop/apps/git/current/etc/x.env", env());
    put("scoop/buckets/main/bucket/pyenv.json", scoopManifest("pyenv"));
    put("scoop/buckets/main/bucket/direnv.json", scoopManifest("direnv"));
    put("AppData/Local/Programs/Python/Python312/Lib/site-packages/foo/x.env", env());
  }
  // --- package caches (every OS) ---------------------------------------------------
  put("go/pkg/mod/github.com/x/y@v1.0.0/x.env", env());
  put(".cargo/registry/src/index.crates.io/foo-1.0.0/.env", env());
  put(".rustup/toolchains/stable/lib/x.env", env());
  put(".m2/repository/org/x/x.env", env());
  put(".gradle/caches/modules-2/x.env", env());
  put(".nuget/packages/foo/1.0.0/x.env", env());
  put(".npm/_cacache/content-v2/x.env", env());
  put("Documents/proj/.venv/Lib/site-packages/bar/x.env", env());
  put("Documents/proj/lib/python3.12/site-packages/baz/x.env", env());
  // --- darwin ------------------------------------------------------------------------
  if (platform === "darwin") {
    put("Library/Application Support/Slack/Cache/x.env", env());
    put("Library/Application Support/Code/Cache/x.env", env());
    put("Library/Application Support/Code/User/globalStorage/x.env", env());
  }
  // --- precision: not a secret ---------------------------------------------------------
  // A scoop-style manifest living OUTSIDE the excluded buckets: the old `*env*.json` rule
  // + a 64-hex "hash" value made it a finding.
  put("tools/scoop-copy/pyenv.json", scoopManifest("pyenv"));
  put("tools/scoop-copy/direnv.json", scoopManifest("direnv"));
  // A source file with a variable called apiKey; a data blob with one enormous line.
  put("Documents/proj/src/config.ts", `export const apiKey = "${scramble(32, 7)}";\n`);
  put(
    "Documents/proj/data/blob.json",
    `{"payload":"${"x".repeat(1500)}","api_key":"${scramble(32, 9)}"}\n`,
  );
  // A copy of .env.example in VS Code local history: a template, not a leak.
  const exampleSrc = path.join(home, "Documents/proj/.env.example");
  const hb = historyBase(platform);
  put(`${hb}/-77aa11bb/k3j9.example`, env());
  put(`${hb}/-77aa11bb/entries.json`, historyIndex(exampleSrc), false);

  // --- the real cases ---------------------------------------------------------------------
  const prodSrc = path.join(home, "Documents/proj/.env.prod");
  const historyProd = `${hb}/-6a9ea81e/9ya8.prod`;
  put(historyProd, `STRIPE_PUBLIC=pk\nGITHUB_TOKEN=${githubToken(7)}\n`, false);
  put(`${hb}/-6a9ea81e/entries.json`, historyIndex(prodSrc), false);
  const envBackup = "Documents/old-site/.env.bak";
  put(envBackup, `STRIPE_SECRET_KEY=${stripeLiveKey(1)}\n`, false);
  const claudeHistory = ".claude/history.jsonl";
  put(
    claudeHistory,
    `${JSON.stringify({ display: `use this token ${githubToken(9)} for the deploy`, project: "x" })}\n`,
    false,
  );
  const prodPem = "Documents/keys/prod-server.pem";
  put(prodPem, pemKey(5), false);

  return { noise, real: { historyProd, envBackup, claudeHistory, prodPem } };
}

function historyIndex(resourceAbs: string): string {
  return JSON.stringify({
    version: 1,
    resource: fileUri(resourceAbs),
    entries: [{ id: "x", source: "Workspace Edit", timestamp: 1 }],
  });
}

/** A scoop bucket manifest: nothing secret, but a random-looking "hash" value. */
function scoopManifest(name: string): string {
  const hash = Array.from(
    { length: 64 },
    (_, i) => "0123456789abcdef"[(i * 7 + name.length * 3) % 16],
  ).join("");
  return JSON.stringify(
    {
      version: "3.1.1",
      description: `${name} — manage versions`,
      homepage: `https://example.org/${name}`,
      url: `https://example.org/${name}/releases/download/v3.1.1/${name}.zip`,
      hash,
      bin: `${name}.exe`,
    },
    null,
    2,
  );
}
