// Pure parsers behind the CLI 0.3 posture / AI-tooling collectors (cli/sweep/src/insights/
// machine-extras.ts does the I/O). Everything here reads text the CLI already has in memory
// and returns a CLASSIFICATION — never a value, a key, a path or a name — so nothing it
// returns can carry a secret off the machine.

import type { AgentAutonomy, CredentialHelperKind, SshKeySummary, SshKeyType } from "./wire";

// ---------------------------------------------------------------------------
// git credential helper
// ---------------------------------------------------------------------------

const KEYCHAIN_HELPERS = new Set([
  "osxkeychain",
  "manager",
  "manager-core",
  "wincred",
  "libsecret",
  "gnome-keyring",
  "1password",
  "op",
]);

/**
 * `git config --global --get-all credential.helper` lines → how credentials are stored. The
 * LAST helper git consults first wins for storage, but a single `store` anywhere still writes
 * a plaintext `~/.git-credentials`, so plaintext beats everything. PURE.
 */
export function classifyCredentialHelper(values: readonly string[]): CredentialHelperKind {
  const helpers = values.map((v) => v.trim()).filter((v) => v.length > 0);
  if (helpers.length === 0) return "none";
  const names = helpers.map((h) => {
    const first = h.split(/\s+/)[0]!.replace(/^!/, "");
    const base = first
      .split(/[\\/]/)
      .pop()!
      .replace(/\.exe$/i, "");
    return base.replace(/^git-credential-/, "").toLowerCase();
  });
  if (names.includes("store")) return "plaintext";
  if (names.some((n) => KEYCHAIN_HELPERS.has(n))) return "keychain";
  if (names.includes("cache")) return "memory";
  return "other";
}

// ---------------------------------------------------------------------------
// SSH keys — type, size and passphrase from the key file's PUBLIC parts only
// ---------------------------------------------------------------------------

/** Read one SSH wire `string` (uint32 length + bytes) at `off`. */
function readString(buf: Uint8Array, off: number): { bytes: Uint8Array; next: number } | null {
  if (off + 4 > buf.length) return null;
  const len =
    ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0;
  const start = off + 4;
  if (start + len > buf.length) return null;
  return { bytes: buf.subarray(start, start + len), next: start + len };
}

const ascii = (b: Uint8Array) => String.fromCharCode(...b);

function decodeBase64(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64.replace(/\s+/g, ""));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** Bits in an SSH `mpint` (big-endian, possibly a leading 0x00). */
function mpintBits(b: Uint8Array): number {
  let i = 0;
  while (i < b.length && b[i] === 0) i++;
  if (i === b.length) return 0;
  return (b.length - i - 1) * 8 + (32 - Math.clz32(b[i]!));
}

function keyTypeOf(name: string): SshKeyType {
  if (name === "ssh-ed25519" || name.startsWith("sk-ssh-ed25519")) return "ed25519";
  if (name.startsWith("ecdsa-") || name.startsWith("sk-ecdsa-")) return "ecdsa";
  if (name === "ssh-rsa") return "rsa";
  if (name === "ssh-dss") return "dsa";
  return "other";
}

export interface SshKeyInfo {
  type: SshKeyType;
  /** RSA modulus size; null for other types or when unknown. */
  bits: number | null;
  /** null = could not tell. */
  encrypted: boolean | null;
}

/** A public-key blob (SSH wire format) → type and RSA size. */
function parsePublicBlob(blob: Uint8Array): Pick<SshKeyInfo, "type" | "bits"> | null {
  const t = readString(blob, 0);
  if (!t) return null;
  const type = keyTypeOf(ascii(t.bytes));
  if (type !== "rsa") return { type, bits: null };
  const e = readString(blob, t.next);
  const n = e ? readString(blob, e.next) : null;
  return { type, bits: n ? mpintBits(n.bytes) : null };
}

/** `ssh-rsa AAAA… comment` (a .pub file) → type and size. The comment is ignored. PURE. */
export function parseSshPublicKey(line: string): Pick<SshKeyInfo, "type" | "bits"> | null {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 2) return null;
  const blob = decodeBase64(parts[1]!);
  return blob ? parsePublicBlob(blob) : null;
}

/**
 * A private key FILE's text → type, size and whether it has a passphrase, read only from its
 * unencrypted header (the OpenSSH container's cipher name and embedded public key, or a PEM
 * header). Never decodes key material. Not a private key → null. PURE.
 */
export function parseSshPrivateKey(text: string): SshKeyInfo | null {
  const openssh =
    /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(text);
  if (openssh) {
    const buf = decodeBase64(openssh[1]!);
    const magic = "openssh-key-v1\0";
    if (!buf || ascii(buf.subarray(0, magic.length)) !== magic) {
      return { type: "other", bits: null, encrypted: null };
    }
    const cipher = readString(buf, magic.length);
    const kdf = cipher ? readString(buf, cipher.next) : null;
    const kdfOpts = kdf ? readString(buf, kdf.next) : null;
    // uint32 key count, then the first public key blob.
    const pub = kdfOpts ? readString(buf, kdfOpts.next + 4) : null;
    const parsed = pub ? parsePublicBlob(pub.bytes) : null;
    return {
      type: parsed?.type ?? "other",
      bits: parsed?.bits ?? null,
      encrypted: cipher ? ascii(cipher.bytes) !== "none" : null,
    };
  }
  const pem = /-----BEGIN ((?:RSA|DSA|EC|ENCRYPTED) )?PRIVATE KEY-----/.exec(text);
  if (!pem) return null;
  const kind = (pem[1] ?? "").trim();
  const type: SshKeyType =
    kind === "RSA" ? "rsa" : kind === "DSA" ? "dsa" : kind === "EC" ? "ecdsa" : "other";
  const encrypted = kind === "ENCRYPTED" || /Proc-Type:\s*4,ENCRYPTED/.test(text);
  return { type, bits: null, encrypted };
}

/** Fold per-key facts into the upload summary. `ages` are days per key. PURE. */
export function summarizeSshKeys(
  keys: ReadonlyArray<SshKeyInfo & { ageDays: number }>,
): SshKeySummary {
  const byType: Partial<Record<SshKeyType, number>> = {};
  let weak = 0;
  let unencrypted = 0;
  let oldest: number | null = null;
  for (const k of keys) {
    byType[k.type] = (byType[k.type] ?? 0) + 1;
    if (k.type === "dsa" || (k.type === "rsa" && k.bits !== null && k.bits < 2048)) weak++;
    if (k.encrypted === false) unencrypted++;
    oldest = oldest === null ? k.ageDays : Math.max(oldest, k.ageDays);
  }
  return { count: keys.length, byType, weak, unencrypted, oldestDays: oldest };
}

// ---------------------------------------------------------------------------
// MCP server configs
// ---------------------------------------------------------------------------

/** A value that looks like a literal credential rather than a reference to one. */
export function looksLikeInlineSecret(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const v = value.trim();
  if (v.length < 16) return false;
  // References and placeholders: ${VAR}, $VAR, {{…}}, <…>, env:/op://-style indirections.
  if (/^\$\{?[A-Za-z_]|\{\{|^<.*>$|^(?:env|op|vault|secret):/i.test(v)) return false;
  if (/^(?:your[-_ ]|xxx|changeme|example)/i.test(v)) return false;
  // A URL is a credential only when it carries one (userinfo or a token-ish query param).
  if (/^https?:\/\//i.test(v))
    return /\/\/[^/@\s]+:[^/@\s]+@|[?&](?:key|token|secret|api[-_]?key)=[^&]{8,}/i.test(v);
  // Path-like or space-separated values are config, not secrets.
  if (/[\\/]|\s/.test(v)) return false;
  // High-variety tokens: letters AND digits, or a known prefix.
  return (/[A-Za-z]/.test(v) && /\d/.test(v)) || /^(?:sk|pk|ghp|gho|xox[abp]|AKIA)[-_]/.test(v);
}

type Json = unknown;
const isObj = (v: Json): v is Record<string, Json> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** Count servers in one `mcpServers`-style map and how many hold an inline secret. */
function countServerMap(map: Json): { servers: number; inlineSecrets: number } {
  if (!isObj(map)) return { servers: 0, inlineSecrets: 0 };
  let servers = 0;
  let inlineSecrets = 0;
  for (const def of Object.values(map)) {
    if (!isObj(def)) continue;
    servers++;
    const values: Json[] = [];
    for (const key of ["env", "headers"]) {
      if (isObj(def[key])) values.push(...Object.values(def[key] as Record<string, Json>));
    }
    if (Array.isArray(def.args)) values.push(...def.args);
    if (typeof def.url === "string") values.push(def.url);
    if (values.some(looksLikeInlineSecret)) inlineSecrets++;
  }
  return { servers, inlineSecrets };
}

/**
 * Every MCP server map a client config can hold: top-level `mcpServers` (Claude, Cursor),
 * `servers` (VS Code `mcp.json`), `mcp.servers` (VS Code settings) and Claude Code's
 * per-project `projects[path].mcpServers`. PURE.
 */
export function countMcpServers(config: Json): { servers: number; inlineSecrets: number } {
  if (!isObj(config)) return { servers: 0, inlineSecrets: 0 };
  const maps: Json[] = [config.mcpServers, config.servers];
  if (isObj(config.mcp)) maps.push((config.mcp as Record<string, Json>).servers);
  if (isObj(config.projects)) {
    for (const p of Object.values(config.projects)) if (isObj(p)) maps.push(p.mcpServers);
  }
  let servers = 0;
  let inlineSecrets = 0;
  for (const m of maps) {
    const c = countServerMap(m);
    servers += c.servers;
    inlineSecrets += c.inlineSecrets;
  }
  return { servers, inlineSecrets };
}

// ---------------------------------------------------------------------------
// Agent autonomy
// ---------------------------------------------------------------------------

const AUTONOMY_RANK: Record<AgentAutonomy, number> = {
  default: 0,
  "auto-edit": 1,
  "broad-shell": 2,
  "full-auto": 3,
};

export const maxAutonomy = (a: AgentAutonomy, b: AgentAutonomy): AgentAutonomy =>
  AUTONOMY_RANK[a] >= AUTONOMY_RANK[b] ? a : b;

/** A Claude Code `settings.json` → how much it runs without asking. PURE. */
export function claudeCodeAutonomy(settings: Json): AgentAutonomy {
  if (!isObj(settings)) return "default";
  const perms = isObj(settings.permissions) ? settings.permissions : {};
  const mode = perms.defaultMode;
  if (mode === "bypassPermissions") return "full-auto";
  const allow = Array.isArray(perms.allow) ? perms.allow : [];
  if (allow.some((r) => r === "Bash" || r === "Bash(*)" || r === "Bash(*:*)")) return "broad-shell";
  if (mode === "acceptEdits") return "auto-edit";
  return "default";
}

/** A Codex `config.toml` → autonomy, from its `approval_policy` / `sandbox_mode` keys. PURE. */
export function codexAutonomy(toml: string): AgentAutonomy {
  const value = (key: string) =>
    new RegExp(`^\\s*${key}\\s*=\\s*["']([^"']+)["']`, "m").exec(toml)?.[1] ?? null;
  const approval = value("approval_policy");
  const sandbox = value("sandbox_mode");
  if (approval === "never" && sandbox === "danger-full-access") return "full-auto";
  if (approval === "never") return "broad-shell";
  if (approval === "on-failure" || sandbox === "workspace-write") return "auto-edit";
  return "default";
}

// ---------------------------------------------------------------------------
// AI extensions and CLIs
// ---------------------------------------------------------------------------

/** Well-known AI editor extension ids (lowercase `publisher.name`). Only these are reported. */
export const AI_EXTENSION_IDS = [
  "github.copilot",
  "github.copilot-chat",
  "anthropic.claude-code",
  "openai.chatgpt",
  "continue.continue",
  "saoudrizwan.claude-dev",
  "rooveterinaryinc.roo-cline",
  "codeium.codeium",
  "windsurf.windsurfpyright",
  "tabnine.tabnine-vscode",
  "sourcegraph.cody-ai",
  "supermaven.supermaven",
  "amazonwebservices.amazon-q-vscode",
  "google.geminicodeassist",
  "kilocode.kilo-code",
] as const;

/** An extensions-folder entry (`publisher.name-1.2.3`) → its known AI id, else null. PURE. */
export function aiExtensionId(folder: string): string | null {
  const m = /^([a-z0-9-]+\.[a-z0-9-]+?)-\d+\.\d+/i.exec(folder);
  const id = (m?.[1] ?? folder).toLowerCase();
  return (AI_EXTENSION_IDS as readonly string[]).includes(id) ? id : null;
}

/** AI coding CLIs looked up on PATH (no spawn). */
export const AI_CLI_BINS = [
  "claude",
  "codex",
  "gemini",
  "aider",
  "cursor-agent",
  "copilot",
  "amp",
  "opencode",
  "goose",
] as const;
