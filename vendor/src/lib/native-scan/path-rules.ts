// ---------------------------------------------------------------------------
// Endpoint Sweep path rules (ENDPOINT-SWEEP-AND-PACKAGE-MAP.md § A2.2) — PURE:
// no fs, no clock. The filename/location half of the endpoint detector; the
// content half is `secret-rules.ts`, reused unchanged.
//
// The CLI walker and the agent-guard hook share this module so a path that the
// sweep flags is the same path the hook refuses to let an agent read.
//
// Three jobs:
//   1. `matchPath`        — does this FILENAME look like a credential store?
//   2. `confirmPathRule`  — given the first ~4 KB of the file, does it really
//                           hold one (a `.pem` that is only a certificate does
//                           not), and how bad is it?
//   3. `adjustSeverity`   — severity reflects WHERE the hit sits: the expected
//                           stores are one step down, stray copies one step up.
//
// "info" in the spec (encrypted keys, temporary STS credentials) maps to the
// existing `low` severity — `Severity` has no `info` tier and widening it would
// ripple through every chart and board. `low` is floored, never dropped.
// ---------------------------------------------------------------------------

import type { Severity } from "@/lib/org-security";
import { SEVERITY_ORDER } from "@/lib/charts/palette";
import { SECRET_RULES, isAllowlisted, shannonEntropy } from "@/lib/native-scan/secret-rules";

// ---------------------------------------------------------------------------
// Location classes (§ A2.1)
// ---------------------------------------------------------------------------

export const LOCATION_CLASSES = [
  "editor-history",
  "agent-transcript",
  "shell-history",
  "credential-store",
  "ssh",
  "downloads-desktop",
  "documents",
] as const;

export type LocationClass = (typeof LOCATION_CLASSES)[number];

/** Classes whose hits are the *expected* home of a credential — one step down. */
const EXPECTED_CLASSES: ReadonlySet<LocationClass> = new Set(["credential-store", "ssh"]);
/** Classes whose hits are stray *copies* of a credential — one step up. */
const COPY_CLASSES: ReadonlySet<LocationClass> = new Set([
  "agent-transcript",
  "editor-history",
  "shell-history",
  "downloads-desktop",
]);

// ---------------------------------------------------------------------------
// Severity stepping
// ---------------------------------------------------------------------------

/** One step more severe (capped at critical). */
export function raiseSeverity(severity: Severity): Severity {
  const i = SEVERITY_ORDER.indexOf(severity);
  return SEVERITY_ORDER[Math.max(0, i - 1)] as Severity;
}

/** One step less severe (floored at low — a hit is never dropped by location). */
export function lowerSeverity(severity: Severity): Severity {
  const i = SEVERITY_ORDER.indexOf(severity);
  return SEVERITY_ORDER[Math.min(SEVERITY_ORDER.length - 1, i + 1)] as Severity;
}

/**
 * Severity by location (§ A2.2). A credential sitting in its expected store
 * (`credential-store`, `ssh`) is one step down; a copy that leaked into an
 * editor/agent/shell history or Downloads/Desktop is one step up; anywhere else
 * is unchanged. Pure; capped at critical, floored at low.
 */
export function adjustSeverity(severity: Severity, locationClass: LocationClass): Severity {
  if (EXPECTED_CLASSES.has(locationClass)) return lowerSeverity(severity);
  if (COPY_CLASSES.has(locationClass)) return raiseSeverity(severity);
  return severity;
}

// ---------------------------------------------------------------------------
// Rule table
// ---------------------------------------------------------------------------

export type PathRuleId =
  | "path.private-key"
  | "path.pkcs12"
  | "path.env-file"
  | "path.env-backup"
  | "path.cookie-jar"
  | "path.service-account"
  | "path.aws-long-lived"
  | "path.registry-token";

export interface PathRule {
  id: PathRuleId;
  /** Provisional severity before content confirmation / location adjustment. */
  severity: Severity;
  description: string;
  /**
   * `finding` rules emit a finding of their own once confirmed. `modifier`
   * rules (`path.env-backup`) never fire alone — they raise a content hit found
   * in a backup-looking file by one severity step.
   */
  kind: "finding" | "modifier";
  /** True when `confirmPathRule` needs the file head (everything but pkcs12). */
  needsContent: boolean;
  /**
   * Content-rule ids (`SECRET_RULES`) this rule supersedes when both fire on the
   * same file, so a key file is one finding rather than a path hit plus a bare
   * header hit.
   */
  shadows: string[];
}

export const PATH_RULES: PathRule[] = [
  {
    id: "path.private-key",
    severity: "critical",
    description: "Private key file",
    kind: "finding",
    needsContent: true,
    shadows: ["private-key"],
  },
  {
    id: "path.pkcs12",
    severity: "high",
    description: "PKCS#12 key bundle (cannot be inspected without its passphrase)",
    kind: "finding",
    needsContent: false,
    shadows: [],
  },
  {
    id: "path.env-file",
    severity: "high",
    description: "Environment file holding secret values",
    kind: "finding",
    needsContent: true,
    shadows: [],
  },
  {
    id: "path.env-backup",
    severity: "high",
    description: "Backup copy of a file that holds a secret",
    kind: "modifier",
    needsContent: false,
    shadows: [],
  },
  {
    id: "path.cookie-jar",
    severity: "high",
    description: "Browser/HTTP cookie jar (session cookies)",
    kind: "finding",
    needsContent: true,
    shadows: [],
  },
  {
    id: "path.service-account",
    severity: "critical",
    description: "Service-account / client-secret JSON",
    kind: "finding",
    needsContent: true,
    shadows: [],
  },
  {
    id: "path.aws-long-lived",
    severity: "high",
    description: "AWS long-lived access key in the shared credentials file",
    kind: "finding",
    needsContent: true,
    shadows: ["aws-access-key-id", "aws-secret-access-key"],
  },
  {
    id: "path.registry-token",
    severity: "high",
    description: "Package-registry auth token",
    kind: "finding",
    needsContent: true,
    shadows: [],
  },
];

const RULE_BY_ID = new Map<PathRuleId, PathRule>(PATH_RULES.map((r) => [r.id, r]));

export function pathRule(id: PathRuleId): PathRule {
  return RULE_BY_ID.get(id) as PathRule;
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/** Forward-slash, lowercased: matching is case-insensitive on every OS (NTFS and
 *  default APFS are, and a stray `ID_RSA` should not slip through on Linux). */
function norm(relPath: string): string {
  return relPath.replace(/\\/g, "/").toLowerCase();
}

function baseName(normalized: string): string {
  const i = normalized.lastIndexOf("/");
  return i < 0 ? normalized : normalized.slice(i + 1);
}

/** `.env.example` and friends are documentation, never findings. */
const EXAMPLE_ENV = /(?:^|[._-])(?:example|sample|template|dist|defaults?)(?:[._-]|$)/;

/** True for env-file *templates* — always allowed, by the sweep and the hook. */
export function isExampleEnvFile(relPath: string): boolean {
  const base = baseName(norm(relPath));
  return /env/.test(base) && EXAMPLE_ENV.test(base);
}

/**
 * Is this path a backup copy? (`*.bak`, `*.old`, `*~`, `-bu-`, `_backup`,
 * `backup/`.) A content hit inside one is a forgotten duplicate, so it rises a
 * severity step.
 */
export function isBackupPath(relPath: string): boolean {
  const p = norm(relPath);
  return (
    p.endsWith(".bak") ||
    p.endsWith(".old") ||
    p.endsWith("~") ||
    p.includes("-bu-") ||
    p.includes("_backup") ||
    p.includes("backup/")
  );
}

/** The expected credential stores (§ A2.1 `credential-store`). The agent guard
 *  denies reads of these outright. */
const CREDENTIAL_STORE_SUFFIXES = [
  ".aws/credentials",
  ".npmrc",
  ".docker/config.json",
  ".kube/config",
  ".netrc",
  ".git-credentials",
];

export function isCredentialStorePath(relPath: string): boolean {
  const p = norm(relPath);
  return CREDENTIAL_STORE_SUFFIXES.some((s) => p === s || p.endsWith(`/${s}`));
}

// --- per-rule filename tests ------------------------------------------------

const SSH_KEY_NAME = /^id_(?:rsa|ecdsa|ed25519|dsa)(?:[._-].*)?$/;
/** Files that live in `~/.ssh` but are never private keys. */
const SSH_NON_KEY =
  /^(?:known_hosts(?:\..*)?|config|authorized_keys2?|allowed_signers|environment|.*\.pub|.*\.log)$/;

function isPrivateKeyName(normalized: string, locationClass: LocationClass): boolean {
  const base = baseName(normalized);
  if (base.endsWith(".pub")) return false;
  if (/\.(?:pem|key|p8)$/.test(base)) return true;
  if (SSH_KEY_NAME.test(base)) return true;
  // Inside ~/.ssh, key files often carry custom names (`id_work`, `deploy`).
  // Content confirmation (the PEM header probe) keeps this precise.
  if (locationClass === "ssh" && !SSH_NON_KEY.test(base)) return true;
  return false;
}

/**
 * Names that ARE an environment file: `.env`, `.env.*`, `*.env`, and the JSON
 * flavours `env.json`, `*.env.json`, `*-env.json`, `*_env.json`, `env.*.json`.
 *
 * Deliberately NOT "any `*env*.json`": that matched installed-software manifests
 * (`pyenv.json`, `direnv.json` in a scoop bucket, `environment.json`) by the
 * hundred. A real env file that doesn't fit the list is still found by the content
 * rules (a provider token is a provider token wherever it sits).
 */
function isEnvFileName(normalized: string): boolean {
  const base = baseName(normalized);
  if (isExampleEnvFile(base)) return false;
  if (base === ".env" || base.startsWith(".env.") || base.endsWith(".env")) return true;
  if (!base.endsWith(".json")) return false;
  return (
    base === "env.json" ||
    base.endsWith(".env.json") ||
    base.endsWith("-env.json") ||
    base.endsWith("_env.json") ||
    /^env\..+\.json$/.test(base)
  );
}

function isCookieJarName(normalized: string): boolean {
  const base = baseName(normalized);
  return (base.includes("cookies") && base.endsWith(".txt")) || base === "cookies.json";
}

function isServiceAccountName(normalized: string): boolean {
  const base = baseName(normalized);
  if (!base.endsWith(".json")) return false;
  return (
    base.includes("service-account") ||
    base.includes("credentials") ||
    base.includes("-secret") ||
    base.includes("app-secret")
  );
}

function isAwsCredentialsName(normalized: string): boolean {
  return normalized === ".aws/credentials" || normalized.endsWith("/.aws/credentials");
}

function isRegistryTokenName(normalized: string): boolean {
  const base = baseName(normalized);
  if (base === ".npmrc") return true;
  return normalized === ".docker/config.json" || normalized.endsWith("/.docker/config.json");
}

/** What `matchPath` reports: the primary rule the filename triggers, plus the
 *  independent backup flag. */
export interface PathRuleHit {
  ruleId: PathRuleId;
  /** Provisional severity (pre-confirmation, pre-location-adjustment). */
  severity: Severity;
  /** The caller must read the file head and call `confirmPathRule`. */
  needsContent: boolean;
  /** The path looks like a backup copy — raise any content hit one step. */
  backup: boolean;
}

/**
 * Does this file NAME look like a credential store? `relPath` may be absolute,
 * home-relative (`~/…`) or bare; either slash style. Returns the single most
 * specific rule, or null. `.env.example` / `.env.sample` / `.env.template` never
 * match. If only the backup pattern matches, the hit is the `path.env-backup`
 * modifier (fires only alongside a content hit).
 */
export function matchPath(relPath: string, locationClass: LocationClass): PathRuleHit | null {
  const p = norm(relPath);
  if (isExampleEnvFile(p)) return null;
  const backup = isBackupPath(p);

  // Most specific first.
  let id: PathRuleId | null = null;
  if (isAwsCredentialsName(p)) id = "path.aws-long-lived";
  else if (isRegistryTokenName(p)) id = "path.registry-token";
  else if (isPrivateKeyName(p, locationClass)) id = "path.private-key";
  else if (/\.(?:p12|pfx)$/.test(baseName(p))) id = "path.pkcs12";
  else if (isCookieJarName(p)) id = "path.cookie-jar";
  else if (isServiceAccountName(p)) id = "path.service-account";
  else if (isEnvFileName(p)) id = "path.env-file";
  else if (backup) id = "path.env-backup";

  if (!id) return null;
  const rule = pathRule(id);
  return { ruleId: id, severity: rule.severity, needsContent: rule.needsContent, backup };
}

// ---------------------------------------------------------------------------
// Content confirmation (§ A2.2) — the first ~4 KB of the file
// ---------------------------------------------------------------------------

/** How much of a file the caller should read for `confirmPathRule`. */
export const HEAD_PROBE_BYTES = 4096;

export interface PathConfirmation {
  /** The file really holds what the filename suggested. */
  fires: boolean;
  severity: Severity;
  /** Short human reason ("unencrypted OpenSSH key"). Never secret material. */
  detail?: string;
  /**
   * A raw secret extracted from the head, when the rule has one to give (AWS key
   * id, registry token, an env value). IN-PROCESS ONLY — hash it with
   * `fingerprint`; never log, persist or serialise it.
   */
  secret?: string;
}

export interface ConfirmContext {
  /** `scanText` already found a content hit in this file (confirms env files). */
  contentHit?: boolean;
}

const NO_FIRE: PathConfirmation = { fires: false, severity: "low" };

// --- private keys -----------------------------------------------------------

const PRIVATE_KEY_HEADER = /-----BEGIN ([A-Z0-9 ]*?PRIVATE KEY(?: BLOCK)?)-----/;

/**
 * Read the cipher/KDF names out of an OpenSSH private key (`openssh-key-v1`):
 * `kdfname == "none"` means the key is stored unencrypted. Returns null when the
 * head is too short or malformed to tell.
 */
export function openSshKeyIsEncrypted(headText: string): boolean | null {
  const m = headText.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)(?:-----END|$)/);
  if (!m) return null;
  const b64 = m[1]!.replace(/[^A-Za-z0-9+/]/g, "").slice(0, 160);
  const usable = b64.slice(0, b64.length - (b64.length % 4));
  if (usable.length < 64) return null;
  const buf = Buffer.from(usable, "base64");
  const MAGIC = "openssh-key-v1\0";
  if (buf.length < MAGIC.length + 8 || buf.subarray(0, MAGIC.length).toString("latin1") !== MAGIC) {
    return null;
  }
  let off = MAGIC.length;
  const readString = (): string | null => {
    if (off + 4 > buf.length) return null;
    const len = buf.readUInt32BE(off);
    off += 4;
    if (len > 64 || off + len > buf.length) return null;
    const s = buf.subarray(off, off + len).toString("latin1");
    off += len;
    return s;
  };
  const cipher = readString();
  const kdf = readString();
  if (cipher === null || kdf === null) return null;
  return kdf !== "none" || cipher !== "none";
}

function confirmPrivateKey(rawHead: string): PathConfirmation {
  // A key embedded in a JSON/JSONL string carries literal `\n` escapes.
  const head = rawHead.replace(/\\r\\n|\\n/g, "\n");
  const m = head.match(PRIVATE_KEY_HEADER);
  if (!m) return NO_FIRE; // certificate / public key only
  const kind = m[1]!;
  if (kind === "OPENSSH PRIVATE KEY") {
    const enc = openSshKeyIsEncrypted(head);
    if (enc === true) return { fires: true, severity: "low", detail: "encrypted OpenSSH key" };
    if (enc === false) {
      return { fires: true, severity: "critical", detail: "unencrypted OpenSSH key" };
    }
    return { fires: true, severity: "high", detail: "OpenSSH key (encryption not determinable)" };
  }
  if (kind === "ENCRYPTED PRIVATE KEY") {
    return { fires: true, severity: "low", detail: "encrypted PKCS#8 key" };
  }
  if (kind === "PGP PRIVATE KEY BLOCK") {
    return { fires: true, severity: "high", detail: "PGP private key (passphrase unknown)" };
  }
  if (/Proc-Type:\s*4,\s*ENCRYPTED/i.test(head)) {
    return { fires: true, severity: "low", detail: "encrypted PEM private key" };
  }
  return { fires: true, severity: "critical", detail: "unencrypted private key" };
}

// --- env files --------------------------------------------------------------

const SECRETISH_KEY =
  /secret|token|passw(?:or)?d|passwd|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth|dsn|database_url|connection[_-]?string|signing/i;
const URL_WITH_CREDENTIALS = /:\/\/[^/\s:@]+:[^/\s@]{3,}@/;
const ASSIGNMENT = /^\s*(?:export\s+)?["']?([A-Za-z_][\w.-]*)["']?\s*[:=]\s*["']?([^"'\n#]*)/;

/** First secret-looking `KEY=value` / `"KEY": "value"` in a text, or null. */
export function findSecretishAssignment(text: string): string | null {
  for (const line of text.split(/\r?\n/)) {
    const m = ASSIGNMENT.exec(line);
    if (!m) continue;
    const key = m[1]!;
    const value = m[2]!.trim().replace(/[,;]+$/, "");
    if (value.length < 8 || /\s/.test(value)) continue;
    if (isAllowlisted(value)) continue;
    if (/^(?:true|false|null|undefined|\d+(?:\.\d+)*)$/i.test(value)) continue;
    if (URL_WITH_CREDENTIALS.test(value)) return value;
    if (SECRETISH_KEY.test(key)) return value;
    // Random-looking regardless of the key name.
    if (
      value.length >= 20 &&
      shannonEntropy(value) >= 3.5 &&
      /[A-Za-z]/.test(value) &&
      /\d/.test(value)
    ) {
      return value;
    }
  }
  return null;
}

function confirmEnvFile(head: string, ctx: ConfirmContext | undefined): PathConfirmation {
  const secret = findSecretishAssignment(head);
  if (secret) return { fires: true, severity: "high", detail: "secret values in env file", secret };
  if (ctx?.contentHit)
    return { fires: true, severity: "high", detail: "secret values in env file" };
  return NO_FIRE;
}

// --- cookie jars ------------------------------------------------------------

function confirmCookieJar(head: string): PathConfirmation {
  const netscape = /^#\s*(?:Netscape )?HTTP Cookie File/im.test(head);
  const tabbed = head.split(/\r?\n/).some((l) => !l.startsWith("#") && l.split("\t").length >= 7);
  const json = /"name"\s*:/.test(head) && /"value"\s*:/.test(head) && /"domain"\s*:/.test(head);
  if (netscape || tabbed || json) {
    return { fires: true, severity: "high", detail: "cookie jar with session cookies" };
  }
  return NO_FIRE;
}

// --- service accounts -------------------------------------------------------

const SERVICE_ACCOUNT_KEY = /"(private_key|client_secret|secret)"\s*:\s*"([^"]{8,})/g;

function confirmServiceAccount(head: string): PathConfirmation {
  for (const m of head.matchAll(SERVICE_ACCOUNT_KEY)) {
    const value = m[2]!;
    // A private_key value is a PEM block — the allowlist's placeholder markers
    // would only ever false-reject it, so gate placeholders on the other keys.
    if (m[1] !== "private_key" && isAllowlisted(value)) continue;
    return {
      fires: true,
      severity: "critical",
      detail: `JSON with ${m[1]}`,
      secret: m[1] === "private_key" ? undefined : value,
    };
  }
  return NO_FIRE;
}

// --- AWS shared credentials file --------------------------------------------

const AWS_KEY_ID = /aws_access_key_id\s*=\s*["']?(A[A-Z0-9]{3}[A-Z0-9]{16})\b/gi;

function confirmAwsLongLived(head: string): PathConfirmation {
  let temporary = false;
  for (const m of head.matchAll(AWS_KEY_ID)) {
    const id = m[1]!;
    if (isAllowlisted(id)) continue;
    if (id.startsWith("AKIA")) {
      return { fires: true, severity: "high", detail: "long-lived AWS access key", secret: id };
    }
    if (id.startsWith("ASIA")) temporary = true;
  }
  if (temporary) {
    return { fires: true, severity: "low", detail: "temporary STS credentials (likely expired)" };
  }
  return NO_FIRE;
}

// --- registry tokens --------------------------------------------------------

const NPM_AUTH = /(?:_authToken|_auth|_password)\s*=\s*["']?([^\s"']+)/g;
const DOCKER_AUTH = /"auth"\s*:\s*"([A-Za-z0-9+/=]{8,})"/;

function confirmRegistryToken(head: string): PathConfirmation {
  for (const m of head.matchAll(NPM_AUTH)) {
    const value = m[1]!;
    if (isAllowlisted(value)) continue; // `${NPM_TOKEN}` interpolation etc.
    return { fires: true, severity: "high", detail: "registry auth token", secret: value };
  }
  const docker = DOCKER_AUTH.exec(head);
  if (docker && !isAllowlisted(docker[1]!)) {
    return { fires: true, severity: "high", detail: "registry credentials", secret: docker[1] };
  }
  return NO_FIRE;
}

/**
 * Confirm a path-rule hit against the file head (≤ `HEAD_PROBE_BYTES`). Pure.
 * `path.env-backup` is a modifier and never confirms on its own.
 */
export function confirmPathRule(
  ruleId: PathRuleId,
  headText: string,
  ctx?: ConfirmContext,
): PathConfirmation {
  switch (ruleId) {
    case "path.private-key":
      return confirmPrivateKey(headText);
    case "path.pkcs12":
      return { fires: true, severity: "high", detail: "PKCS#12 bundle" };
    case "path.env-file":
      return confirmEnvFile(headText, ctx);
    case "path.cookie-jar":
      return confirmCookieJar(headText);
    case "path.service-account":
      return confirmServiceAccount(headText);
    case "path.aws-long-lived":
      return confirmAwsLongLived(headText);
    case "path.registry-token":
      return confirmRegistryToken(headText);
    case "path.env-backup":
      return NO_FIRE;
  }
}

// ---------------------------------------------------------------------------
// Rotation links (§ A2.5) — the CLI prints these; it never calls a provider.
// ---------------------------------------------------------------------------

const OWASP_SECRETS =
  "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html";
const OWASP_SESSIONS =
  "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html";
const SSH_KEYS_DOC =
  "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent";
const AWS_KEYS = "https://console.aws.amazon.com/iam/home#/security_credentials";
const GH_TOKENS = "https://github.com/settings/tokens";
const NPM_REVOKE = "https://docs.npmjs.com/revoking-access-tokens";
const SLACK_APPS = "https://api.slack.com/apps";

/** Rule id → where to rotate/revoke. Keyed by every path rule id and every
 *  `SECRET_RULES` id (a test asserts the coverage). */
export const ROTATION_URLS: Record<string, string> = {
  "path.private-key": SSH_KEYS_DOC,
  "path.pkcs12": SSH_KEYS_DOC,
  "path.env-file": OWASP_SECRETS,
  "path.env-backup": OWASP_SECRETS,
  "path.cookie-jar": OWASP_SESSIONS,
  "path.service-account": "https://console.cloud.google.com/iam-admin/serviceaccounts",
  "path.aws-long-lived": AWS_KEYS,
  "path.registry-token": NPM_REVOKE,
  "private-key": SSH_KEYS_DOC,
  "aws-access-key-id": AWS_KEYS,
  "aws-secret-access-key": AWS_KEYS,
  "gcp-api-key": "https://console.cloud.google.com/apis/credentials",
  "github-personal-access-token": GH_TOKENS,
  "github-oauth-token": "https://github.com/settings/applications",
  "github-app-token": "https://github.com/settings/installations",
  "github-refresh-token": "https://github.com/settings/applications",
  "github-fine-grained-pat": "https://github.com/settings/personal-access-tokens",
  "stripe-secret-key": "https://dashboard.stripe.com/apikeys",
  "slack-token": SLACK_APPS,
  "slack-webhook-url": SLACK_APPS,
  "twilio-api-key": "https://console.twilio.com/us1/account/keys-credentials/api-keys",
  "sendgrid-api-key": "https://app.sendgrid.com/settings/api_keys",
  "npm-access-token": NPM_REVOKE,
  jwt: "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-revocation",
  "generic-secret-assignment": OWASP_SECRETS,
};

/** Rotation link for a rule id, falling back to the generic secrets guide. */
export function rotationUrl(ruleId: string): string {
  return ROTATION_URLS[ruleId] ?? OWASP_SECRETS;
}

/** Every rule id that must have a rotation entry (path rules + content rules). */
export function allRuleIds(): string[] {
  return [...PATH_RULES.map((r) => r.id), ...new Set(SECRET_RULES.map((r) => r.id))];
}

/** Content-rule ids a confirmed path rule supersedes on the same file. */
export function shadowedContentRules(ruleId: PathRuleId): readonly string[] {
  return pathRule(ruleId).shadows;
}
