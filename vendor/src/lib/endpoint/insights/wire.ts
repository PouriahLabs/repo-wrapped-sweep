// The Machine Insights upload block (ENDPOINT-MACHINE-INSIGHTS § C3) — the wire shape and
// its caps, shared by the CLI (which builds it) and the server (whose Zod schema enforces
// it). PURE types + constants only — no zod, no I/O — so the CLI bundle can import it.
//
// METADATA ONLY: counts, sizes, versions, timestamps, model ids and token totals. A repo
// travels as a `RepoRef` — a salted id, plus its readable name only when the device shares
// paths (and the server strips the name anyway when it doesn't).

import type { AiTool } from "./ai-usage";
import type { BackupState } from "./backup";
import type { DiskClass } from "./disk-classes";
import type { RepoState } from "./git-state";
import type { ToolId } from "./pins";

/** Upload schema version that carries the optional `insights` block. */
export const INSIGHTS_SCHEMA_VERSION = 2;

/** Caps (§ C3). The server rejects a body over any of them; the CLI never builds one. */
export const MAX_GIT_TOP = 20;
export const MAX_DRIFT_ROWS = 50;
export const MAX_AI_ROWS = 400;
export const MAX_BACKUP_TOP = 20;
/** Readable repo names (home-relative paths) longer than this are dropped, not truncated. */
export const MAX_REPO_NAME_LENGTH = 300;
export const MAX_MODEL_LENGTH = 100;
export const MAX_VERSION_LENGTH = 64;

/** 16 hex chars — `repoRefId` (`repo-ref.ts`). */
export const REPO_REF_ID_RE = /^[0-9a-f]{16}$/;

/** Most entries in the `repoNames` directory. */
export const MAX_REPO_NAMES = 1000;

/**
 * Salted hash always; a readable name only on opt-in: `owner/repo` (or the folder name) with
 * `shareRepoNames`, else the home-relative path with `sharePaths`.
 */
export interface RepoRef {
  id: string;
  /** `owner/repo` with `shareRepoNames`; `~/code/app` with `sharePaths`. */
  name?: string;
}

export interface MachineInfo {
  /** Kernel / OS build release (`os.release()`), e.g. `10.0.26100`, `24.1.0`, `6.8.0-45-generic`. */
  osVersion: string;
  /** `os.arch()`: `x64`, `arm64`, … */
  arch: string;
  cpuCount: number;
  memGb: number;
  /** The volume holding the home directory. 0 when it could not be read. */
  diskTotalGb: number;
  diskFreeGb: number;
  // ---- CLI 0.3+ (all optional: an older CLI omits them) ----
  /** Marketing name + version: `macOS 15.1`, `Windows 11 Pro 24H2`, `Ubuntu 24.04.1 LTS`. */
  osName?: string;
  /** `os.cpus()[0].model`, e.g. `Apple M3 Pro`. */
  cpuModel?: string;
  /** Hours since boot. */
  uptimeHours?: number;
  /** Login shell basename: `zsh`, `bash`, `pwsh`, `cmd`. */
  shell?: string;
}

/** Tri-state for a setting the CLI could not always read (no admin rights, unsupported OS). */
export type OnOff = "on" | "off" | "unknown";

export const CREDENTIAL_HELPER_KINDS = [
  "keychain",
  "plaintext",
  "memory",
  "none",
  "other",
] as const;
/** How `git` stores HTTPS credentials: an OS keychain, a plaintext file (`store`), in memory
 *  for a while (`cache`), nothing configured, or a helper we don't classify. */
export type CredentialHelperKind = (typeof CREDENTIAL_HELPER_KINDS)[number];

export const SSH_KEY_TYPES = ["ed25519", "ecdsa", "rsa", "dsa", "other"] as const;
export type SshKeyType = (typeof SSH_KEY_TYPES)[number];

export interface SshKeySummary {
  count: number;
  byType: Partial<Record<SshKeyType, number>>;
  /** RSA under 2048 bits, or any DSA key. */
  weak: number;
  /** Private keys with no passphrase. */
  unencrypted: number;
  /** Age of the oldest private key file, days; null with no keys. */
  oldestDays: number | null;
}

/** Security posture (CLI 0.3+). Read-only local checks — no admin rights, no network. */
export interface PostureInsights {
  diskEncryption: OnOff;
  firewall: OnOff;
  /** Days since the last installed OS update; null when it could not be read. */
  osUpdateAgeDays: number | null;
  gitCredentialHelper: CredentialHelperKind | null;
  /** `commit.gpgsign` on in the global git config; null when git is absent. */
  commitSigning: boolean | null;
  sshKeys: SshKeySummary;
}

export const AI_CLIENTS = ["claude-code", "claude-desktop", "cursor", "vscode", "codex"] as const;
export type AiClient = (typeof AI_CLIENTS)[number];

export interface McpClientSummary {
  client: AiClient;
  /** MCP servers configured (user-level plus per-project). */
  servers: number;
  /** Servers whose config holds a literal credential-looking value instead of a reference. */
  inlineSecrets: number;
}

export const AGENT_AUTONOMY = ["default", "auto-edit", "broad-shell", "full-auto"] as const;
/** How much an AI agent may do without asking: `full-auto` skips every prompt
 *  (bypassPermissions / approval `never`), `broad-shell` pre-approves any shell command. */
export type AgentAutonomy = (typeof AGENT_AUTONOMY)[number];

/** AI tooling on the machine (CLI 0.3+). Names are well-known public tool/extension ids only. */
export interface AiToolsInsights {
  /** AI CLIs found on PATH, e.g. `claude`, `codex`, `gemini`, `aider`. */
  clis: string[];
  /** Known AI editor extensions, as `editor:extension-id`. */
  extensions: string[];
  mcp: McpClientSummary[];
  autonomy: Array<{ client: AiClient; level: AgentAutonomy }>;
}

/** Local coding rhythm (CLI 0.3+): commits by this machine's git identity. The identity
 *  itself never leaves the machine — only counts. */
export interface ActivityInsights {
  commits7d: number;
  commits365d: number;
  activeDays365d: number;
  longestStreakDays: number;
  /** 24 counts, local hour of day. */
  byHour: number[];
  /** 7 counts, local weekday, Sunday first. */
  byWeekday: number[];
  /** The repo with the most commits in the last year. */
  topRepo: { repo: RepoRef; commits: number } | null;
  biggestProject: { repo: RepoRef; bytes: number } | null;
  /** The project left untouched the longest. */
  oldestProject: { repo: RepoRef; lastTouched: string } | null;
}

export const MAX_AI_TOOL_ITEMS = 32;

export interface GitTopRow {
  repo: RepoRef;
  states: RepoState[];
  /** Commits on no remote (0 for a repo with no remote at all — `states` says `no-remote`). */
  ahead: number;
  /** Changed entries in the working tree. */
  uncommitted: number;
  stashes: number;
}

export interface GitInsights {
  repos: number;
  byState: Partial<Record<RepoState, number>>;
  unpushedCommits: number;
  staleStashes: number;
  top?: GitTopRow[];
}

export interface DiskInsights {
  reclaimableGb: number;
  staleReclaimableGb: number;
  /** GB per class. */
  byClass: Partial<Record<DiskClass, number>>;
  dockerGb?: number;
}

export interface DriftRow {
  repo: RepoRef;
  tool: ToolId;
  installed: string | null;
  wanted: string;
}

export interface ToolchainInsights {
  /** Version, or null when absent / unknown. */
  tools: Partial<Record<ToolId, string | null>>;
  managers: string[];
  drift: DriftRow[];
}

export interface AiDayRow {
  /** UTC day, `YYYY-MM-DD`. */
  day: string;
  repo: RepoRef | null;
  tool: AiTool;
  model: string;
  sessions: number;
  activeMinutes: number;
  inputTokens: number;
  outputTokens: number;
  cacheWriteTokens: number;
  cacheReadTokens: number;
  /** API-equivalent USD; null when the model is unpriced. */
  costUsd: number | null;
}

export interface AiInsights {
  pricesAsOf: string;
  /** Complete-day totals for the days since the last successful upload. */
  days: AiDayRow[];
}

export interface BackupTopRow {
  project: RepoRef;
  state: BackupState;
  bytes: number;
  /** ISO-8601, or null when nothing in the folder could be dated. */
  lastTouched: string | null;
}

export interface BackupInsights {
  projects: number;
  byState: Partial<Record<BackupState, number>>;
  localOnlyBytes: number;
  top?: BackupTopRow[];
}

export interface InsightsBlock {
  collectedAt: string;
  machine: MachineInfo;
  git?: GitInsights;
  disk?: DiskInsights;
  toolchain?: ToolchainInsights;
  ai?: AiInsights;
  backup?: BackupInsights;
  posture?: PostureInsights;
  aiTools?: AiToolsInsights;
  activity?: ActivityInsights;
  /**
   * Only with `shareRepoNames`: id → name for every repo the CLI knows, so names also reach
   * rows uploaded before sharing was turned on (repo ids never change).
   */
  repoNames?: RepoRef[];
}
