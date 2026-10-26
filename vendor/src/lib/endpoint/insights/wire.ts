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

/** Salted hash always; the readable name only when the device shares paths. */
export interface RepoRef {
  id: string;
  /** Home-relative path (`~/code/app`) — only with `sharePaths`. */
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
}

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
}
