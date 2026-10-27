// RepoRef ids for Machine Insights uploads (ENDPOINT-MACHINE-INSIGHTS § C3) — PURE
// (node:crypto only; the salt is an input, like fingerprint.ts).
//
// A repo leaves the device as a salted id, never as a name or path (the readable name is a
// separate opt-in, `sharePaths`). For an ORG device the salt is the org's, so two laptops that
// cloned the same repo send the same id and fold to one row. That only works if the id is
// derived from something the clones share — the remote URL — normalized so ssh and https
// spellings, a `.git` suffix and a differently-cased host all match. With no remote (a
// local-only repo) the home-relative path is the best identity there is.
//
// Credentials in a remote (`https://user:token@host/…`) are discarded during normalization
// and never reach the hash input.

import { createHmac } from "node:crypto";

/** 8 bytes of the HMAC → 16 hex chars. */
export const REPO_REF_ID_BYTES = 8;

/** Hosts whose owner/repo paths are case-insensitive, so `Acme/App` and `acme/app` are one repo. */
const CASE_INSENSITIVE_HOSTS = new Set(["github.com", "gitlab.com", "bitbucket.org"]);

/**
 * `host/owner/repo` for a network remote, or null for anything that isn't one (a local path,
 * a `file://` URL, garbage). Handles ssh (`git@host:owner/repo.git`, `ssh://git@host:22/…`),
 * https/http/git URLs with or without credentials and ports, trailing slashes and `.git`.
 * The host is lower-cased; so is the path on hosts known to ignore case.
 */
export function normalizeRemoteUrl(raw: string): string | null {
  const url = raw.trim();
  if (!url || /^[a-z]:[\\/]/i.test(url)) return null; // empty, or a Windows drive path

  let host: string;
  let path: string;
  const scheme = /^([a-z][a-z0-9+.-]*):\/\/(.*)$/i.exec(url);
  if (scheme) {
    if (scheme[1]!.toLowerCase() === "file") return null;
    const rest = scheme[2]!;
    const slash = rest.indexOf("/");
    if (slash < 0) return null;
    const authority = rest.slice(0, slash);
    host = authority.slice(authority.lastIndexOf("@") + 1).replace(/:\d*$/, "");
    path = rest.slice(slash + 1);
  } else {
    // scp-like: [user@]host:path
    const m = /^(?:[^@/\\:]+@)?([^:/\\]+):(.+)$/.exec(url);
    if (!m) return null;
    host = m[1]!;
    path = m[2]!;
  }

  host = host.toLowerCase().replace(/\.$/, "");
  if (host === "ssh.github.com") host = "github.com";
  path = path
    .replace(/[?#].*$/, "")
    .replace(/\\/g, "/")
    .replace(/\/{2,}/g, "/")
    .replace(/^\/+|\/+$/g, "")
    .replace(/\.git$/i, "")
    .replace(/\/+$/g, "");
  if (!host || !path) return null;
  if (CASE_INSENSITIVE_HOSTS.has(host)) path = path.toLowerCase();
  return `${host}/${path}`;
}

/** Forward slashes, no leading `./` or `/`, no trailing `/` — a home-relative path in canonical form. */
export function normalizeHomePath(p: string): string {
  return p
    .replace(/\\/g, "/")
    .replace(/\/{2,}/g, "/")
    .replace(/^(?:\.\/)+/, "")
    .replace(/^\/+|\/+$/g, "");
}

/**
 * The readable name sent with `shareRepoNames`: `owner/repo` from the remote (the host is
 * dropped; a nested group keeps its path), or the folder's own name for a repo with no remote.
 * Never a full path, so it carries no username. Null when nothing usable is left.
 */
export function repoDisplayName(identity: RepoIdentity): string | null {
  const remote = identity.remoteUrl ? normalizeRemoteUrl(identity.remoteUrl) : null;
  const name = remote
    ? remote.slice(remote.indexOf("/") + 1)
    : (normalizeHomePath(identity.homeRelativePath).split("/").pop() ?? "");
  return isRepoDisplayName(name) ? name : null;
}

/** Max length of a `shareRepoNames` name. */
export const MAX_REPO_DISPLAY_NAME_LENGTH = 200;

/**
 * A repo name, not a path: up to four `/`-separated segments of letters, digits, `.`, `_`,
 * `-` and spaces, none of them `.`/`..`, no leading `~` or `/`. The server applies the same
 * test, so a path can't be smuggled in as a "name".
 */
export function isRepoDisplayName(name: string): boolean {
  if (!name || name.length > MAX_REPO_DISPLAY_NAME_LENGTH) return false;
  const parts = name.split("/");
  return (
    parts.length <= 4 &&
    parts.every((p) => /^[A-Za-z0-9._ -]+$/.test(p) && p !== "." && p !== ".." && p.trim() === p)
  );
}

export interface RepoIdentity {
  /** The `origin` (or first) remote URL as printed by git; null when there is none. */
  remoteUrl: string | null;
  /** The folder's path relative to the home directory; used when there's no usable remote. */
  homeRelativePath: string;
}

/**
 * HMAC-SHA256(salt, identity) truncated to 16 hex chars. Remote-derived and path-derived ids
 * are domain-separated, so a repo literally named like a URL can't collide with a remote.
 */
export function repoRefId(salt: Uint8Array, identity: RepoIdentity): string {
  if (salt.length === 0) throw new Error("repo ref salt must not be empty");
  const remote = identity.remoteUrl ? normalizeRemoteUrl(identity.remoteUrl) : null;
  const domain = remote !== null ? "repo-ref:remote\0" : "repo-ref:path\0";
  const data = remote ?? normalizeHomePath(identity.homeRelativePath);
  return createHmac("sha256", salt)
    .update(domain)
    .update(data)
    .digest()
    .subarray(0, REPO_REF_ID_BYTES)
    .toString("hex");
}
